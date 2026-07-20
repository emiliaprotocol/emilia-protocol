// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const appliedMigrationUrl = new URL(
  '../supabase/migrations/20260719123600_tenant_api_key_audited_issue.sql',
  import.meta.url,
);
const forwardMigrationUrl = new URL(
  '../supabase/migrations/20260720060553_approval_request_permission.sql',
  import.meta.url,
);
const appliedMigration = readFileSync(appliedMigrationUrl, 'utf8');
const forwardMigration = readFileSync(forwardMigrationUrl, 'utf8');

describe('approval-request tenant API-key permission migration', () => {
  it('follows the applied issuer migration without rewriting it', () => {
    const appliedName = basename(fileURLToPath(appliedMigrationUrl));
    const forwardName = basename(fileURLToPath(forwardMigrationUrl));

    expect(forwardName.localeCompare(appliedName)).toBeGreaterThan(0);
    expect(appliedMigration).not.toContain("'approval_request'");
    expect(forwardMigration).toContain(
      'CREATE OR REPLACE FUNCTION public.issue_tenant_api_key_audited(',
    );
  });

  it('adds approval_request to the exact bounded permission allowlist', () => {
    expect(forwardMigration).toContain(
      "p_permissions <@ ARRAY['read', 'write', 'admin', 'policy_rollout', 'approval_request']::TEXT[]",
    );
    expect(forwardMigration).toContain(
      "RAISE EXCEPTION 'invalid_tenant_api_key_issue'",
    );
  });

  it('preserves secure audited issuance and service-role-only execution', () => {
    expect(forwardMigration).toMatch(
      /LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/,
    );
    expect(forwardMigration).toContain('INSERT INTO public.tenant_api_keys');
    expect(forwardMigration).toContain('INSERT INTO public.audit_events');
    expect(forwardMigration).toContain("'cloud.tenant_api_key.issued'");
    expect(forwardMigration).toContain('p_issued_by');
    expect(forwardMigration).toMatch(
      /REVOKE ALL ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+FROM PUBLIC, anon, authenticated;/,
    );
    expect(forwardMigration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+TO service_role;/,
    );
  });
});
