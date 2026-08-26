// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const previousMigrationUrl = new URL(
  '../supabase/migrations/20260720060553_approval_request_permission.sql',
  import.meta.url,
);
const receiptMigrationUrl = new URL(
  '../supabase/migrations/20260825130000_receipt_api_key_permissions.sql',
  import.meta.url,
);
const previousMigration = readFileSync(previousMigrationUrl, 'utf8');
const receiptMigration = readFileSync(receiptMigrationUrl, 'utf8');

const EXACT_PERMISSIONS = [
  'read',
  'write',
  'admin',
  'policy_rollout',
  'approval_request',
  'receipt.read',
  'receipt.evidence',
  'receipt.consume',
  'receipt.execute',
];

describe('receipt tenant API-key permission migration', () => {
  it('is a forward-only replacement of the audited issuer', () => {
    expect(
      basename(fileURLToPath(receiptMigrationUrl)).localeCompare(
        basename(fileURLToPath(previousMigrationUrl)),
      ),
    ).toBeGreaterThan(0);
    expect(previousMigration).not.toContain("'receipt.read'");
    expect(receiptMigration).toContain(
      'CREATE OR REPLACE FUNCTION public.issue_tenant_api_key_audited(',
    );
  });

  it('uses the exact bounded allowlist including all receipt operations', () => {
    expect(receiptMigration).toContain(
      `p_permissions <@ ARRAY[${EXACT_PERMISSIONS.map((value) => `'${value}'`).join(', ')}]::TEXT[]`,
    );
    expect(receiptMigration).toContain(
      "RAISE EXCEPTION 'invalid_tenant_api_key_issue'",
    );
  });

  it('preserves audited issuance and service-role-only execution', () => {
    expect(receiptMigration).toMatch(
      /LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/,
    );
    expect(receiptMigration).toContain('INSERT INTO public.tenant_api_keys');
    expect(receiptMigration).toContain('INSERT INTO public.audit_events');
    expect(receiptMigration).toContain("'cloud.tenant_api_key.issued'");
    expect(receiptMigration).toMatch(
      /REVOKE ALL ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+FROM PUBLIC, anon, authenticated;/,
    );
    expect(receiptMigration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+TO service_role;/,
    );
  });
});
