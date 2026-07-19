// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719123600_tenant_api_key_audited_issue.sql', import.meta.url),
  'utf8',
);

describe('tenant API-key audited issuance migration', () => {
  it('bounds permissions and expiry and records the actor atomically', () => {
    expect(migration).toContain("'policy_rollout'");
    expect(migration).toContain("interval '90 days 5 minutes'");
    expect(migration).toContain("'cloud.tenant_api_key.issued'");
    expect(migration).toContain('p_issued_by');
    expect(migration).toContain('INSERT INTO public.tenant_api_keys');
    expect(migration).toContain('INSERT INTO public.audit_events');
  });

  it('exposes only the narrow issuer function to service_role', () => {
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+FROM PUBLIC, anon, authenticated;/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.issue_tenant_api_key_audited[\s\S]+TO service_role;/,
    );
  });
});
