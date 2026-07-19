// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719125500_trust_receipt_atomic_consume.sql', import.meta.url),
  'utf8',
);

describe('generic Trust Receipt atomic consume migration', () => {
  it('locks registry facts and appends consume in one security-definer transaction', () => {
    expect(migration).toContain('p_registry_bindings JSONB');
    expect(migration).toContain('FROM public.approver_credentials ac');
    expect(migration).toContain('FROM public.authorities a');
    expect(migration).toContain("a.subject_ref = binding ->> 'approver_id'");
    expect(migration).toContain("count(DISTINCT binding ->> 'approver_id')");
    expect(migration).toContain('FOR UPDATE');
    expect(migration).toContain("'guard.trust_receipt.consumed'");
    expect(migration).toContain("v_created ->> 'action_type' = 'policy_rollout'");
    expect(migration).toMatch(/LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/);
  });

  it('is service-role only', () => {
    expect(migration).toMatch(
      /REVOKE ALL ON FUNCTION public\.consume_trust_receipt_authorized[\s\S]+FROM PUBLIC, anon, authenticated;/,
    );
    expect(migration).toMatch(
      /GRANT EXECUTE ON FUNCTION public\.consume_trust_receipt_authorized[\s\S]+TO service_role;/,
    );
  });
});
