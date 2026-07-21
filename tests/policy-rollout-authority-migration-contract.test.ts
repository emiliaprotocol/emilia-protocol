// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migration = readFileSync(
  new URL('../supabase/migrations/20260719123500_policy_rollout_authority_admin.sql', import.meta.url),
  'utf8',
);

describe('policy rollout authority administration migration', () => {
  it('restricts grants to a live Class-A credential and narrow role/scope', () => {
    expect(migration).toContain("p_role NOT IN ('policy_admin', 'control_plane_approver')");
    expect(migration).toContain("p_valid_to > pg_catalog.now() + interval '366 days'");
    expect(migration).toContain("ac.key_class = 'A'");
    expect(migration).toContain('ac.revoked_at IS NULL');
    expect(migration).toContain("ARRAY['policy_rollout']::TEXT[]");
    expect(migration).toContain('FOR UPDATE');
  });

  it('records both grant and revocation in the append-only audit log', () => {
    expect(migration).toContain("'guard.authority.granted'");
    expect(migration).toContain("'guard.authority.revoked'");
    expect(migration).toContain('INSERT INTO public.audit_events');
    expect(migration).toContain('p_granted_by');
    expect(migration).toContain('p_revoked_by');
  });

  it('exposes only the narrow security-definer functions to service_role', () => {
    expect(migration).toMatch(/LANGUAGE plpgsql\s+SECURITY DEFINER\s+SET search_path = ''/);
    expect(migration).toMatch(/REVOKE ALL ON FUNCTION public\.grant_policy_rollout_authority[\s\S]+FROM PUBLIC, anon, authenticated;/);
    expect(migration).toMatch(/GRANT EXECUTE ON FUNCTION public\.grant_policy_rollout_authority[\s\S]+TO service_role;/);
    expect(migration).toMatch(/REVOKE ALL ON FUNCTION public\.revoke_policy_rollout_authority[\s\S]+FROM PUBLIC, anon, authenticated;/);
    expect(migration).toMatch(/GRANT EXECUTE ON FUNCTION public\.revoke_policy_rollout_authority[\s\S]+TO service_role;/);
    expect(migration).toMatch(
      /REVOKE INSERT, UPDATE, DELETE, TRUNCATE[\s\S]+ON TABLE public\.authorities[\s\S]+service_role;/,
    );
    expect(migration).toContain('GRANT SELECT ON TABLE public.authorities TO service_role');
  });
});
