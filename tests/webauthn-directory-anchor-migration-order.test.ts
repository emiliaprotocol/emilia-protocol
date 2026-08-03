// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const restored = readFileSync(resolve(
  ROOT,
  'supabase/migrations/20260802231000_restore_webauthn_directory_anchor.sql',
), 'utf8');

describe('WebAuthn directory anchor migration order', () => {
  it('makes the final registration function persist the directory basis atomically', () => {
    expect(restored).toContain('enrollment_basis,');
    expect(restored).toContain('directory_user_id');
    expect(restored).toContain("v_enrollment_basis = 'directory'");
    expect(restored).toContain("RETURN jsonb_build_object('error', 'directory_basis_mismatch')");
    expect(restored).toContain('FOR UPDATE');
    expect(restored).toContain('SET search_path =');
    expect(restored).toContain("SET lock_timeout = '2s'");
    expect(restored).toContain("SET statement_timeout = '5s'");
    expect(restored).toContain('FROM public.scim_users AS directory_user');
    expect(restored).toContain('directory_user.active = TRUE');
    expect(restored).toContain('FROM public.scim_provisioning_tokens AS token');
    expect(restored).toContain("RETURN jsonb_build_object('error', 'directory_user_inactive')");
    expect(restored).toContain('v_completed_at := pg_catalog.clock_timestamp()');
    expect(restored).toContain('v_challenge.expires_at <= v_completed_at');
    expect(restored).toContain('SET consumed_at = v_completed_at');
  });

  it('keeps the function service-only and fully qualifies security-definer tables', () => {
    expect(restored).toContain('FROM public.webauthn_challenges');
    expect(restored).toContain('INSERT INTO public.approver_credentials');
    expect(restored).toContain('UPDATE public.webauthn_challenges');
    expect(restored).toContain('FROM PUBLIC, anon, authenticated');
    expect(restored).toContain('TO service_role');
  });
});
