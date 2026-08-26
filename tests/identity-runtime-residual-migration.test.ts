// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const sql = fs.readFileSync(path.join(
  process.cwd(),
  'supabase/migrations/20260826170000_identity_runtime_residual_closure.sql',
), 'utf8');

function section(endMarker: string, previousMarker?: string): string {
  const end = sql.indexOf(endMarker);
  const start = previousMarker ? sql.indexOf(previousMarker) : 0;
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return sql.slice(start, end);
}

describe('identity runtime residual migration contract', () => {
  it('binds mobile pairings and sessions to an exact Class-A directory identity', () => {
    const mobile = section('-- END STRIX-44-MOBILE-IDENTITY');
    expect(mobile).toContain('directory_user_id UUID');
    expect(mobile).toContain('identity_credential_id TEXT');
    expect(mobile).toContain("credential.key_class IS DISTINCT FROM 'A'");
    expect(mobile).toContain('v_now := pg_catalog.clock_timestamp();');
    expect(mobile).toContain('touch_mobile_session_verified');
    expect(mobile).toContain('mobile_session_identity_is_active');
    expect(mobile).toContain('commit_mobile_action_decision_identity_unchecked_v1');
    expect(mobile).toContain('register_mobile_action_challenge_identity_unchecked_v1');
    expect(mobile).toContain('enroll_mobile_device_identity_unchecked_v1');
    expect(mobile).toMatch(/FROM public\.mobile_sessions AS session[\s\S]*FOR UPDATE;/);
    expect(mobile).toContain("'scim_username_changed'");
    expect(mobile).toContain("'scim_tenant_changed'");
    expect(mobile).toContain('identity_proof_required');
    expect(mobile).not.toMatch(/GRANT EXECUTE ON FUNCTION public\.exchange_mobile_pairing\(/);
  });

  it('locks handshake and party state and binds the exact issuer key and proof', () => {
    const handshake = section(
      '-- END STRIX-48-HANDSHAKE-ISSUER-PROOF',
      '-- END STRIX-44-MOBILE-IDENTITY',
    );
    expect(handshake).toMatch(/FROM public\.handshakes AS handshake[\s\S]*FOR UPDATE;/);
    expect(handshake).toMatch(/FROM public\.handshake_parties AS party[\s\S]*FOR UPDATE;/);
    expect(handshake).toContain('p_authority_key_digest');
    expect(handshake).toContain('authority_key_changed_at_write');
    expect(handshake).toContain("'presentation_id', v_presentation_id");
    expect(handshake).toContain("v_payload_hash := 'sha256:'");
    expect(handshake).toContain('legacy_issuer_unproven');
  });

  it('requires the exact locked SCIM token for user and group mutations', () => {
    const scim = section(
      '-- END STRIX-42-SCIM-EXACT-BEARER',
      '-- END STRIX-48-HANDSHAKE-ISSUER-PROOF',
    );
    expect(scim).toContain('scim_mutation_token_is_active');
    expect(scim).toContain('WHERE token.id = p_token_id');
    expect(scim).toContain('create_scim_user_authorized');
    expect(scim).toContain('apply_scim_group_authorized');
    expect(scim).toContain('token_authority_invalid');
    expect(scim).toMatch(/REVOKE ALL ON FUNCTION public\.apply_scim_user_and_authority_atomic\([\s\S]*TEXT, TEXT, UUID, INTEGER, JSONB, BOOLEAN, TEXT/);
  });
});
