// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { createArenaAllowance, deriveArenaActionBinding } from './core';
import { signArenaRefusal, verifyArenaPublicProjection } from './refusal';

function fixture() {
  const keys = crypto.generateKeyPairSync('ed25519');
  const allowance = createArenaAllowance({
    sessionId: `arena_session_${'a'.repeat(32)}`,
    agentName: 'Night Shift',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['compute.batch', 'vendor.demo'],
    issuedAt: '2026-08-02T11:00:00.000Z',
    expiresAt: '2026-08-03T11:00:00.000Z',
  });
  const action = {
    operation_id: 'operation-001',
    action_type: 'arena.resource.allocate.1' as const,
    target: 'vendor.demo',
    amount: 900,
    currency: 'CREDITS' as const,
    purpose: 'synthetic-vendor-payment',
  };
  const artifact = signArenaRefusal({
    allowance,
    action,
    reason: 'allowance_per_action_limit_exceeded',
    attemptId: `arena_attempt_${'b'.repeat(32)}`,
    attemptNonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    refusedAt: '2026-08-02T12:00:00.000Z',
    expiresAt: '2026-08-09T12:00:00.000Z',
    signer: {
      issuer_id: 'arena:emilia:session',
      key_id: 'arena-key-1',
      private_key: keys.privateKey,
    },
  });
  const binding = deriveArenaActionBinding(action);
  const projection = {
    profile: 'EP-ARENA-PUBLIC-REFUSAL-v1',
    challenge_id: 'emilia.arena.allowance',
    challenge_version: 1,
    attempt: {
      attempt_id: `arena_attempt_${'b'.repeat(32)}`,
      action, caid: binding.caid, action_digest: binding.action_digest,
      decision: 'refuse', reason: 'allowance_per_action_limit_exceeded',
      created_at: '2026-08-02T12:00:00.000Z',
    },
    refusal_artifact: artifact.statement,
    refusal_digest: artifact.refusal_digest,
    issuer: {
      issuer_id: 'arena:emilia:session', key_id: 'arena-key-1',
      public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    claim_boundary: 'synthetic_challenge_not_identity_competence_certification_money_or_production_authority',
  };
  return { projection };
}

describe('Arena refusal publication verification', () => {
  it('verifies exact-action integrity while refusing to claim authorization acceptance', () => {
    const { projection } = fixture();
    const result = verifyArenaPublicProjection(projection, Date.parse('2026-08-02T12:01:00.000Z'));
    expect(result.integrity_verified).toBe(true);
    expect(result.currently_valid).toBe(true);
    expect(result.accepted).toBeNull();
    expect(result.issuer_trust).toBe('arena_session_key_from_public_record');
  });

  it('keeps historical signature verification separate from current validity', () => {
    const { projection } = fixture();
    const result = verifyArenaPublicProjection(projection, Date.parse('2026-08-10T00:00:00.000Z'));
    expect(result.integrity_verified).toBe(true);
    expect(result.currently_valid).toBe(false);
    expect(result.current_reason).toBe('refusal_expired');
  });

  it('accepts PostgreSQL microsecond rendering of the signed millisecond instant', () => {
    const { projection } = fixture();
    projection.attempt.created_at = '2026-08-02T12:00:00.000085+00:00';
    const result = verifyArenaPublicProjection(projection, Date.parse('2026-08-02T12:01:00.000Z'));
    expect(result.integrity_verified).toBe(true);
  });

  it('refuses a PostgreSQL timestamp in the next signed millisecond', () => {
    const { projection } = fixture();
    projection.attempt.created_at = '2026-08-02T12:00:00.001085+00:00';
    const result = verifyArenaPublicProjection(projection, Date.parse('2026-08-02T12:01:00.000Z'));
    expect(result.integrity_verified).toBe(false);
    expect(result.reason).toBe('arena_projection_binding_mismatch');
  });

  it.each(['amount', 'action_digest', 'public_key', 'reason', 'created_at'])('fails closed on projection or key substitution', (field) => {
    const { projection } = fixture();
    const tampered: any = structuredClone(projection);
    if (field === 'amount') tampered.attempt.action.amount = 1;
    if (field === 'action_digest') tampered.attempt.action_digest = `sha256:${'f'.repeat(64)}`;
    if (field === 'public_key') tampered.issuer.public_key = crypto.generateKeyPairSync('ed25519').publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    if (field === 'reason') tampered.attempt.reason = 'allowance_target_not_allowed';
    if (field === 'created_at') tampered.attempt.created_at = '2099-01-01T00:00:00.000Z';
    expect(verifyArenaPublicProjection(tampered).integrity_verified).toBe(false);
  });
});
