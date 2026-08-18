// SPDX-License-Identifier: Apache-2.0
//
// EP-ARENA-PUBLIC-REFUSAL-v2 hostile matrix: adoption of the ALREADY-BUILT
// EP-ACTION-REFUSAL-STATEMENT-v2 hybrid signer/verifier
// (packages/gate/src/action-refusal-statement.ts) through the arena's public
// refusal delegator (lib/arena/refusal.ts). The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  createArenaAllowance,
  deriveArenaActionBinding,
  type ArenaAction,
} from './core';
import {
  PUBLIC_PROFILE_V2,
  signArenaRefusal,
  signArenaRefusalV2,
  verifyArenaPublicProjection,
  verifyArenaPublicProjectionV2,
  ARENA_PUBLIC_CLAIM_BOUNDARY,
} from './refusal';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const CHALLENGE_ID = 'emilia.arena.allowance';
const CHALLENGE_VERSION = 1;

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const ISSUER_ID = 'ep:arena:issuer:test';
const KEY_ID = 'ep:arena:key:test';

function allowance() {
  return createArenaAllowance({
    sessionId: 'arena-session-v2-001',
    agentName: 'Hybrid Test Agent',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['compute.batch', 'vendor.demo'],
    issuedAt: '2026-08-17T11:59:00.000Z',
    expiresAt: '2026-08-18T11:59:00.000Z',
  });
}

function action(overrides: Record<string, unknown> = {}): ArenaAction {
  return {
    operation_id: 'operation-v2-001',
    action_type: 'arena.resource.allocate.1',
    target: 'production.database',
    amount: 900,
    currency: 'CREDITS',
    purpose: 'synthetic-production-change',
    ...overrides,
  } as ArenaAction;
}

async function buildSignedV2(now = '2026-08-17T12:00:00.000Z') {
  const binding = deriveArenaActionBinding(action());
  const signed = await signArenaRefusalV2({
    allowance: allowance(),
    action: action(),
    reason: 'allowance_target_not_allowed',
    attemptId: 'attempt-v2-001',
    attemptNonce: 'nonce-v2-001',
    refusedAt: now,
    expiresAt: '2026-08-24T12:00:00.000Z',
    signer: {
      issuer_id: ISSUER_ID,
      key_id: KEY_ID,
      private_key: ed.privateKey,
      pq_public_key: pqPubB64u,
      pq_private_key: pqPrivB64u,
    },
  });
  return { signed, binding };
}

function projectionOf(signed: any, binding: any, now = '2026-08-17T12:00:00.000Z') {
  return {
    profile: PUBLIC_PROFILE_V2,
    challenge_id: CHALLENGE_ID,
    challenge_version: CHALLENGE_VERSION,
    attempt: {
      attempt_id: 'attempt-v2-001',
      action: action(),
      caid: binding.caid,
      action_digest: binding.action_digest,
      decision: 'refuse',
      reason: 'allowance_target_not_allowed',
      created_at: now,
    },
    refusal_artifact: signed.statement,
    refusal_digest: signed.refusal_digest,
    issuer: { issuer_id: ISSUER_ID, key_id: KEY_ID, public_key: edPubB64u, pq_public_key: pqPubB64u },
    claim_boundary: ARENA_PUBLIC_CLAIM_BOUNDARY,
  };
}

describe('EP-ARENA-PUBLIC-REFUSAL-v2 adoption hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid arena refusal verifies under both pinned keys', async () => {
    const { signed, binding } = await buildSignedV2();
    const res = await verifyArenaPublicProjectionV2(projectionOf(signed, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(true);
    expect(res.currently_valid).toBe(true);
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const { signed, binding } = await buildSignedV2();
    const tampered = { ...signed.statement, proof: { ...signed.statement.proof, signatures: signed.statement.proof.signatures.filter((s: any) => s.alg === 'Ed25519') } };
    const res = await verifyArenaPublicProjectionV2(projectionOf({ ...signed, statement: tampered }, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const { signed, binding } = await buildSignedV2();
    const tampered = { ...signed.statement, proof: { ...signed.statement.proof, signatures: signed.statement.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65') } };
    const res = await verifyArenaPublicProjectionV2(projectionOf({ ...signed, statement: tampered }, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const { signed, binding } = await buildSignedV2();
    const tampered = { ...signed.statement, proof: { ...signed.statement.proof, required_algorithms: ['Ed25519'] } };
    const res = await verifyArenaPublicProjectionV2(projectionOf({ ...signed, statement: tampered }, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated leg refuses without throwing', async () => {
    const { signed, binding } = await buildSignedV2();
    const sigs = signed.statement.proof.signatures.map((s: any) => (
      s.alg === 'Ed25519' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 5).toString('base64url') } : s
    ));
    const tampered = { ...signed.statement, proof: { ...signed.statement.proof, signatures: sigs } };
    const res = await verifyArenaPublicProjectionV2(projectionOf({ ...signed, statement: tampered }, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const { signed, binding } = await buildSignedV2();
    const tampered = { ...signed.statement, proof: { ...signed.statement.proof, public_key: ed448Pub } };
    const projection = projectionOf({ ...signed, statement: tampered }, binding);
    projection.issuer.public_key = ed448Pub;
    const res = await verifyArenaPublicProjectionV2(projection, Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
  });

  it('V1 REFUSES V2: verifyArenaPublicProjection (v1, sync) refuses a v2 projection cleanly on the profile marker, without throwing', async () => {
    const { signed, binding } = await buildSignedV2();
    const res = verifyArenaPublicProjection(projectionOf(signed, binding), Date.parse('2026-08-17T12:01:00.000Z'));
    expect(res.integrity_verified).toBe(false);
    expect(res.reason).toBe('arena_projection_invalid');
  });

  it('the v1 delegator (signArenaRefusal) still produces a v1 statement unaffected by v2 adoption', () => {
    const binding = deriveArenaActionBinding(action());
    const signed = signArenaRefusal({
      allowance: allowance(),
      action: action(),
      reason: 'allowance_target_not_allowed',
      attemptId: 'attempt-v1-001',
      attemptNonce: 'nonce-v1-001',
      refusedAt: '2026-08-17T12:00:00.000Z',
      expiresAt: '2026-08-24T12:00:00.000Z',
      signer: { issuer_id: ISSUER_ID, key_id: KEY_ID, private_key: ed.privateKey },
    });
    expect(signed.statement['@version']).not.toBe('EP-ACTION-REFUSAL-STATEMENT-v2');
    void binding;
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyArenaPublicProjectionV2(junk as any, Date.now());
      expect(res.integrity_verified).toBe(false);
    }
  });
});
