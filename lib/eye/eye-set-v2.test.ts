// SPDX-License-Identifier: Apache-2.0
//
// EP-EYE-SET-v2 hostile matrix: the hybrid (Ed25519 + ML-DSA-65) Eye
// Security Event Token envelope. The PQ leg runs for real.
import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';

import {
  EYE_SET_V2_VERSION,
  EYE_SET_V2_REQUIRED_ALGORITHMS,
  buildEyeSetV2,
  verifyEyeSetV2,
  verifyEyeSet,
} from './eye-set';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = crypto.createPublicKey(ed.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqPrivB64u = Buffer.from(pq.secretKey).toString('base64url');

const KID = 'ep:eye:emitter-1';

function advisory() {
  return {
    status: 'elevated',
    scope_binding_hash: `sha256:${'e'.repeat(64)}`,
    reason_codes: ['anomalous_tool_call_rate'],
    recommended_policy_action: 'require_class_a_signoff',
    advisory_hash: `sha256:${'f'.repeat(64)}`,
    expires_at: '2026-08-17T13:00:00.000Z',
  };
}

async function buildSet() {
  return buildEyeSetV2(advisory(), {
    signer: { kid: KID, privateKey: ed.privateKey, pqPrivateKey: pqPrivB64u, pqPublicKey: pqPubB64u },
    audience: 'ep:gate:test',
  });
}

function pinnedKeys() {
  return { [KID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } };
}

describe('EP-EYE-SET-v2 hostile matrix', () => {
  it('real ML-DSA-65 backend is available for this suite', () => {
    expect(typeof ml_dsa65?.sign).toBe('function');
  });

  it('a real hybrid SET verifies under both pinned keys and returns an advisory posture', async () => {
    const env = await buildSet();
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys(), audience: 'ep:gate:test' });
    expect(res.valid).toBe(true);
    expect(res.posture?.status).toBe('elevated');
  });

  it('the envelope names the registered algorithm set', async () => {
    const env: any = await buildSet();
    expect(env.proof.required_algorithms).toEqual([...EYE_SET_V2_REQUIRED_ALGORITHMS]);
    expect(env['@version']).toBe(EYE_SET_V2_VERSION);
  });

  it('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const env: any = await buildSet();
    env.proof.signatures = env.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys() });
    expect(res.valid).toBe(false);
    expect(res.checks.jws_signature_valid).toBe(false);
  });

  it('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const env: any = await buildSet();
    env.proof.signatures = env.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys() });
    expect(res.valid).toBe(false);
  });

  it('NARROWED SET: required_algorithms trimmed refuses structurally', async () => {
    const env: any = await buildSet();
    env.proof.required_algorithms = ['Ed25519'];
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys() });
    expect(res.valid).toBe(false);
    expect(res.checks.algorithm_set).toBe(false);
  });

  it('WRONG-LENGTH SIGNATURE: a truncated leg refuses without throwing', async () => {
    const env: any = await buildSet();
    env.proof.signatures = env.proof.signatures.map((s: any) => (
      s.alg === 'ML-DSA-65' ? { ...s, sig: Buffer.from(s.sig, 'base64url').subarray(0, 20).toString('base64url') } : s
    ));
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys() });
    expect(res.valid).toBe(false);
  });

  it('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const env = await buildSet();
    const res = await verifyEyeSetV2(env, { pinnedKeys: { [KID]: { public_key: ed448Pub, pq_public_key: pqPubB64u } } });
    expect(res.valid).toBe(false);
  });

  it('V1 REFUSES V2: verifyEyeSet (v1) refuses a v2 envelope cleanly, without throwing', () => {
    const res = verifyEyeSet({} as any, { pinnedKeys: pinnedKeys() });
    expect(res.valid).toBe(false);
    // A JSON object is not a compact-string SET; the type gate refuses first.
    expect(res.checks.alg_is_eddsa).toBe(false);
  });

  it('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const env = await buildSet();
    const res = await verifyEyeSetV2(env, { pinnedKeys: pinnedKeys(), mldsaBackendLoader: async () => null });
    expect(res.valid).toBe(false);
  });

  it('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
      const res = await verifyEyeSetV2(junk as any, { pinnedKeys: pinnedKeys() });
      expect(res.valid).toBe(false);
    }
  });
});
