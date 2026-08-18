// SPDX-License-Identifier: Apache-2.0
//
// EP-TRUSTED-CONTEXT-BINDING-v2 hybrid migration test (fresh, following the
// EP-REVOCATION-v2 reference pattern in docs/protocol/pq-hybrid-program.md
// directly via packages/verify/src/pq-signature-agility.ts). Hostile matrix:
// stripped leg, narrowed set, wrong-length signature, Ed448 masquerade,
// v1-refuses-v2, valid v2 roundtrip.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import {
  TRUSTED_CONTEXT_BINDING_V2_VERSION,
  canonicalContextRecordDigest,
  signTrustedContextBindingV2,
  trustedContextActionSubjectDigest,
  verifyTrustedContextBindingV2,
} from './trusted-context.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const NOW = '2026-08-10T12:00:00.000Z';

function digest(label: string) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function projectionRecord() {
  return { projection: { digest: digest('projection') }, other: 'field' };
}

function action() {
  return { action_type: 'agent.spend', amount: 100 };
}

function material() {
  const pair = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(23));
  return {
    pair, pq,
    pin: {
      public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
    },
  };
}

async function buildBinding(m: ReturnType<typeof material>, overrides: Record<string, any> = {}) {
  return signTrustedContextBindingV2({
    providerId: 'provider:memory:01',
    providerProfile: 'profile:default',
    projectionRecord: projectionRecord(),
    action: action(),
    policyDigest: digest('policy'),
    nonce: 'nonce-v2-01',
    issuedAt: '2026-08-10T11:59:00.000Z',
    expiresAt: '2026-08-10T12:05:00.000Z',
    binderId: 'binder:example',
    keyId: 'key:binder-ed25519',
    privateKey: m.pair.privateKey,
    pqKeyId: 'key:binder-ml-dsa',
    pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url'),
    ...overrides,
  });
}

function verifyOptions(m: ReturnType<typeof material>) {
  return {
    action: action(),
    projectionRecordDigest: canonicalContextRecordDigest(projectionRecord()),
    projectionDigest: digest('projection'),
    policyDigest: digest('policy'),
    expectedNonce: 'nonce-v2-01',
    verificationTime: NOW,
    pin: m.pin,
  };
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid binding verifies under both pinned keys', async () => {
  const m = material();
  const binding: any = await buildBinding(m);
  assert.equal(binding['@version'], TRUSTED_CONTEXT_BINDING_V2_VERSION);
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'VERIFIED', result.reason ?? '');
});

test('the v2 verifier refuses a stale @version marker cleanly', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding['@version'] = 'EP-TRUSTED-CONTEXT-BINDING-v1';
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'NOT_VERIFIED');
  assert.ok(result.reason?.startsWith('unsupported_version'));
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding.proof.signatures = binding.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'NOT_VERIFIED');
  assert.equal(result.reason, 'context_binding_missing_ML-DSA-65_signature');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding.proof.signatures = binding.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'NOT_VERIFIED');
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails both structurally and cryptographically', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding.proof.required_algorithms = ['Ed25519'];
  binding.proof.signatures = binding.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'NOT_VERIFIED');
});

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding.proof.signatures = binding.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s));
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  assert.equal(result.state, 'NOT_VERIFIED');
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const binding = await buildBinding(m);
  const ed448 = generateKeyPairSync('ed448');
  const result = await verifyTrustedContextBindingV2(binding, {
    ...verifyOptions(m),
    pin: { public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), pq_public_key: m.pin.pq_public_key },
  });
  assert.equal(result.state, 'NOT_VERIFIED');
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const binding = await buildBinding(m);
  const result = await verifyTrustedContextBindingV2(binding, { ...verifyOptions(m), mldsaBackendLoader: async () => null });
  assert.equal(result.state, 'NOT_VERIFIED');
  assert.equal(result.reason, 'context_binding_pq_backend_unavailable');
});

test('TAMPERED AFTER SIGNING: editing nonce breaks the binding of both legs', async () => {
  const m = material();
  const binding: any = structuredClone(await buildBinding(m));
  binding.nonce = 'tampered-nonce';
  const result = await verifyTrustedContextBindingV2(binding, verifyOptions(m));
  // Either the expected-nonce mismatch fires first, or the signature check
  // does; either way this must never verify.
  assert.equal(result.state, 'NOT_VERIFIED');
});

test('subject digest mismatch (action swapped after signing) refuses', async () => {
  const m = material();
  const binding = await buildBinding(m);
  const result = await verifyTrustedContextBindingV2(binding, {
    ...verifyOptions(m),
    action: { action_type: 'agent.spend', amount: 999 },
  });
  assert.equal(result.state, 'NOT_VERIFIED');
  assert.equal(result.reason, 'action_context_binding_mismatch');
});
