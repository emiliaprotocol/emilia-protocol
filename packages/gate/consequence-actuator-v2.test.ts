// SPDX-License-Identifier: Apache-2.0
//
// EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v2 hybrid migration test (fresh, following
// the EP-REVOCATION-v2 reference pattern in docs/protocol/pq-hybrid-program.md
// directly via packages/verify/src/pq-signature-agility.ts). Hostile matrix:
// stripped leg, narrowed set, wrong-length signature, Ed448 masquerade,
// v1-refuses-v2, valid v2 roundtrip.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION,
  CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
  signConsequenceExecutionEnvelope,
  signConsequenceExecutionEnvelopeV2,
  verifyConsequenceExecutionEnvelope,
  verifyConsequenceExecutionEnvelopeV2,
} from './src/consequence-actuator.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const NOW = Date.parse('2026-07-25T01:00:00.000Z');
const ACTION_DIGEST = `sha256:${'a'.repeat(64)}`;
const TARGET_DIGEST = `sha256:${'c'.repeat(64)}`;
const CAID = `caid:1:example.execute.1:jcs-sha256:${'A'.repeat(43)}`;

function payloadV2(overrides: Record<string, any> = {}) {
  return {
    '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION,
    issuer_id: 'authorization-service',
    tenant_id: 'tenant-1',
    attempt_id: 'attempt-1',
    action_digest: ACTION_DIGEST,
    caid: CAID,
    provider_account_id: 'provider-account-1',
    target_digest: TARGET_DIGEST,
    operation: 'payment.capture',
    idempotency_key: 'operation-1',
    nonce: randomBytes(24).toString('base64url'),
    issued_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 30_000).toISOString(),
    ...overrides,
  };
}

function material() {
  const ed = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(29));
  return { ed, pq };
}

function pinsV2(m: ReturnType<typeof material>) {
  return {
    tenantId: 'tenant-1',
    caid: CAID,
    providerAccountId: 'provider-account-1',
    targetDigest: TARGET_DIGEST,
    operation: 'payment.capture',
    envelopeIssuerId: 'authorization-service',
    envelopeKeyId: 'actuator-key-v2',
    envelopePublicKey: m.ed.publicKey,
    envelopePqKeyId: 'actuator-pq-key-v2',
    envelopePqPublicKey: Buffer.from(m.pq.publicKey).toString('base64url'),
    maxEnvelopeTtlMs: 60_000,
    clockSkewMs: 2_000,
  };
}

function expected() {
  return { attemptId: 'attempt-1', actionDigest: ACTION_DIGEST, idempotencyKey: 'operation-1' };
}

async function sign(m: ReturnType<typeof material>, overrides: Record<string, any> = {}) {
  return signConsequenceExecutionEnvelopeV2(payloadV2(overrides) as any, {
    privateKey: m.ed.privateKey,
    keyId: 'actuator-key-v2',
    pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url'),
    pqKeyId: 'actuator-pq-key-v2',
  });
}

test('real ML-DSA-65 backend is available for this suite', () => {
  assert.ok(typeof ml_dsa65?.sign === 'function');
});

test('a real hybrid envelope verifies under both pinned keys', async () => {
  const m = material();
  const envelope: any = await sign(m);
  assert.equal(envelope.payload['@version'], CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION);
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, true, (verified as any).reason);
});

test('the v1 verifier refuses a v2 envelope cleanly on shape', async () => {
  const m = material();
  const envelope: any = await sign(m);
  const verified = verifyConsequenceExecutionEnvelope(envelope, {
    pins: { ...pinsV2(m), envelopeKeyId: 'actuator-key-v2' } as any,
    expected: expected(),
    now: NOW,
  });
  assert.equal(verified.ok, false);
});

test('the v1 verifier still accepts a v1 envelope, unchanged', () => {
  const m = material();
  const envelope = signConsequenceExecutionEnvelope(
    { '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION, ...payloadV2({ '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION }) } as any,
    { privateKey: m.ed.privateKey, keyId: 'actuator-key-v1' },
  );
  const verified = verifyConsequenceExecutionEnvelope(envelope, {
    pins: { ...pinsV2(m), envelopeKeyId: 'actuator-key-v1' } as any,
    expected: expected(),
    now: NOW,
  });
  assert.equal(verified.ok, true, (verified as any).reason);
});

test('the v2 verifier refuses a v1 envelope on the version marker', async () => {
  const m = material();
  const envelope = signConsequenceExecutionEnvelope(
    { '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION, ...payloadV2({ '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION }) } as any,
    { privateKey: m.ed.privateKey, keyId: 'actuator-key-v2' },
  );
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
  assert.equal((verified as any).reason, 'malformed_envelope');
});

test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
  const m = material();
  const signed: any = await sign(m);
  const envelope = structuredClone(signed);
  envelope.proof.signatures = envelope.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
  assert.equal((verified as any).reason, 'signature_invalid');
});

test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
  const m = material();
  const signed: any = await sign(m);
  const envelope = structuredClone(signed);
  envelope.proof.signatures = envelope.proof.signatures.filter((s: any) => s.alg === 'ML-DSA-65');
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
});

test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails both structurally and cryptographically', async () => {
  const m = material();
  const signed: any = await sign(m);
  const envelope = structuredClone(signed);
  envelope.proof.required_algorithms = ['Ed25519'];
  envelope.proof.signatures = envelope.proof.signatures.filter((s: any) => s.alg === 'Ed25519');
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
});

test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
  const m = material();
  const signed: any = await sign(m);
  const envelope = structuredClone(signed);
  envelope.proof.signatures = envelope.proof.signatures.map((s: any) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s));
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
});

test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
  const m = material();
  const envelope = await sign(m);
  const ed448 = generateKeyPairSync('ed448');
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, {
    pins: { ...pinsV2(m), envelopePublicKey: ed448.publicKey },
    expected: expected(),
    now: NOW,
  });
  assert.equal(verified.ok, false);
});

test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
  const m = material();
  const envelope = await sign(m);
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, {
    pins: pinsV2(m), expected: expected(), now: NOW, mldsaBackendLoader: async () => null,
  });
  assert.equal(verified.ok, false);
  assert.equal((verified as any).reason, 'pq_backend_unavailable');
});

test('TAMPERED AFTER SIGNING: editing the target digest breaks both legs', async () => {
  const m = material();
  const signed: any = await sign(m);
  const envelope = structuredClone(signed);
  envelope.payload.target_digest = `sha256:${'e'.repeat(64)}`;
  const verified = await verifyConsequenceExecutionEnvelopeV2(envelope, { pins: pinsV2(m), expected: expected(), now: NOW });
  assert.equal(verified.ok, false);
});
