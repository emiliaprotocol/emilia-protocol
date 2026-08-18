// SPDX-License-Identifier: Apache-2.0
// Generated from execution-value-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-EXECUTION-VALUE-ATTESTATION-v2 hybrid migration test (fresh, following
// the EP-REVOCATION-v2 reference pattern in docs/protocol/pq-hybrid-program.md
// directly via packages/verify/src/pq-signature-agility.ts). Hostile matrix:
// stripped leg, narrowed set, wrong-length signature, Ed448 masquerade,
// v1-refuses-v2, valid v2 roundtrip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { EXECUTION_VALUE_ATTESTATION_V2_VERSION, signExecutionValueAttestation, signExecutionValueAttestationV2, verifyExecutionValueAttestation, verifyExecutionValueAttestationV2, } from './execution-value.js';
import { hashCanonical } from './execution-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-08-03T12:00:00.000Z');
const ACTION = {
    action_type: 'trade.execute',
    instrument: 'EURUSD',
    amount: 10_000,
    currency: 'EUR',
    order_id: 'order-1',
};
function material() {
    const pair = generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(new Uint8Array(32).fill(17));
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const pqPublicKey = Buffer.from(pq.publicKey).toString('base64url');
    return {
        pair, pq, publicKey, pqPublicKey,
        trustedKeys: { 'oracle-key-v2': { public_key: publicKey, pq_public_key: pqPublicKey } },
    };
}
function payloadInput() {
    return {
        action_digest: `sha256:${hashCanonical(ACTION)}`,
        asset_currency: 'EUR',
        quote_currency: 'USD',
        value_minor: 1_080_000,
        source: 'oracle.example/v1',
        key_id: 'oracle-key-v2',
        observed_at: new Date(NOW - 1_000).toISOString(),
        expires_at: new Date(NOW + 5_000).toISOString(),
    };
}
function options(m) {
    return {
        action: ACTION,
        trustedKeys: m.trustedKeys,
        allowedSources: ['oracle.example/v1'],
        maxValueMinor: 1_100_000,
        now: NOW,
    };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid attestation verifies under both pinned keys', async () => {
    const m = material();
    const attestation = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    assert.equal(attestation.payload.version, EXECUTION_VALUE_ATTESTATION_V2_VERSION);
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, true, verified.reason);
});
test('the v1 verifier refuses a v2 attestation cleanly on the version marker', async () => {
    const m = material();
    const attestation = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const verified = verifyExecutionValueAttestation(attestation, { ...options(m), trustedKeys: { 'oracle-key-v2': m.publicKey } });
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, 'execution_value_attestation_malformed');
});
test('the v1 verifier still accepts a v1 attestation, unchanged', () => {
    const m = material();
    const attestation = signExecutionValueAttestation(payloadInput(), m.pair.privateKey);
    const verified = verifyExecutionValueAttestation(attestation, { ...options(m), trustedKeys: { 'oracle-key-v2': m.publicKey } });
    assert.equal(verified.ok, true, verified.reason);
});
test('the v2 verifier refuses a v1 attestation on the version marker', async () => {
    const m = material();
    const attestation = signExecutionValueAttestation(payloadInput(), m.pair.privateKey);
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, 'execution_value_attestation_malformed');
});
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const m = material();
    const signed = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const attestation = structuredClone(signed);
    attestation.proof.signatures = attestation.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, 'execution_value_proof_missing_ML-DSA-65');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const m = material();
    const signed = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const attestation = structuredClone(signed);
    attestation.proof.signatures = attestation.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, false);
});
test('SET NARROWING: dropping the PQ leg and narrowing required_algorithms fails both ways', async () => {
    const m = material();
    const signed = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const attestation = structuredClone(signed);
    attestation.proof.required_algorithms = ['Ed25519'];
    attestation.proof.signatures = attestation.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, false);
});
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 signature refuses', async () => {
    const m = material();
    const signed = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const attestation = structuredClone(signed);
    attestation.proof.signatures = attestation.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, sig: s.sig.slice(0, -4) } : s));
    const verified = await verifyExecutionValueAttestationV2(attestation, options(m));
    assert.equal(verified.ok, false);
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const m = material();
    const attestation = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const ed448 = generateKeyPairSync('ed448');
    const verified = await verifyExecutionValueAttestationV2(attestation, {
        ...options(m),
        trustedKeys: { 'oracle-key-v2': { public_key: ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), pq_public_key: m.pqPublicKey } },
    });
    assert.equal(verified.ok, false);
});
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const m = material();
    const attestation = await signExecutionValueAttestationV2(payloadInput(), { privateKey: m.pair.privateKey, pqPrivateKey: Buffer.from(m.pq.secretKey).toString('base64url') });
    const verified = await verifyExecutionValueAttestationV2(attestation, { ...options(m), mldsaBackendLoader: async () => null });
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, 'execution_value_pq_backend_unavailable');
});
