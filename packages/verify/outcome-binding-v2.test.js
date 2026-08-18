// SPDX-License-Identifier: Apache-2.0
// Generated from outcome-binding-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-OUTCOME-ATTESTATION-v2 / EP-OUTCOME-OBSERVATION-v2 hybrid verifier test:
// the reference hybrid migration for both signed leaves in outcome-binding.ts.
// Builds REAL Ed25519 + ML-DSA-65 signed artifacts, then asserts the
// fail-closed predicate: leg stripping, set narrowing, a wrong-length
// signature, an Ed448 masquerade, missing PQ backend, and a v1 verifier
// refusing a v2 artifact.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { OUTCOME_V2_REQUIRED_ALGORITHMS, buildOutcomeAttestation, buildOutcomeAttestationV2, verifyOutcomeAttestation, verifyOutcomeAttestationV2, buildOutcomeObservation, buildOutcomeObservationV2, verifyOutcomeObservation, verifyOutcomeObservationV2, } from './outcome-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
const OBSERVED_EFFECTS = [{ effect_type: 'transfer', target: 'acct1', value: '100' }];
async function buildAttestationV2() {
    return buildOutcomeAttestationV2({
        receipt_id: 'r1', receipt_digest: `sha256:${'a'.repeat(64)}`, action_hash: `sha256:${'b'.repeat(64)}`,
        consumption_nonce: 'n1', execution_id: 'e1', executor_id: 'ex1', executed_at: '2026-06-01T00:00:00Z',
        observed_effects: OBSERVED_EFFECTS,
        signer: { privateKey: ed.privateKey, pqPrivateKey: pqSecretB64u, pqPublicKey: pqPubB64u },
    });
}
const EXECUTOR_KEYS = { ex1: { public_key: edPubB64u, pq_public_key: pqPubB64u } };
const ATT_OPTS = { executorKeys: EXECUTOR_KEYS, now: '2026-06-01T01:00:00Z' };
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid outcome attestation verifies under both pinned keys', async () => {
    const attestation = await buildAttestationV2();
    const res = await verifyOutcomeAttestationV2(attestation, ATT_OPTS);
    assert.equal(res.valid, true, res.errors.join(' | '));
});
test('the v1 attestation verifier refuses a v2 attestation cleanly', async () => {
    const attestation = await buildAttestationV2();
    const res = verifyOutcomeAttestation(attestation, ATT_OPTS);
    assert.equal(res.valid, false);
    assert.ok(res.errors.includes('malformed_outcome_attestation'));
});
test('the v2 attestation verifier refuses a v1 attestation', () => {
    const v1 = buildOutcomeAttestation({
        receipt_id: 'r1', receipt_digest: `sha256:${'a'.repeat(64)}`, action_hash: `sha256:${'b'.repeat(64)}`,
        consumption_nonce: 'n1', execution_id: 'e1', executor_id: 'ex1', executed_at: '2026-06-01T00:00:00Z',
        observed_effects: OBSERVED_EFFECTS,
        signer: { privateKey: ed.privateKey },
    });
    return verifyOutcomeAttestationV2(v1, ATT_OPTS).then((res) => {
        assert.equal(res.valid, false);
    });
});
test('ATTESTATION LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const attestation = await buildAttestationV2();
    attestation.proof.signatures = attestation.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyOutcomeAttestationV2(attestation, ATT_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('ATTESTATION SET NARROWING: a narrowed required_algorithms fails structurally', async () => {
    const attestation = await buildAttestationV2();
    attestation.required_algorithms = ['Ed25519'];
    const res = await verifyOutcomeAttestationV2(attestation, ATT_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.checks.algorithm_set, false);
});
test('ATTESTATION WRONG-LENGTH SIGNATURE refuses', async () => {
    const attestation = await buildAttestationV2();
    const edSig = attestation.proof.signatures.find((s) => s.alg === 'Ed25519');
    edSig.sig = edSig.sig.slice(0, -4);
    const res = await verifyOutcomeAttestationV2(attestation, ATT_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('ATTESTATION ED448 MASQUERADE refuses', async () => {
    const attestation = await buildAttestationV2();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyOutcomeAttestationV2(attestation, {
        executorKeys: { ex1: { public_key: ed448PubB64u, pq_public_key: pqPubB64u } },
        now: '2026-06-01T01:00:00Z',
    });
    assert.equal(res.valid, false);
});
test('ATTESTATION NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const attestation = await buildAttestationV2();
    const res = await verifyOutcomeAttestationV2(attestation, { ...ATT_OPTS, mldsaBackendLoader: async () => null });
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// ── EP-OUTCOME-OBSERVATION-v2 ─────────────────────────────────────────────
async function buildObservationV2() {
    return buildOutcomeObservationV2({
        receipt_id: 'r1', receipt_digest: `sha256:${'a'.repeat(64)}`, action_hash: `sha256:${'b'.repeat(64)}`,
        consumption_nonce: 'n1', operation_id: 'op1',
        source: { role: 'executor', source_id: 'src1', source_class: 'system' },
        observed_from: '2026-06-01T00:00:00Z', observed_until: '2026-06-01T00:01:00Z', attested_at: '2026-06-01T00:02:00Z',
        observed_effects: OBSERVED_EFFECTS,
        signer: { privateKey: ed.privateKey, pqPrivateKey: pqSecretB64u, pqPublicKey: pqPubB64u },
    });
}
const SOURCE_KEYS = {
    src1: {
        public_key: edPubB64u, pq_public_key: pqPubB64u, role: 'executor', source_class: 'system',
        valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z', status: 'active',
    },
};
const OBS_OPTS = { sourceKeys: SOURCE_KEYS, now: '2026-06-01T01:00:00Z' };
test('a real hybrid outcome observation verifies under both pinned keys', async () => {
    const observation = await buildObservationV2();
    const res = await verifyOutcomeObservationV2(observation, OBS_OPTS);
    assert.equal(res.valid, true, res.errors.join(' | '));
});
test('the v1 observation verifier refuses a v2 observation cleanly', async () => {
    const observation = await buildObservationV2();
    const res = verifyOutcomeObservation(observation, OBS_OPTS);
    assert.equal(res.valid, false);
    assert.ok(res.errors.includes('malformed_outcome_observation'));
});
test('OBSERVATION LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const observation = await buildObservationV2();
    observation.proof.signatures = observation.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyOutcomeObservationV2(observation, OBS_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
test('OBSERVATION SET NARROWING fails structurally', async () => {
    const observation = await buildObservationV2();
    observation.required_algorithms = ['Ed25519'];
    const res = await verifyOutcomeObservationV2(observation, OBS_OPTS);
    assert.equal(res.valid, false);
    assert.equal(res.checks.algorithm_set, false);
});
test('OBSERVATION ED448 MASQUERADE refuses', async () => {
    const observation = await buildObservationV2();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyOutcomeObservationV2(observation, {
        sourceKeys: { src1: { ...SOURCE_KEYS.src1, public_key: ed448PubB64u } },
        now: '2026-06-01T01:00:00Z',
    });
    assert.equal(res.valid, false);
});
test('the registered required algorithm set is fixed and Ed25519-first', () => {
    assert.deepEqual([...OUTCOME_V2_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
});
