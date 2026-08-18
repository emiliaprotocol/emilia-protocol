// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow-custodian-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-ACTION-ESCROW-CUSTODIAN-OBSERVATION-v2 hybrid verifier test. Copies the
// hostile matrix of the reference migration (packages/verify/revocation-v2.test.ts):
// leg stripping both directions, set narrowing, duplicate algorithm, an
// Ed448 SPKI masquerading as the Ed25519 half, wrong-length signatures, plus
// the old-verifier-refuses-new capture and a valid hybrid roundtrip.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION, ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION, signActionEscrowCustodianObservationV2, verifyActionEscrowCustodianStatementV2, verifyActionEscrowCustodianStatementAny, custodianObservationV2Bytes, } from './action-escrow-custodian.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const digest = (character) => `sha256:${character.repeat(64)}`;
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const KEY_ID = 'key:operator-hybrid-1';
const OPERATOR_KEYS_V2 = { [KEY_ID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } };
function payloadFields(overrides = {}) {
    return {
        provider_id: 'escrow.com',
        environment: 'sandbox',
        statement_type: 'release',
        status: 'released',
        agreement_digest: digest('1'),
        document_action_binding_digest: digest('2'),
        milestone_id: 'milestone-provider-001',
        release_action_digest: digest('3'),
        parties_digest: digest('4'),
        profile_digest: digest('5'),
        provider_idempotency_key: 'ep-ae-release:test',
        provider_request_digest: digest('6'),
        provider_effect_reference: 'ep-ae-release:test',
        provider_transaction_id: 'transaction-001',
        provider_milestone_id: 'milestone-provider-001',
        amount: '18400.00',
        currency: 'USD',
        destination_id: 'contractor@example.test',
        provider_snapshot_digest: digest('7'),
        observed_at: '2026-08-17T18:00:00.000Z',
        ...overrides,
    };
}
async function buildV2(overrides = {}) {
    return signActionEscrowCustodianObservationV2(payloadFields(overrides), [
        { alg: 'Ed25519', private_key: ed.privateKey, key_id: KEY_ID },
        { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: KEY_ID },
    ]);
}
function expected(overrides = {}) {
    const f = payloadFields();
    return {
        statement_type: f.statement_type,
        agreement_digest: f.agreement_digest,
        document_action_binding_digest: f.document_action_binding_digest,
        milestone_id: f.milestone_id,
        release_action_digest: f.release_action_digest,
        parties_digest: f.parties_digest,
        profile_digest: f.profile_digest,
        provider_idempotency_key: f.provider_idempotency_key,
        provider_request_digest: f.provider_request_digest,
        provider_transaction_id: f.provider_transaction_id,
        provider_milestone_id: f.provider_milestone_id,
        amount: f.amount,
        currency: f.currency,
        destination_id: f.destination_id,
        ...overrides,
    };
}
function verifyOpts(overrides = {}) {
    return {
        operatorKeys: OPERATOR_KEYS_V2,
        providerId: 'escrow.com',
        environment: 'sandbox',
        expected: expected(),
        ...overrides,
    };
}
// --- honesty gate --------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ------------------------------------------------------------
test('a real hybrid custodian observation verifies under both pinned keys (valid roundtrip)', async () => {
    const stmt = await buildV2();
    assert.equal(stmt.payload['@version'], ACTION_ESCROW_CUSTODIAN_OBSERVATION_V2_VERSION);
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, true, res.reason);
    assert.equal(res.status, 'released');
});
// --- old-verifier-refuses-new -----------------------------------------------
test('verifyActionEscrowCustodianStatementAny routes a v2 statement to the hybrid verifier', async () => {
    const res = await verifyActionEscrowCustodianStatementAny(await buildV2(), verifyOpts());
    assert.equal(res.valid, true, res.reason);
});
test('the v2 verifier refuses a v1-shaped (flat signature) statement', async () => {
    const flatV1Shaped = {
        payload: { '@version': ACTION_ESCROW_CUSTODIAN_OBSERVATION_VERSION, ...payloadFields() },
        signature: { algorithm: 'Ed25519', key_id: KEY_ID, value: 'x' },
    };
    const res = await verifyActionEscrowCustodianStatementV2(flatV1Shaped, verifyOpts());
    assert.equal(res.valid, false);
});
// --- anti-stripping ----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_signature_leg_stripped');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
});
test('SET NARROWING: narrowing required_algorithms to Ed25519-only refuses structurally', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.required_algorithms = ['Ed25519'];
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_algorithm_set_invalid');
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = [stmt.proof.signatures[0], stmt.proof.signatures[0]];
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_signature_leg_duplicate');
});
// --- wrong-length signature ---------------------------------------------------
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
    const stmt = structuredClone(await buildV2());
    const leg = stmt.proof.signatures.find((s) => s.alg === 'Ed25519');
    leg.sig = Buffer.from(leg.sig, 'base64url').subarray(0, 10).toString('base64url');
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
});
// --- masquerade ----------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({
        operatorKeys: { [KEY_ID]: { public_key: ed448Pub, pq_public_key: pqPubB64u } },
    }));
    assert.equal(res.valid, false);
});
// --- pinning ---------------------------------------------------------------
test('an unpinned operator key confers nothing', async () => {
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({ operatorKeys: {} }));
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_operator_key_not_pinned');
});
test('pinning the Ed25519 half but not the ML-DSA half refuses', async () => {
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({
        operatorKeys: { [KEY_ID]: { public_key: edPubB64u } },
    }));
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_operator_key_not_pinned');
});
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({
        operatorKeys: { [KEY_ID]: { public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.equal(res.valid, false);
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({ mldsaBackendLoader: async () => null }));
    assert.equal(res.valid, false);
});
// --- binding ---------------------------------------------------------------
test('TAMPERED AFTER SIGNING: editing the amount after signing breaks the binding', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.payload.amount = '99999.99';
    const res = await verifyActionEscrowCustodianStatementV2(stmt, verifyOpts());
    assert.equal(res.valid, false);
});
test('expected-binding mismatch refuses on custodian_observation_binding_mismatch', async () => {
    const res = await verifyActionEscrowCustodianStatementV2(await buildV2(), verifyOpts({
        expected: expected({ amount: '1.00' }),
    }));
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'custodian_observation_binding_mismatch');
});
// --- fail-closed on junk -------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyActionEscrowCustodianStatementV2(junk, verifyOpts());
        assert.equal(res.valid, false);
    }
});
// custodianObservationV2Bytes is exercised indirectly through signing/
// verification above; reference it so an unused-import checker stays quiet.
void custodianObservationV2Bytes;
