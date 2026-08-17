// SPDX-License-Identifier: Apache-2.0
// Generated from allowance-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-GATE-ALLOWANCE-v2 hybrid profile test. Builds a REAL Ed25519 + ML-DSA-65
// signed Gate allowance and runs the hostile matrix (leg stripping both ways,
// set narrowing structural + independent crypto.verify, widening, duplicate
// alg, Ed448 masquerade, relabelling, swapped legs, PQ key substitution, tamper
// after signing), plus domain refusals (expiry/window/context), the
// v1-refuses-v2 capture, and a v1 byte-identity regression.
//
// The PQ leg runs for real; this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync, sign } from 'node:crypto';
import { GATE_ALLOWANCE_VERSION, GATE_ALLOWANCE_V2_VERSION, signGateAllowance, verifyGateAllowance, signGateAllowanceV2, verifyGateAllowanceV2, } from './src/allowance.js';
import { capabilityBaseReceiptDigest } from './src/capability-receipt.js';
import { canonicalize } from './src/execution-binding.js';
import { RISK_HYBRID_PROFILE } from './src/reliance-risk-crypto.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-07-30T18:30:00.000Z');
const ISSUER = 'customer:acme';
const KEY_ID = 'key:allow';
const ed = generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const PINS = { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u, pq_public_key: pqPubB64u } };
const mutable = (x) => JSON.parse(JSON.stringify(x));
function receipt() {
    const payload = { receipt_id: 'r1', created_at: '2026-07-30T17:59:00.000Z', subject: 'o@x.test', claim: { action_type: 'gate.allowance.issue', outcome: 'allow', capability_only: true } };
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(payload)), ed.privateKey).toString('base64url') },
        public_key: edPubB64u,
    };
}
function allowanceInput() {
    const r = receipt();
    return {
        allowance_id: 'allowance:x:01', tenant_id: 'tenant:x', subject_id: 'agent:x', audience: 'gate:x',
        connector_id: 'stripe', action_type: 'stripe.payout.create', capability_id: 'cap:x',
        capability_issuer_key_digest: `sha256:${crypto.createHash('sha256').update(Buffer.from(edPubB64u, 'base64url')).digest('hex')}`,
        revision: 1, supersedes_allowance_digest: null,
        authorization_receipt_digest: capabilityBaseReceiptDigest(r),
        presentation_digest: `sha256:${crypto.createHash('sha256').update('pres').digest('hex')}`,
        issued_at: '2026-07-30T17:59:00.000Z', valid_from: '2026-07-30T18:00:00.000Z', expires_at: '2026-07-31T18:00:00.000Z',
        constraints: {
            currency: 'USD', aggregate_amount: 50000, max_amount_per_action: 5000,
            material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
            operation_id_field: 'operation_id', amount_field: 'amount', currency_field: 'currency', target_field: 'destination',
            allowed_targets: ['acct_a', 'acct_b'], allowed_values: {},
        },
    };
}
const signer = { issuer_id: ISSUER, key_id: KEY_ID, private_key: ed.privateKey, pq_private_key: pqSecretB64u };
const v1Signer = { issuer_id: ISSUER, key_id: KEY_ID, private_key: ed.privateKey };
function buildV2() {
    return signGateAllowanceV2(allowanceInput(), signer);
}
function opts(extra = {}) {
    return {
        trusted_keys: PINS, now: NOW,
        expected_allowance_id: 'allowance:x:01', expected_tenant_id: 'tenant:x', expected_subject_id: 'agent:x',
        expected_audience: 'gate:x', expected_connector_id: 'stripe', expected_authorizer_id: ISSUER,
        ...extra,
    };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
// --- happy path ---------------------------------------------------------------
test('a real hybrid allowance verifies under both pinned keys', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts());
    assert.equal(res.accepted, true, res.reason ?? '');
});
test('the proof carries the set shape and committed set', async () => {
    const a = await buildV2();
    assert.equal(a['@version'], GATE_ALLOWANCE_V2_VERSION);
    assert.equal(a.proof.profile, RISK_HYBRID_PROFILE);
    assert.deepEqual(a.proof.signatures.map((s) => s.alg), ['Ed25519', 'ML-DSA-65']);
});
// --- v1 / v2 compatibility ----------------------------------------------------
test('the v1 verifier refuses a v2 allowance (version/envelope marker)', async () => {
    const res = verifyGateAllowance(await buildV2(), {
        trusted_keys: { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u } },
        now: NOW, expected_allowance_id: 'allowance:x:01', expected_tenant_id: 'tenant:x', expected_subject_id: 'agent:x',
        expected_audience: 'gate:x', expected_connector_id: 'stripe', expected_authorizer_id: ISSUER,
    });
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_signature_invalid');
});
test('v1 signing is byte-identical and still verifies (regression)', () => {
    const a = signGateAllowance(allowanceInput(), v1Signer);
    const b = signGateAllowance(allowanceInput(), v1Signer);
    assert.equal(a['@version'], GATE_ALLOWANCE_VERSION);
    assert.equal(a.proof.algorithm, 'Ed25519');
    assert.equal(a.proof.signature_b64u, b.proof.signature_b64u);
    const res = verifyGateAllowance(a, {
        trusted_keys: { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u } },
        now: NOW, expected_allowance_id: 'allowance:x:01', expected_tenant_id: 'tenant:x', expected_subject_id: 'agent:x',
        expected_audience: 'gate:x', expected_connector_id: 'stripe', expected_authorizer_id: ISSUER,
    });
    assert.equal(res.accepted, true, res.reason ?? '');
});
// --- anti-stripping -----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const a = mutable(await buildV2());
    a.proof.signatures = a.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_signature_invalid');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses', async () => {
    const a = mutable(await buildV2());
    a.proof.signatures = a.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
test('SET NARROWING: narrow required_algorithms + drop PQ leg fails structurally AND cryptographically', async () => {
    const a = mutable(await buildV2());
    a.proof.required_algorithms = ['Ed25519'];
    const survivingEd = a.proof.signatures.find((s) => s.alg === 'Ed25519');
    a.proof.signatures = [survivingEd];
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
    const { proof: _p, ...body } = a;
    const narrowedBytes = Buffer.from(canonicalize({ profile: RISK_HYBRID_PROFILE, required_algorithms: ['Ed25519'], version: GATE_ALLOWANCE_V2_VERSION, body }), 'utf8');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(survivingEd.sig, 'base64url')), false);
});
test('SET WIDENING refuses', async () => {
    const a = mutable(await buildV2());
    a.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
test('DUPLICATE ALGORITHM refuses', async () => {
    const a = mutable(await buildV2());
    const edLeg = a.proof.signatures.find((s) => s.alg === 'Ed25519');
    a.proof.signatures = [edLeg, edLeg];
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE refuses', async () => {
    const ed448 = generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyGateAllowanceV2(await buildV2(), opts({
        trusted_keys: { [KEY_ID]: { issuer_id: ISSUER, public_key: ed448Pub, pq_public_key: pqPubB64u } },
    }));
    assert.equal(res.accepted, false);
});
test('ALGORITHM RELABELLING refuses', async () => {
    const a = mutable(await buildV2());
    a.proof.signatures = a.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
test('SWAPPED LEGS refuse', async () => {
    const a = mutable(await buildV2());
    const pqLeg = a.proof.signatures.find((s) => s.alg === 'ML-DSA-65');
    a.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
// --- pinning ------------------------------------------------------------------
test('PQ KEY SUBSTITUTION refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyGateAllowanceV2(await buildV2(), opts({
        trusted_keys: { [KEY_ID]: { issuer_id: ISSUER, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.equal(res.accepted, false);
});
test('unpinned issuer is untrusted', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts({ trusted_keys: {} }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_issuer_untrusted');
});
// --- binding + domain refusals ------------------------------------------------
test('TAMPERED AFTER SIGNING breaks the binding', async () => {
    const a = mutable(await buildV2());
    a.tenant_id = 'tenant:evil';
    const res = await verifyGateAllowanceV2(a, opts());
    assert.equal(res.accepted, false);
});
test('tenant mismatch refuses on context', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts({ expected_tenant_id: 'tenant:other' }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'tenant_mismatch');
});
test('expired allowance refuses', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts({ now: Date.parse('2026-08-01T00:00:00.000Z') }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_expired');
});
test('not-yet-valid allowance refuses', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts({ now: Date.parse('2026-07-30T17:59:30.000Z') }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_not_yet_valid');
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyGateAllowanceV2(await buildV2(), opts({ options: { mldsaBackendLoader: async () => null } }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'allowance_signature_invalid');
});
// --- fail-closed on junk ------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyGateAllowanceV2(junk, opts());
        assert.equal(res.accepted, false);
    }
});
