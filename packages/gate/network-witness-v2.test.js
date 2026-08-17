// SPDX-License-Identifier: Apache-2.0
// Generated from network-witness-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-GATE-NETWORK-WITNESS-v2 hybrid profile test. Builds a REAL Ed25519 +
// ML-DSA-65 signed witness statement and runs the hostile matrix (leg stripping
// both ways, set narrowing structural + independent crypto.verify, widening,
// duplicate alg, Ed448 masquerade, relabelling, swapped legs, PQ key
// substitution, tamper after signing), plus domain refusals (pin/config/action/
// freshness), the v1-refuses-v2 capture, a v1 byte-identity regression, and the
// online acceptance path.
//
// The PQ leg runs for real; this suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync } from 'node:crypto';
import { NETWORK_WITNESS_V2_VERSION, NETWORK_WITNESS_V2_DOMAIN, NETWORK_WITNESS_V2_REQUIRED_ALGORITHMS, NETWORK_WITNESS_ACCEPTANCE_V2_VERSION, signNetworkWitnessStatement, verifyNetworkWitnessStatement, signNetworkWitnessStatementV2, verifyNetworkWitnessStatementV2, acceptNetworkWitnessStatementV2, createMemoryWitnessSequenceStore, } from './src/network-witness.js';
import { canonicalize } from './src/execution-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const ACTION = `sha256:${'ab'.repeat(32)}`;
const CONFIG = `sha256:${'cd'.repeat(32)}`;
const FLOW = `sha256:${'ef'.repeat(32)}`;
const ed = generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const KEYS = { edPrivateKey: ed.privateKey, pqPrivateKey: pqSecretB64u };
const mutable = (x) => JSON.parse(JSON.stringify(x));
const INPUT = {
    witness_id: 'witness:edge-1',
    capture_point_id: 'capture:grid-ingress-a',
    sequence: 5,
    observed_at: '2026-07-16T19:59:30.000Z',
    event: 'request_observed',
    direction: 'ingress',
    action_digest: ACTION,
    flow_digest: FLOW,
    config_digest: CONFIG,
};
function pin() {
    return {
        witness_id: 'witness:edge-1',
        key_id: undefined,
        public_key: edPubB64u,
        pq_public_key: pqPubB64u,
        capture_point_ids: ['capture:grid-ingress-a'],
        config_digests: [CONFIG],
    };
}
async function buildV2() {
    const stmt = await signNetworkWitnessStatementV2(INPUT, KEYS);
    const p = pin();
    p.key_id = stmt.proof.key_id;
    return { stmt, p };
}
function vopts(p, extra = {}) {
    return { pinnedWitnesses: [p], now: NOW, ...extra };
}
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
// --- happy path ---------------------------------------------------------------
test('a real hybrid witness statement verifies under both pinned keys', async () => {
    const { stmt, p } = await buildV2();
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p, { expectedActionDigest: ACTION, expectedEvent: 'request_observed' }));
    assert.equal(res.verified, true, res.reason ?? '');
    assert.equal(res.action_digest, ACTION);
    assert.equal(res.checks.legs, true);
});
test('the proof carries the set shape and committed set', async () => {
    const { stmt } = await buildV2();
    assert.equal(stmt['@version'], NETWORK_WITNESS_V2_VERSION);
    assert.equal(stmt.proof.profile, NETWORK_WITNESS_V2_VERSION);
    assert.deepEqual(stmt.proof.required_algorithms, [...NETWORK_WITNESS_V2_REQUIRED_ALGORITHMS]);
    assert.deepEqual(stmt.proof.signatures.map((s) => s.alg), ['Ed25519', 'ML-DSA-65']);
});
// --- v1 / v2 compatibility ----------------------------------------------------
test('the v1 verifier refuses a v2 statement (shape/version marker)', async () => {
    const { stmt } = await buildV2();
    const res = verifyNetworkWitnessStatement(stmt, { pinnedWitnesses: [], now: NOW });
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'statement_shape_invalid');
});
test('v1 signing is byte-identical and still verifies (regression)', () => {
    const a = signNetworkWitnessStatement(INPUT, ed.privateKey);
    const b = signNetworkWitnessStatement(INPUT, ed.privateKey);
    assert.equal(a.signature.algorithm, 'Ed25519');
    assert.equal(a.signature.signature_b64u, b.signature.signature_b64u);
    const p = pin();
    p.key_id = a.signature.key_id;
    const res = verifyNetworkWitnessStatement(a, { pinnedWitnesses: [p], now: NOW });
    assert.equal(res.verified, true, res.reason ?? '');
});
// --- anti-stripping -----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.proof.signatures = a.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_set_incomplete');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.proof.signatures = a.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_set_incomplete');
});
test('SET NARROWING fails structurally AND cryptographically', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.proof.required_algorithms = ['Ed25519'];
    const survivingEd = a.proof.signatures.find((s) => s.alg === 'Ed25519');
    a.proof.signatures = [survivingEd];
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'algorithm_set_invalid');
    const { proof: _p, ...body } = a;
    const narrowedBytes = Buffer.from(NETWORK_WITNESS_V2_DOMAIN + canonicalize({ required_algorithms: ['Ed25519'], body }), 'utf8');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, Buffer.from(survivingEd.sig, 'base64url')), false);
});
test('SET WIDENING refuses', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'algorithm_set_invalid');
});
test('DUPLICATE ALGORITHM refuses', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    const edLeg = a.proof.signatures.find((s) => s.alg === 'Ed25519');
    a.proof.signatures = [edLeg, edLeg];
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_set_invalid');
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE (pinned Ed448 as the Ed25519 half) refuses', async () => {
    const { stmt, p } = await buildV2();
    const ed448 = generateKeyPairSync('ed448');
    p.public_key = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'pinned_key_invalid');
});
test('ALGORITHM RELABELLING refuses (closed registry)', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.proof.signatures = a.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_set_invalid');
});
test('SWAPPED LEGS refuse', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    const pqLeg = a.proof.signatures.find((s) => s.alg === 'ML-DSA-65');
    a.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_invalid');
});
// --- pinning ------------------------------------------------------------------
test('PQ KEY SUBSTITUTION refuses', async () => {
    const { stmt, p } = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    p.pq_public_key = Buffer.from(other.publicKey).toString('base64url');
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'signature_invalid');
});
test('unpinned witness confers nothing', async () => {
    const { stmt } = await buildV2();
    const res = await verifyNetworkWitnessStatementV2(stmt, { pinnedWitnesses: [], now: NOW });
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'witness_key_unpinned');
});
test('pinning the Ed25519 half but not the ML-DSA half refuses', async () => {
    const { stmt, p } = await buildV2();
    delete p.pq_public_key;
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'witness_key_unpinned');
});
// --- binding + domain refusals ------------------------------------------------
test('TAMPERED AFTER SIGNING breaks the digest binding', async () => {
    const { stmt, p } = await buildV2();
    const a = mutable(stmt);
    a.observation.action_digest = `sha256:${'99'.repeat(32)}`;
    const res = await verifyNetworkWitnessStatementV2(a, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'statement_digest_mismatch');
});
test('config mismatch refuses', async () => {
    const { stmt, p } = await buildV2();
    p.config_digests = [`sha256:${'11'.repeat(32)}`];
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'witness_config_unpinned');
});
test('expected action-digest mismatch refuses', async () => {
    const { stmt, p } = await buildV2();
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p, { expectedActionDigest: `sha256:${'22'.repeat(32)}` }));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'action_digest_mismatch');
});
test('stale observation refuses', async () => {
    const { stmt, p } = await buildV2();
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p, { maxAgeSec: 10 }));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'observation_stale');
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const { stmt, p } = await buildV2();
    const res = await verifyNetworkWitnessStatementV2(stmt, vopts(p, { mldsaBackendLoader: async () => null }));
    assert.equal(res.verified, false);
    assert.equal(res.reason, 'pq_backend_unavailable');
});
// --- online acceptance --------------------------------------------------------
test('acceptNetworkWitnessStatementV2 consumes the sequence exactly once', async () => {
    const { stmt, p } = await buildV2();
    const store = createMemoryWitnessSequenceStore();
    const options = { pinnedWitnesses: [p], now: NOW, sequenceStore: store, allowEphemeralStore: true };
    const first = await acceptNetworkWitnessStatementV2(stmt, options);
    assert.equal(first.accepted, true, first.reason ?? '');
    assert.equal(first.acceptance_version, NETWORK_WITNESS_ACCEPTANCE_V2_VERSION);
    const replay = await acceptNetworkWitnessStatementV2(stmt, options);
    assert.equal(replay.accepted, false);
    assert.equal(replay.reason, 'statement_replay');
});
// --- fail-closed on junk ------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyNetworkWitnessStatementV2(junk, { pinnedWitnesses: [pin()], now: NOW });
        assert.equal(res.verified, false);
    }
});
