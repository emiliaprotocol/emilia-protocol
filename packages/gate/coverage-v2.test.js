// SPDX-License-Identifier: Apache-2.0
// Generated from coverage-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-GATE-ENFORCEMENT-PROBE-v2 hybrid verifier test. Copies the hostile
// matrix of the reference migration (packages/verify/revocation-v2.test.ts):
// leg stripping both directions, set narrowing, duplicate algorithm, an
// Ed448 SPKI masquerading as the Ed25519 half, algorithm relabelling, PQ-key
// substitution, wrong-length signatures, plus the old-verifier-refuses-new
// capture and a valid hybrid roundtrip.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ENFORCEMENT_PROBE_VERSION, ENFORCEMENT_PROBE_V2_VERSION, ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS, signEnforcementProbe, verifyEnforcementProbe, signEnforcementProbeV2, verifyEnforcementProbeV2, verifyEnforcementProbeAny, probeV2Bytes, } from './coverage.js';
import { canonicalize } from './execution-binding.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const ACTION = `sha256:${'11'.repeat(32)}`;
const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const TESTED_AT = '2026-07-16T19:59:30.000Z';
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const PROBE_ID = 'probe:independent-1';
const KEY_ID = 'key:probe-hybrid-1';
const PINS_V2 = [{ probe_id: PROBE_ID, key_id: KEY_ID, public_key: edPubB64u, pq_public_key: pqPubB64u, surface_ids: ['surface:curtailment-west'] }];
function probeInput(overrides = {}) {
    return {
        probe_id: PROBE_ID,
        key_id: KEY_ID,
        surface_id: 'surface:curtailment-west',
        gate_id: 'gate:grid-west',
        environment_id: 'env:prod-west',
        action_family: 'grid.curtailment',
        action_digest: ACTION,
        tested_at: TESTED_AT,
        nonce: 'probe-blocked-without-receipt-1',
        result: 'blocked_without_receipt',
        response_status: 428,
        ...overrides,
    };
}
async function buildV2(overrides = {}) {
    return signEnforcementProbeV2(probeInput(overrides), [
        { alg: 'Ed25519', private_key: ed.privateKey, key_id: KEY_ID },
        { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: KEY_ID },
    ]);
}
function verifyOpts(overrides = {}) {
    return { pinnedProbes: PINS_V2, now: NOW, maxAgeSec: 300, maxFutureSkewSec: 30, ...overrides };
}
// --- honesty gate --------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ------------------------------------------------------------
test('a real hybrid probe statement verifies under both pinned keys (valid roundtrip)', async () => {
    const stmt = await buildV2();
    assert.equal(stmt['@version'], ENFORCEMENT_PROBE_V2_VERSION);
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, true, res.reason);
});
test('the committed bytes carry the required algorithm set and the v2 marker', async () => {
    const stmt = await buildV2();
    const { proof: _proof, ...body } = stmt;
    const bytes = probeV2Bytes(body).toString('utf8');
    assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
});
// --- old-verifier-refuses-new -----------------------------------------------
test('the v1 (classical) verifier refuses a v2 hybrid probe cleanly on the version marker', async () => {
    const stmt = await buildV2();
    const res = verifyEnforcementProbe(stmt, verifyOpts());
    assert.equal(res.accepted, false);
});
test('the v2 verifier refuses a v1 (classical) probe on the version marker', () => {
    const classical = signEnforcementProbe(probeInput(), ed.privateKey);
    assert.equal(classical['@version'], ENFORCEMENT_PROBE_VERSION);
    return verifyEnforcementProbeV2(classical, verifyOpts()).then((res) => {
        assert.equal(res.accepted, false);
    });
});
test('verifyEnforcementProbeAny routes each version to its own verifier', async () => {
    assert.equal((await verifyEnforcementProbeAny(await buildV2(), verifyOpts())).accepted, true);
    const classical = signEnforcementProbe(probeInput(), ed.privateKey);
    assert.equal((await verifyEnforcementProbeAny(classical, verifyOpts({
        pinnedProbes: [{ probe_id: PROBE_ID, key_id: classical.probe.key_id, public_key: edPubB64u, surface_ids: ['surface:curtailment-west'] }],
    }))).accepted, true);
});
// --- anti-stripping ----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses structurally', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_signature_leg_stripped');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
});
test('SET NARROWING: narrowing required_algorithms to Ed25519-only refuses structurally', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.required_algorithms = ['Ed25519'];
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_algorithm_set_invalid');
    // Independent cryptographic half: the surviving Ed25519 signature was
    // made over bytes committing to the FULL set. probeV2Bytes() itself
    // refuses a non-registered set (by design -- it only ever rebuilds from
    // the REGISTERED set), so the narrowed bytes are recomputed by hand here,
    // mirroring what a stripping attacker would have to forge.
    const { proof, ...body } = structuredClone(await buildV2());
    const narrowedBytes = Buffer.from(`${ENFORCEMENT_PROBE_V2_VERSION}\0${canonicalize({ ...body, required_algorithms: ['Ed25519'] })}`, 'utf8');
    const survivingSig = Buffer.from(proof.signatures.find((s) => s.alg === 'Ed25519').sig, 'base64url');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false);
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = [stmt.proof.signatures[0], stmt.proof.signatures[0]];
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_signature_leg_duplicate');
});
// --- wrong-length signature ---------------------------------------------------
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
    const stmt = structuredClone(await buildV2());
    const leg = stmt.proof.signatures.find((s) => s.alg === 'Ed25519');
    leg.sig = Buffer.from(leg.sig, 'base64url').subarray(0, 10).toString('base64url');
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyEnforcementProbeV2(await buildV2(), verifyOpts({
        pinnedProbes: [{ probe_id: PROBE_ID, key_id: KEY_ID, public_key: ed448Pub, pq_public_key: pqPubB64u, surface_ids: ['surface:curtailment-west'] }],
    }));
    assert.equal(res.accepted, false);
});
test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_signature_leg_unexpected');
});
// --- pinning -------------------------------------------------------------------
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyEnforcementProbeV2(await buildV2(), verifyOpts({
        pinnedProbes: [{ probe_id: PROBE_ID, key_id: KEY_ID, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url'), surface_ids: ['surface:curtailment-west'] }],
    }));
    assert.equal(res.accepted, false);
});
test('an unpinned probe key confers nothing', async () => {
    const res = await verifyEnforcementProbeV2(await buildV2(), verifyOpts({ pinnedProbes: [] }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_key_unpinned');
});
test('pinning the Ed25519 half but not the ML-DSA half refuses', async () => {
    const res = await verifyEnforcementProbeV2(await buildV2(), verifyOpts({
        pinnedProbes: [{ probe_id: PROBE_ID, key_id: KEY_ID, public_key: edPubB64u, surface_ids: ['surface:curtailment-west'] }],
    }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'probe_key_unpinned');
});
// --- fail-closed backend --------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyEnforcementProbeV2(await buildV2(), verifyOpts({ mldsaBackendLoader: async () => null }));
    assert.equal(res.accepted, false);
});
// --- fail-closed on junk ---------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyEnforcementProbeV2(junk, verifyOpts());
        assert.equal(res.accepted, false);
    }
});
test('TAMPERED AFTER SIGNING: editing the test result after signing breaks the signature', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.test.result = 'executed_without_receipt';
    const res = await verifyEnforcementProbeV2(stmt, verifyOpts());
    assert.equal(res.accepted, false);
});
