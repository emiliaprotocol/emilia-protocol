// SPDX-License-Identifier: Apache-2.0
// Generated from field-origin-evidence-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-FIELD-ORIGIN-v0.2 hybrid verifier test. Copies the hostile matrix of the
// reference migration (packages/verify/revocation-v2.test.ts): leg stripping both
// directions, set narrowing (structural + independent crypto.verify over the
// narrowed bytes), set widening, duplicate algorithm, an Ed448 SPKI masquerading
// as the Ed25519 half, algorithm relabelling, swapped legs, PQ-key substitution,
// tamper-after-signing, plus the field-origin domain refusals, the v1-refuses-v2
// capture, and a v1 byte-identity regression.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import crypto from 'node:crypto';
import test from 'node:test';
import { canonicalize } from './execution-binding.js';
import { FIELD_ORIGIN_CLAIM_BOUNDARY, FIELD_ORIGIN_EVIDENCE_VERSION, FIELD_ORIGIN_EVIDENCE_V2_VERSION, FIELD_ORIGIN_EVIDENCE_V2_DOMAIN, FIELD_ORIGIN_V2_REQUIRED_ALGORITHMS, fieldOriginV2SignedPayload, signFieldOriginEvidence, signFieldOriginEvidenceV2, verifyFieldOriginEvidence, verifyFieldOriginEvidenceV2, verifyFieldOriginEvidenceAny, } from './field-origin-evidence.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = '2026-08-17T22:30:00.000Z';
const RP = 'rp:gap6-finops';
const KEY_ID = 'key:field-origin-issuer';
const ACTION = Object.freeze({
    action_type: 'finops.vendor.bank_detail_change',
    vendor_id: 'V-88012',
    amount: '4200.00',
});
function rule(path, allowedOrigins) {
    return {
        path, role: 'control', required: true,
        allowed_origins: allowedOrigins, snapshot_policy: 'immutable',
        max_snapshot_age_sec: null, allowed_transform_ids: [],
    };
}
const PROFILE = Object.freeze({
    profile_id: 'profile:finops-field-origin:01',
    relying_party_id: RP,
    action_type: ACTION.action_type,
    fields: [
        rule('/action_type', ['operator_pinned']),
        rule('/vendor_id', ['operator_pinned', 'approver_supplied']),
        rule('/amount', ['approver_supplied']),
    ],
    transforms: [],
});
function annotations() {
    return [
        { path: '/action_type', origin_class: 'operator_pinned', snapshot: { kind: 'immutable', observed_at: null, source_version: null }, transform: null },
        { path: '/vendor_id', origin_class: 'operator_pinned', snapshot: { kind: 'immutable', observed_at: null, source_version: null }, transform: null },
        { path: '/amount', origin_class: 'approver_supplied', snapshot: { kind: 'immutable', observed_at: null, source_version: null }, transform: null },
    ];
}
const ed = generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
function signer() {
    return { issuer_id: RP, key_id: KEY_ID, private_key: ed.privateKey, pq_public_key: pqPubB64u, pq_private_key: pqSecretB64u };
}
function input() {
    return { evidence_id: 'evidence:field-origin:v2-001', profile: PROFILE, observed_action: ACTION, observed_at: NOW, annotations: annotations() };
}
function buildV2() { return signFieldOriginEvidenceV2(input(), signer()); }
function ctx(overrides = {}) {
    return {
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: edPubB64u, pq_public_key: pqPubB64u } },
        pinned_profile: PROFILE,
        expected_relying_party_id: RP,
        observed_action: ACTION,
        now: NOW,
        ...overrides,
    };
}
// --- honesty gate -------------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ---------------------------------------------------------------
test('a real hybrid field-origin artifact verifies under both pinned keys', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx());
    assert.equal(res.accepted, true, res.reason);
    assert.equal(res.verified, true);
    assert.equal(res.field_count, 3);
});
test('the committed bytes carry the required algorithm set and the v0.2 marker', async () => {
    const stmt = await buildV2();
    const { proof, ...bodyNoProof } = stmt;
    const bytes = fieldOriginV2SignedPayload(bodyNoProof).toString('utf8');
    assert.ok(bytes.startsWith(FIELD_ORIGIN_EVIDENCE_V2_DOMAIN), bytes.slice(0, 64));
    assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
});
// --- v1 / v2 compatibility ----------------------------------------------------
test('the v1 verifier refuses a v0.2 artifact CLEANLY (no throw, named reason)', async () => {
    const res = verifyFieldOriginEvidence(await buildV2(), {
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: edPubB64u } },
        pinned_profile: PROFILE, expected_relying_party_id: RP, observed_action: ACTION, now: NOW,
    });
    assert.equal(res.accepted, false);
    assert.equal(typeof res.reason, 'string');
});
test('v1 byte-identity regression: a v1 artifact verifies and re-signs identically', () => {
    const a = signFieldOriginEvidence(input(), { issuer_id: RP, key_id: KEY_ID, private_key: ed.privateKey });
    const b = signFieldOriginEvidence(input(), { issuer_id: RP, key_id: KEY_ID, private_key: ed.privateKey });
    assert.equal(a['@version'], FIELD_ORIGIN_EVIDENCE_VERSION);
    assert.equal(a.proof.signature_b64u, b.proof.signature_b64u, 'v1 Ed25519 signing must stay byte-identical');
    const res = verifyFieldOriginEvidence(a, {
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: edPubB64u } },
        pinned_profile: PROFILE, expected_relying_party_id: RP, observed_action: ACTION, now: NOW,
    });
    assert.equal(res.accepted, true, res.reason);
});
test('the v2 verifier refuses a v1 artifact on the version marker', async () => {
    const v1 = signFieldOriginEvidence(input(), { issuer_id: RP, key_id: KEY_ID, private_key: ed.privateKey });
    const res = await verifyFieldOriginEvidenceV2(v1, ctx());
    assert.equal(res.accepted, false);
    assert.ok(/unsupported_version/.test(res.reason), res.reason);
});
test('verifyFieldOriginEvidenceAny routes each version to its own verifier', async () => {
    assert.equal((await verifyFieldOriginEvidenceAny(await buildV2(), ctx())).accepted, true);
    const v1 = signFieldOriginEvidence(input(), { issuer_id: RP, key_id: KEY_ID, private_key: ed.privateKey });
    assert.equal((await verifyFieldOriginEvidenceAny(v1, {
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: edPubB64u } },
        pinned_profile: PROFILE, expected_relying_party_id: RP, observed_action: ACTION, now: NOW,
    })).accepted, true);
});
// --- anti-stripping -----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_signature_leg_stripped');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_signature_leg_stripped');
});
test('SET NARROWING: narrowing required_algorithms fails BOTH structurally and cryptographically', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.required_algorithms = ['Ed25519'];
    stmt.proof.signatures = stmt.proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_algorithm_set_invalid');
    const { proof, ...bodyNoProof } = stmt;
    const narrowedBytes = Buffer.from(FIELD_ORIGIN_EVIDENCE_V2_DOMAIN + canonicalize({ ...bodyNoProof, required_algorithms: ['Ed25519'] }), 'utf8');
    const survivingSig = Buffer.from(proof.signatures[0].sig, 'base64url');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false, 'narrowing the committed set must break the surviving signature');
});
test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_algorithm_set_invalid');
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = [{ ...stmt.proof.signatures[0] }, { ...stmt.proof.signatures[0] }];
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_signature_leg_duplicate');
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const stmt = structuredClone(await buildV2());
    stmt.proof.public_key = ed448Pub;
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx({
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: ed448Pub, pq_public_key: pqPubB64u } },
    }));
    assert.equal(res.accepted, false);
    // A non-Ed25519 pin is rejected while normalizing the v2 context.
    assert.equal(res.reason, 'field_origin_verification_context_required');
});
test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.proof.signatures = stmt.proof.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_signature_leg_unexpected');
});
test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const stmt = structuredClone(await buildV2());
    const pqLeg = stmt.proof.signatures.find((s) => s.alg === 'ML-DSA-65');
    stmt.proof.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.ok(/field_origin_signature_invalid/.test(res.reason), res.reason);
});
// --- pinning ------------------------------------------------------------------
test('an unpinned issuer confers nothing', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx({ trusted_keys: { 'key:other': { issuer_id: RP, public_key: edPubB64u, pq_public_key: pqPubB64u } } }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_issuer_untrusted');
});
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx({
        trusted_keys: { [KEY_ID]: { issuer_id: RP, public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_issuer_untrusted');
});
// --- field-origin domain refusals ---------------------------------------------
test('TAMPERED AFTER SIGNING: editing a signed body field breaks the signature', async () => {
    const stmt = structuredClone(await buildV2());
    stmt.evidence_id = 'evidence:field-origin:tampered';
    const res = await verifyFieldOriginEvidenceV2(stmt, ctx());
    assert.equal(res.accepted, false);
    assert.ok(/field_origin_signature_invalid/.test(res.reason), res.reason);
});
test('action-digest mismatch refuses on the shared v1 policy', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx({ observed_action: { ...ACTION, amount: '9999.99' } }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_action_mismatch');
});
test('relying-party mismatch refuses on the shared v1 policy', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx({ expected_relying_party_id: 'rp:someone-else' }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_relying_party_mismatch');
});
test('evidence dated after the decision time refuses on the shared v1 policy', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx({ now: '2026-08-17T22:29:00.000Z' }));
    assert.equal(res.accepted, false);
    assert.equal(res.reason, 'field_origin_evidence_from_future');
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const res = await verifyFieldOriginEvidenceV2(await buildV2(), ctx(), { mldsaBackendLoader: async () => null });
    assert.equal(res.accepted, false);
    assert.ok(/pq_backend_unavailable/.test(res.reason), res.reason);
});
// --- fail-closed on junk ------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyFieldOriginEvidenceV2(junk, ctx());
        assert.equal(res.accepted, false);
    }
    const stmt = structuredClone(await buildV2());
    delete stmt.proof.pq_public_key;
    assert.equal((await verifyFieldOriginEvidenceV2(stmt, ctx())).accepted, false);
});
