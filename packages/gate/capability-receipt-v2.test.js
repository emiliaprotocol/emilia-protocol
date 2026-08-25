// SPDX-License-Identifier: Apache-2.0
// Generated from capability-receipt-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-CAPABILITY-RECEIPT-v2 hybrid verifier test. Copies the hostile matrix of the
// reference migration (packages/verify/revocation-v2.test.ts): leg stripping both
// directions, set narrowing (structural + independent crypto.verify over the
// narrowed bytes), set widening, duplicate algorithm, an Ed448 SPKI masquerading
// as the Ed25519 half, algorithm relabelling, swapped legs, PQ-key substitution,
// tamper-after-signing, plus the capability domain refusals, the v1-refuses-v2
// capture, and a v1 byte-identity regression.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import { CAPABILITY_RECEIPT_VERSION, CAPABILITY_RECEIPT_V2_VERSION, CAPABILITY_V2_REQUIRED_ALGORITHMS, CAPABILITY_SCOPE_PROFILE, capabilityActionDigest, capabilityBaseReceiptDigest, capabilityV2SignedPayload, mintCapabilityReceipt, mintCapabilityReceiptV2, verifyCapabilityReceipt, verifyCapabilityReceiptV2, verifyCapabilityReceiptAny, } from './capability-receipt.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-08-17T22:00:00.000Z');
const ed = generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const pqSecretB64u = Buffer.from(pq.secretKey).toString('base64url');
const SCOPED_ACTION = { amount: 1, currency: 'USD', operation_id: 'op_1' };
function baseReceipt(receiptId = 'base_1') {
    const payload = {
        receipt_id: receiptId,
        created_at: new Date(NOW - 1000).toISOString(),
        subject: 'operator@example.test',
        claim: { action_type: 'payment.release', outcome: 'allow', capability_only: true },
    };
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(payload)), ed.privateKey).toString('base64url') },
        public_key: edPubB64u,
    };
}
function mintOptions(overrides = {}) {
    return {
        issuerPrivateKey: ed.privateKey,
        pqPublicKey: pqPubB64u,
        pqPrivateKey: pqSecretB64u,
        budget: { amount: 100, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        capabilityId: 'cap-fixed-v2',
        secret: Buffer.alloc(32, 7),
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(SCOPED_ACTION)],
        },
        ...overrides,
    };
}
function buildV2() { return mintCapabilityReceiptV2(baseReceipt(), mintOptions()); }
const PINS = [{ public_key: edPubB64u, pq_public_key: pqPubB64u }];
// --- honesty gate -------------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ---------------------------------------------------------------
test('a real hybrid capability envelope verifies under both pinned keys', async () => {
    const { capabilityReceipt } = await buildV2();
    const res = await verifyCapabilityReceiptV2(capabilityReceipt, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, true, res.reason);
    assert.equal(res.issuer_public_key, edPubB64u);
    assert.equal(res.issuer_pq_public_key, pqPubB64u);
});
test('the committed bytes carry the required algorithm set and the v2 marker', async () => {
    const { capabilityReceipt } = await buildV2();
    const bytes = capabilityV2SignedPayload(capabilityReceipt.receipt, capabilityReceipt.capability).toString('utf8');
    assert.ok(bytes.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'), bytes);
    assert.ok(bytes.includes(`"@version":"${CAPABILITY_RECEIPT_V2_VERSION}"`), bytes);
});
// --- v1 / v2 compatibility ----------------------------------------------------
test('the v1 verifier refuses a v2 envelope CLEANLY on the version marker', async () => {
    const { capabilityReceipt } = await buildV2();
    const res = verifyCapabilityReceipt(capabilityReceipt, { trustedIssuerKeys: [edPubB64u] });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'malformed_capability_receipt');
});
test('v1 byte-identity regression: a v1 envelope verifies and re-mints identically', () => {
    const v1Opts = {
        issuerPrivateKey: ed.privateKey,
        budget: { amount: 100, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        capabilityId: 'cap-fixed-v1',
        secret: Buffer.alloc(32, 7),
        scope: { profile: CAPABILITY_SCOPE_PROFILE, operation_id_field: 'operation_id', action_digests: [capabilityActionDigest(SCOPED_ACTION)] },
    };
    const a = mintCapabilityReceipt(baseReceipt(), v1Opts);
    const b = mintCapabilityReceipt(baseReceipt(), v1Opts);
    assert.equal(a.capabilityReceipt['@version'], CAPABILITY_RECEIPT_VERSION);
    assert.equal(a.capabilityReceipt.capability_signature.value, b.capabilityReceipt.capability_signature.value, 'v1 Ed25519 signing must stay byte-identical');
    const res = verifyCapabilityReceipt(a.capabilityReceipt, { trustedIssuerKeys: [edPubB64u] });
    assert.equal(res.ok, true, res.reason);
});
test('the v2 verifier refuses a v1 envelope on the version marker', async () => {
    const v1 = mintCapabilityReceipt(baseReceipt(), {
        issuerPrivateKey: ed.privateKey, budget: { amount: 100, currency: 'USD' }, expiry: NOW + 60_000,
        revocationMode: 'direct', capabilityId: 'cap-v1', secret: Buffer.alloc(32, 7),
        scope: { profile: CAPABILITY_SCOPE_PROFILE, operation_id_field: 'operation_id', action_digests: [capabilityActionDigest(SCOPED_ACTION)] },
    });
    const res = await verifyCapabilityReceiptV2(v1.capabilityReceipt, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'malformed_capability_receipt');
});
test('verifyCapabilityReceiptAny routes each version to its own verifier', async () => {
    const { capabilityReceipt } = await buildV2();
    assert.equal((await verifyCapabilityReceiptAny(capabilityReceipt, { trustedIssuerKeys: PINS })).ok, true);
    const v1 = mintCapabilityReceipt(baseReceipt(), {
        issuerPrivateKey: ed.privateKey, budget: { amount: 100, currency: 'USD' }, expiry: NOW + 60_000,
        revocationMode: 'direct', capabilityId: 'cap-v1b', secret: Buffer.alloc(32, 7),
        scope: { profile: CAPABILITY_SCOPE_PROFILE, operation_id_field: 'operation_id', action_digests: [capabilityActionDigest(SCOPED_ACTION)] },
    });
    assert.equal((await verifyCapabilityReceiptAny(v1.capabilityReceipt, { trustedIssuerKeys: [edPubB64u] })).ok, true);
});
// --- anti-stripping -----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg (set intact) refuses structurally', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.signatures = cr.capability_signature.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_signature_leg_stripped');
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.signatures = cr.capability_signature.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_signature_leg_stripped');
});
test('SET NARROWING: narrowing required_algorithms fails BOTH structurally and cryptographically', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.required_algorithms = ['Ed25519'];
    cr.capability_signature.signatures = cr.capability_signature.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_algorithm_set_invalid');
    const narrowedBytes = Buffer.from(canonicalize({
        '@version': CAPABILITY_RECEIPT_V2_VERSION,
        base_receipt_id: cr.receipt.payload.receipt_id,
        base_receipt_digest: capabilityBaseReceiptDigest(cr.receipt),
        capability: cr.capability,
        required_algorithms: ['Ed25519'],
    }), 'utf8');
    const survivingSig = Buffer.from(cr.capability_signature.signatures[0].sig, 'base64url');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false, 'narrowing the committed set must break the surviving signature');
});
test('SET WIDENING: an extra algorithm in required_algorithms refuses', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_algorithm_set_invalid');
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.signatures = [{ ...cr.capability_signature.signatures[0] }, { ...cr.capability_signature.signatures[0] }];
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_signature_leg_duplicate');
});
// --- masquerade ---------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI presented and pinned as the Ed25519 half refuses', async () => {
    const ed448 = generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.public_key = ed448Pub;
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: [{ public_key: ed448Pub, pq_public_key: pqPubB64u }] });
    assert.equal(res.ok, false);
    // Curve pin: the ed key id cannot be derived from a non-Ed25519 SPKI.
    assert.equal(res.reason, 'capability_issuer_key_unbound');
});
test('ALGORITHM RELABELLING: calling the Ed25519 leg "Ed448" refuses (closed registry)', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.signatures = cr.capability_signature.signatures.map((s) => (s.alg === 'Ed25519' ? { ...s, alg: 'Ed448' } : s));
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_signature_leg_unexpected');
});
test('SWAPPED LEGS: the ML-DSA signature relabelled as Ed25519 refuses', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    const pqLeg = cr.capability_signature.signatures.find((s) => s.alg === 'ML-DSA-65');
    cr.capability_signature.signatures = [{ ...pqLeg, alg: 'Ed25519' }, pqLeg];
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.ok(/capability_signature_invalid/.test(res.reason), res.reason);
});
// --- pinning ------------------------------------------------------------------
test('an unpinned issuer confers nothing (no allowUntrustedIssuer)', async () => {
    const { capabilityReceipt } = await buildV2();
    const res = await verifyCapabilityReceiptV2(capabilityReceipt, { trustedIssuerKeys: [] });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_issuer_not_trusted');
});
test('allowUntrustedIssuer cannot turn a self-signed v2 envelope into authority', async () => {
    const { capabilityReceipt } = await buildV2();
    const res = await verifyCapabilityReceiptV2(capabilityReceipt, {
        trustedIssuerKeys: [],
        allowUntrustedIssuer: true,
    });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_issuer_not_trusted');
});
test('allowUntrustedIssuer cannot turn a self-signed v1 envelope into authority', () => {
    const { capabilityReceipt } = mintCapabilityReceipt(baseReceipt(), {
        issuerPrivateKey: ed.privateKey,
        budget: { amount: 100, currency: 'USD' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        capabilityId: 'cap-self-asserted-v1',
        secret: Buffer.alloc(32, 7),
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(SCOPED_ACTION)],
        },
    });
    const res = verifyCapabilityReceipt(capabilityReceipt, {
        trustedIssuerKeys: [],
        allowUntrustedIssuer: true,
    });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_issuer_not_trusted');
});
test('pinning the Ed25519 half but a wrong ML-DSA half refuses (both halves must match)', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const { capabilityReceipt } = await buildV2();
    const res = await verifyCapabilityReceiptV2(capabilityReceipt, {
        trustedIssuerKeys: [{ public_key: edPubB64u, pq_public_key: Buffer.from(other.publicKey).toString('base64url') }],
    });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_issuer_not_trusted');
});
test('PQ KEY SUBSTITUTION: presenting a different ML-DSA key than pinned refuses', async () => {
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability_signature.pq_public_key = Buffer.from(other.publicKey).toString('base64url');
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_issuer_not_trusted');
});
// --- capability domain refusals -----------------------------------------------
test('TAMPERED AFTER SIGNING: editing the signed capability breaks the signature', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.capability.budget.amount = 999999;
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS, allowUntrustedIssuer: true });
    assert.equal(res.ok, false);
    // assertCapabilityShape passes (999999 is a valid amount); the signature over the
    // original body no longer matches.
    assert.ok(/capability_signature_invalid/.test(res.reason), res.reason);
});
test('a malformed base receipt (not capability_only) refuses', async () => {
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    cr.receipt.payload.claim.capability_only = false;
    const res = await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS });
    assert.equal(res.ok, false);
    assert.equal(res.reason, 'capability_malformed');
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const { capabilityReceipt } = await buildV2();
    const res = await verifyCapabilityReceiptV2(capabilityReceipt, { trustedIssuerKeys: PINS, mldsaBackendLoader: async () => null });
    assert.equal(res.ok, false);
    assert.ok(/pq_backend_unavailable/.test(res.reason), res.reason);
});
// --- fail-closed on junk ------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyCapabilityReceiptV2(junk, { trustedIssuerKeys: PINS });
        assert.equal(res.ok, false);
    }
    const cr = structuredClone((await buildV2()).capabilityReceipt);
    delete cr.capability_signature.pq_public_key;
    assert.equal((await verifyCapabilityReceiptV2(cr, { trustedIssuerKeys: PINS })).ok, false);
});
