// SPDX-License-Identifier: Apache-2.0
// Generated from hybrid-receipt-profile.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Tests for src/hybrid-receipt-profile.ts (the Gate-side EP-RECEIPT-HYBRID-v1
 * deployment profile).
 *
 * Drives the REAL issuance module (packages/issue) and therefore REAL
 * ML-DSA-65 through EP-SIG-AGILITY-v1. The suite FAILS LOUDLY if that module
 * cannot be resolved rather than skipping: a profile test that never minted a
 * hybrid receipt proves nothing about the profile.
 *
 * Run: node --test packages/gate/hybrid-receipt-profile.test.js
 *  or: npx tsx --test packages/gate/hybrid-receipt-profile.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CLASSICAL_RECEIPT_PROFILE_ID, HYBRID_ISSUANCE_MODES, HYBRID_PROFILE_REASONS, HYBRID_RECEIPT_PROFILE_ID, acceptUnderHybridProfile, issueUnderHybridProfile, loadHybridIssuanceModule, resolveHybridReceiptProfile, } from './dist/hybrid-receipt-profile.js';
import { generateHybridIssuerKeyBundle, signingKeysFromHybridBundle, verificationKeysFromHybridBundle, } from '../issue/dist/hybrid-issuance.js';
import { canonicalize } from '../verify/index.js';
// --- fixtures ---------------------------------------------------------------
const issuance = await loadHybridIssuanceModule();
assert.ok(issuance, 'the hybrid issuance module must resolve; a skipped profile suite proves nothing');
const bundle = await generateHybridIssuerKeyBundle();
const hybridSigningKeys = signingKeysFromHybridBundle(bundle);
const hybridVerificationKeys = verificationKeysFromHybridBundle(bundle);
const PAYLOAD = {
    action: { parameters: { amount: '25.00' }, type: 'payment.capture.1' },
    issued_at: '2026-08-16T00:00:00Z',
    issuer: 'ep:issuer:gate-test',
};
// A minimal stand-in for whatever EP-RECEIPT-v1 issuance a deployment already
// has at its receipt-issuing call site.
const classicalKeys = crypto.generateKeyPairSync('ed25519');
const classicalPublicKey = classicalKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
function issueClassical({ payload, metadata }) {
    return {
        '@version': CLASSICAL_RECEIPT_PROFILE_ID,
        payload,
        signature: {
            algorithm: 'Ed25519',
            value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), classicalKeys.privateKey).toString('base64url'),
        },
        ...(metadata ? { metadata } : {}),
    };
}
function verifyClassical(receipt) {
    try {
        const ok = crypto.verify(null, Buffer.from(canonicalize(receipt.payload), 'utf8'), crypto.createPublicKey({ key: Buffer.from(classicalPublicKey, 'base64url'), format: 'der', type: 'spki' }), Buffer.from(receipt.signature.value, 'base64url'));
        return ok ? { valid: true } : { valid: false, error: 'signature_invalid' };
    }
    catch {
        return { valid: false, error: 'signature_invalid' };
    }
}
// --- config -----------------------------------------------------------------
test('resolveHybridReceiptProfile defaults to disabled and fails closed on garbage', () => {
    for (const off of [undefined, null, {}, { hybrid_issuance: undefined }, false, { hybrid_issuance: false }]) {
        const profile = resolveHybridReceiptProfile(off);
        assert.equal(profile.mode, 'disabled');
        assert.equal(profile.issues_hybrid, false);
        assert.equal(profile.requires_hybrid, false);
    }
    assert.equal(resolveHybridReceiptProfile('enabled').mode, 'enabled');
    assert.equal(resolveHybridReceiptProfile({ hybrid_issuance: 'enabled' }).mode, 'enabled');
    assert.equal(resolveHybridReceiptProfile(true).mode, 'enabled');
    const required = resolveHybridReceiptProfile({ hybrid_issuance: 'required' });
    assert.equal(required.mode, 'required');
    assert.equal(required.issues_hybrid, true);
    assert.equal(required.requires_hybrid, true);
    assert.deepEqual([...HYBRID_ISSUANCE_MODES], ['disabled', 'enabled', 'required']);
    // A misconfigured security flag stops the deployment; it is never rounded
    // down to the permissive default.
    for (const bad of ['on', 'REQUIRED', 'yes', 1, { hybrid_issuance: 'optional' }]) {
        assert.throws(() => resolveHybridReceiptProfile(bad), /hybrid_issuance must be one of/);
    }
    assert.ok(Object.isFrozen(resolveHybridReceiptProfile('enabled')));
});
// --- issuance ---------------------------------------------------------------
test('disabled issues classical receipts and refuses hybrid requests', async () => {
    const profile = resolveHybridReceiptProfile('disabled');
    const classical = await issueUnderHybridProfile({ profile, payload: PAYLOAD, issueClassical });
    assert.equal(classical.ok, true);
    assert.equal(classical.ok && classical.profile, CLASSICAL_RECEIPT_PROFILE_ID);
    assert.equal(classical.ok && classical.receipt['@version'], CLASSICAL_RECEIPT_PROFILE_ID);
    const refused = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        requestHybrid: true,
        hybridKeys: hybridSigningKeys,
        issueClassical,
    });
    assert.equal(refused.ok, false);
    assert.equal(!refused.ok && refused.reason, HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_DISABLED);
});
test('enabled mints a hybrid receipt only when the request asks for one', async () => {
    const profile = resolveHybridReceiptProfile('enabled');
    const classical = await issueUnderHybridProfile({ profile, payload: PAYLOAD, issueClassical });
    assert.equal(classical.ok && classical.profile, CLASSICAL_RECEIPT_PROFILE_ID);
    const hybrid = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        requestHybrid: true,
        hybridKeys: hybridSigningKeys,
        issueClassical,
    });
    assert.equal(hybrid.ok, true);
    assert.equal(hybrid.ok && hybrid.profile, HYBRID_RECEIPT_PROFILE_ID);
    const doc = hybrid.ok ? hybrid.receipt : null;
    assert.equal(doc['@version'], HYBRID_RECEIPT_PROFILE_ID);
    assert.deepEqual(doc.signatures.map((s) => s.alg), ['Ed25519', 'ML-DSA-65']);
    // And it really verifies under the profile's own acceptance path.
    const accepted = await acceptUnderHybridProfile({
        profile,
        receipt: doc,
        hybridKeys: hybridVerificationKeys,
        verifyClassical,
    });
    assert.equal(accepted.ok, true);
    assert.equal(accepted.ok && accepted.profile, HYBRID_RECEIPT_PROFILE_ID);
});
test('required mints hybrid by default and refuses an explicit classical ask', async () => {
    const profile = resolveHybridReceiptProfile('required');
    const hybrid = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        hybridKeys: hybridSigningKeys,
        issueClassical,
    });
    assert.equal(hybrid.ok && hybrid.profile, HYBRID_RECEIPT_PROFILE_ID);
    const refused = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        requestHybrid: false,
        hybridKeys: hybridSigningKeys,
        issueClassical,
    });
    assert.equal(!refused.ok && refused.reason, HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
});
test('a hybrid intent that cannot be met refuses; it never falls back to classical', async () => {
    const profile = resolveHybridReceiptProfile('required');
    // No keys configured.
    const noKeys = await issueUnderHybridProfile({ profile, payload: PAYLOAD, issueClassical });
    assert.equal(!noKeys.ok && noKeys.reason, HYBRID_PROFILE_REASONS.HYBRID_KEYS_MISSING);
    // Issuance module unreachable.
    const noModule = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        hybridKeys: hybridSigningKeys,
        issuance: {},
        issueClassical,
    });
    assert.equal(!noModule.ok && noModule.reason, HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);
    // ML-DSA backend unavailable: createHybridReceipt throws, the Gate refuses.
    const noBackend = await issueUnderHybridProfile({
        profile,
        payload: PAYLOAD,
        hybridKeys: hybridSigningKeys,
        agilityOptions: { mldsaBackendLoader: () => null },
        issueClassical,
    });
    assert.equal(!noBackend.ok && noBackend.reason, HYBRID_PROFILE_REASONS.HYBRID_ISSUANCE_UNAVAILABLE);
    // None of the three produced a receipt of any kind.
    for (const outcome of [noKeys, noModule, noBackend]) {
        assert.equal(outcome.receipt, undefined);
    }
});
// --- acceptance -------------------------------------------------------------
test('required refuses a classical receipt and disabled refuses a hybrid one', async () => {
    const required = resolveHybridReceiptProfile('required');
    const disabled = resolveHybridReceiptProfile('disabled');
    const classicalReceipt = issueClassical({ payload: PAYLOAD });
    const hybridOutcome = await issueUnderHybridProfile({
        profile: required,
        payload: PAYLOAD,
        hybridKeys: hybridSigningKeys,
    });
    const hybridReceipt = hybridOutcome.ok ? hybridOutcome.receipt : null;
    assert.ok(hybridReceipt);
    const classicalUnderRequired = await acceptUnderHybridProfile({
        profile: required,
        receipt: classicalReceipt,
        hybridKeys: hybridVerificationKeys,
        verifyClassical,
    });
    assert.equal(!classicalUnderRequired.ok && classicalUnderRequired.reason, HYBRID_PROFILE_REASONS.HYBRID_REQUIRED);
    const hybridUnderDisabled = await acceptUnderHybridProfile({
        profile: disabled,
        receipt: hybridReceipt,
        hybridKeys: hybridVerificationKeys,
        verifyClassical,
    });
    assert.equal(!hybridUnderDisabled.ok && hybridUnderDisabled.reason, HYBRID_PROFILE_REASONS.HYBRID_RECEIPT_NOT_ACCEPTED);
    // The classical path still works where it is allowed.
    const classicalUnderEnabled = await acceptUnderHybridProfile({
        profile: resolveHybridReceiptProfile('enabled'),
        receipt: classicalReceipt,
        hybridKeys: hybridVerificationKeys,
        verifyClassical,
    });
    assert.equal(classicalUnderEnabled.ok, true);
    assert.equal(classicalUnderEnabled.ok && classicalUnderEnabled.profile, CLASSICAL_RECEIPT_PROFILE_ID);
});
test('acceptance surfaces the underlying refusal for a tampered hybrid receipt', async () => {
    const profile = resolveHybridReceiptProfile('required');
    const outcome = await issueUnderHybridProfile({ profile, payload: PAYLOAD, hybridKeys: hybridSigningKeys });
    assert.ok(outcome.ok);
    const doc = JSON.parse(JSON.stringify(outcome.ok ? outcome.receipt : null));
    doc.signatures = doc.signatures.filter((s) => s.alg !== 'ML-DSA-65');
    const stripped = await acceptUnderHybridProfile({ profile, receipt: doc, hybridKeys: hybridVerificationKeys });
    assert.equal(!stripped.ok && stripped.reason, 'hybrid_leg_missing');
    assert.equal(!stripped.ok && stripped.detail?.failed_algorithm, 'ML-DSA-65');
});
test('an unrecognized receipt profile is refused, never guessed at', async () => {
    const profile = resolveHybridReceiptProfile('enabled');
    for (const receipt of [null, undefined, [], 'EP-RECEIPT-v1', { '@version': 'EP-RECEIPT-v2' }, {}]) {
        const outcome = await acceptUnderHybridProfile({
            profile,
            receipt,
            hybridKeys: hybridVerificationKeys,
            verifyClassical,
        });
        assert.equal(!outcome.ok && outcome.reason, HYBRID_PROFILE_REASONS.UNKNOWN_RECEIPT_PROFILE);
    }
});
test('the profile object itself is validated at the call site', async () => {
    await assert.rejects(() => issueUnderHybridProfile({ profile: { mode: 'required' }, payload: PAYLOAD }), /resolveHybridReceiptProfile/);
    await assert.rejects(() => acceptUnderHybridProfile({ profile: null, receipt: {} }), /resolveHybridReceiptProfile/);
});
