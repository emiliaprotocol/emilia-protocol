// SPDX-License-Identifier: Apache-2.0
// Generated from authorization-bundle-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-AUTHORIZATION-BUNDLE-v2 hybrid Class B/C signoff verifier test. Copies
// the hostile matrix of the reference migration (revocation-v2.test.ts): leg
// stripping both directions, set narrowing (structural + independent
// crypto.verify over the narrowed bytes), duplicate algorithm, an Ed448 SPKI
// masquerading as the Ed25519 half, wrong-length signatures, plus the
// old-verifier-refuses-new capture and a valid hybrid roundtrip. Class A
// signoffs are explicitly out of scope for this migration (WebAuthn hardware
// ceiling, unchanged from v1) and are not exercised here.
//
// The PQ leg runs for real; a green run means ML-DSA-65 actually verified.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { AUTHORIZATION_BUNDLE_VERSION, AUTHORIZATION_BUNDLE_V2_VERSION, verifyAuthorizationBundle, verifyAuthorizationBundleV2, verifyAuthorizationBundleAny, signAuthorizationBundleSignoffV2, signoffV2SigningBytes, } from './authorization-bundle.js';
import { digestAeb, canonicalizeAeb } from './aeb-adapter-contract.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = '2026-08-17T12:00:00Z';
const AUDIENCE = 'https://payments.example.com';
const ACTION = { initiator: 'user:alice', action_type: 'payment.release', amount: '100.00' };
const ACTION_HASH = digestAeb(ACTION);
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const KEY_ID = 'key:bob-hybrid-1';
const APPROVER_KEYS_V2 = {
    [KEY_ID]: {
        approver_id: 'user:bob',
        key_class: 'C',
        valid_from: '2026-01-01T00:00:00Z',
        valid_to: '2027-01-01T00:00:00Z',
        public_key: edPubB64u,
        pq_public_key: pqPubB64u,
    },
};
function b64u(bytes) {
    return crypto.randomBytes(bytes).toString('base64url');
}
function baseContext() {
    return {
        action_hash: ACTION_HASH,
        policy_hash: `sha256:${'11'.repeat(32)}`,
        policy_id: 'policy:release',
        approver: 'user:bob',
        initiator: 'user:alice',
        approver_index: 1,
        required_approvals: 1,
        nonce: b64u(16),
        authorization_instance: b64u(16),
        audience: AUDIENCE,
        issued_at: '2026-08-17T11:55:00Z',
        expires_at: '2026-08-17T12:30:00Z',
        decision: 'approved',
    };
}
async function buildV2({ context = baseContext(), signers } = {}) {
    const contextDigest = digestAeb(context);
    const proof = await signAuthorizationBundleSignoffV2(contextDigest, signers ?? [
        { alg: 'Ed25519', private_key: ed.privateKey, key_id: KEY_ID },
        { alg: 'ML-DSA-65', private_key: Buffer.from(pq.secretKey).toString('base64url'), key_id: KEY_ID },
    ]);
    const signoff = {
        context_hash: contextDigest,
        approver_key_id: KEY_ID,
        key_class: 'C',
        signed_at: '2026-08-17T11:56:00Z',
        proof,
    };
    const bundle = {
        bundle_version: AUTHORIZATION_BUNDLE_V2_VERSION,
        bundle_id: 'bundle:hybrid-1',
        action: ACTION,
        action_hash: ACTION_HASH,
        contexts: [context],
        signoffs: [signoff],
        approver_key_proofs: [],
        presentation_evidence: [],
    };
    return { bundle, context, signoff };
}
function verifyOpts(context, overrides = {}) {
    return {
        now: NOW,
        audience: AUDIENCE,
        approverKeys: APPROVER_KEYS_V2,
        expectedApprovers: ['user:bob'],
        acceptedKeyClasses: ['C'],
        currentPolicy: { policy_hash: context.policy_hash, decision: 'PERMIT', checked_at: '2026-08-17T11:50:00Z', expires_at: '2026-08-17T12:30:00Z' },
        expectedAction: ACTION,
        expectedAuthorizationInstance: context.authorization_instance,
        ...overrides,
    };
}
// --- honesty gate --------------------------------------------------------
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function', 'PQ tests must run for real');
});
// --- happy path ------------------------------------------------------------
test('a real hybrid Class C signoff verifies under both pinned keys (valid roundtrip -> SATISFIED)', async () => {
    const { bundle, context } = await buildV2();
    const res = await verifyAuthorizationBundleV2(bundle, verifyOpts(context));
    assert.equal(res.verdict, 'SATISFIED', res.reasons.join(' | '));
    assert.equal(res.checks.signatures, true);
    assert.equal(res.authorization_decision, false);
});
// --- old-verifier-refuses-new -----------------------------------------------
test('the v1 (classical) verifier refuses a v2 hybrid bundle cleanly on the version marker', async () => {
    const { bundle, context } = await buildV2();
    const res = verifyAuthorizationBundle(bundle, verifyOpts(context));
    assert.equal(res.verdict, 'REFUSE');
    assert.ok(res.reasons.includes('bundle_malformed'));
});
test('the v2 verifier refuses a v1-shaped (flat signature) bundle', async () => {
    const context = baseContext();
    const v1Shaped = {
        bundle_version: AUTHORIZATION_BUNDLE_VERSION,
        bundle_id: 'bundle:v1-classical',
        action: ACTION,
        action_hash: ACTION_HASH,
        contexts: [context],
        signoffs: [{
                context_hash: digestAeb(context),
                approver_key_id: KEY_ID,
                key_class: 'C',
                signed_at: '2026-08-17T11:56:00Z',
                signature: 'x'.repeat(86) + '==',
            }],
        approver_key_proofs: [],
        presentation_evidence: [],
    };
    const res = await verifyAuthorizationBundleV2(v1Shaped, verifyOpts(context));
    assert.equal(res.verdict, 'REFUSE');
    assert.ok(res.reasons.includes('bundle_malformed'));
});
test('verifyAuthorizationBundleAny routes each version to its own verifier', async () => {
    const { bundle, context } = await buildV2();
    assert.equal((await verifyAuthorizationBundleAny(bundle, verifyOpts(context))).verdict, 'SATISFIED');
});
// --- anti-stripping ----------------------------------------------------------
test('LEG STRIPPING: removing the ML-DSA leg refuses the signoff (never SATISFIED)', async () => {
    const { bundle, context } = await buildV2();
    const stripped = structuredClone(bundle);
    stripped.signoffs[0].proof.signatures = stripped.signoffs[0].proof.signatures.filter((s) => s.alg === 'Ed25519');
    const res = await verifyAuthorizationBundleV2(stripped, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
    assert.equal(res.checks.signatures, false);
    assert.ok(res.reasons.includes('signoff_signature_invalid'));
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const { bundle, context } = await buildV2();
    const stripped = structuredClone(bundle);
    stripped.signoffs[0].proof.signatures = stripped.signoffs[0].proof.signatures.filter((s) => s.alg === 'ML-DSA-65');
    const res = await verifyAuthorizationBundleV2(stripped, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
});
test('SET NARROWING: narrowing required_algorithms to Ed25519-only refuses structurally and cryptographically', async () => {
    const { bundle, context } = await buildV2();
    const narrowed = structuredClone(bundle);
    narrowed.signoffs[0].proof.required_algorithms = ['Ed25519'];
    const res = await verifyAuthorizationBundleV2(narrowed, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
    assert.equal(res.checks.signatures, false);
    // Independent cryptographic half: the surviving Ed25519 signature was made
    // over bytes committing to the FULL required set. signoffV2SigningBytes()
    // itself refuses a non-registered set (it only ever rebuilds from the
    // REGISTERED set), so the narrowed bytes are recomputed by hand here,
    // mirroring what a stripping attacker would have to forge.
    const contextDigest = digestAeb(context);
    const fullBytes = signoffV2SigningBytes(contextDigest);
    const survivingSig = Buffer.from(bundle.signoffs[0].proof.signatures.find((s) => s.alg === 'Ed25519').sig, 'base64url');
    assert.equal(crypto.verify(null, fullBytes, ed.publicKey, survivingSig), true, 'sanity: the surviving signature DOES verify over the full (unmodified) committed bytes');
    const narrowedBytes = Buffer.from(`EP-AUTHORIZATION-BUNDLE-SIGNOFF-v2\0${canonicalizeAeb({ context_hash: contextDigest, required_algorithms: ['Ed25519'] })}`, 'utf8');
    assert.equal(crypto.verify(null, narrowedBytes, ed.publicKey, survivingSig), false, 'narrowing the committed set must break the surviving signature');
});
test('DUPLICATE ALGORITHM: two entries for one algorithm refuse', async () => {
    const { bundle, context } = await buildV2();
    const dup = structuredClone(bundle);
    dup.signoffs[0].proof.signatures = [dup.signoffs[0].proof.signatures[0], dup.signoffs[0].proof.signatures[0]];
    const res = await verifyAuthorizationBundleV2(dup, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
});
// --- wrong-length signature ---------------------------------------------------
test('WRONG-LENGTH SIGNATURE: a truncated Ed25519 leg refuses', async () => {
    const { bundle, context } = await buildV2();
    const truncated = structuredClone(bundle);
    const leg = truncated.signoffs[0].proof.signatures.find((s) => s.alg === 'Ed25519');
    leg.sig = Buffer.from(leg.sig, 'base64url').subarray(0, 10).toString('base64url');
    const res = await verifyAuthorizationBundleV2(truncated, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
});
// --- masquerade ----------------------------------------------------------------
test('ED448 MASQUERADE: an Ed448 SPKI pinned as the Ed25519 half refuses', async () => {
    const { bundle, context } = await buildV2();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448Pub = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const res = await verifyAuthorizationBundleV2(bundle, verifyOpts(context, {
        approverKeys: { [KEY_ID]: { ...APPROVER_KEYS_V2[KEY_ID], public_key: ed448Pub } },
    }));
    assert.notEqual(res.verdict, 'SATISFIED');
    assert.equal(res.checks.signatures, false);
});
// --- pinning ---------------------------------------------------------------
test('a key entry missing the ML-DSA half refuses (both halves required)', async () => {
    const { bundle, context } = await buildV2();
    const { pq_public_key: _pq, ...halfKey } = APPROVER_KEYS_V2[KEY_ID];
    const res = await verifyAuthorizationBundleV2(bundle, verifyOpts(context, {
        approverKeys: { [KEY_ID]: halfKey },
    }));
    assert.notEqual(res.verdict, 'SATISFIED');
    assert.equal(res.checks.signatures, false);
});
test('PQ KEY SUBSTITUTION: a different pinned ML-DSA key refuses', async () => {
    const { bundle, context } = await buildV2();
    const other = ml_dsa65.keygen(crypto.randomBytes(32));
    const res = await verifyAuthorizationBundleV2(bundle, verifyOpts(context, {
        approverKeys: { [KEY_ID]: { ...APPROVER_KEYS_V2[KEY_ID], pq_public_key: Buffer.from(other.publicKey).toString('base64url') } },
    }));
    assert.notEqual(res.verdict, 'SATISFIED');
});
// --- fail-closed backend ------------------------------------------------------
test('NO ML-DSA BACKEND is a refusal, never a SATISFIED verdict on the classical leg alone', async () => {
    const { bundle, context } = await buildV2();
    const res = await verifyAuthorizationBundleV2(bundle, { ...verifyOpts(context), mldsaBackendLoader: async () => null });
    assert.notEqual(res.verdict, 'SATISFIED');
    assert.equal(res.checks.signatures, false);
});
// --- binding -----------------------------------------------------------------
test('TAMPERED AFTER SIGNING: editing signed_at after signing does not affect the signoff signature (it only binds the context digest)', async () => {
    // Honest boundary check: v2 signoffs sign the CONTEXT DIGEST, not the
    // signoff envelope itself (matching v1's convention). Tampering a
    // context field changes context_hash, which then fails to match the
    // signed digest -- exercised by the next test.
    const { bundle, context } = await buildV2();
    const tampered = structuredClone(bundle);
    tampered.signoffs[0].signed_at = '2026-08-17T11:57:00Z';
    const res = await verifyAuthorizationBundleV2(tampered, verifyOpts(context));
    assert.equal(res.verdict, 'SATISFIED', res.reasons.join(' | '));
});
test('TAMPERED CONTEXT: editing a signed context field after signing breaks context/signoff coverage', async () => {
    const { bundle, context } = await buildV2();
    const tampered = structuredClone(bundle);
    tampered.contexts[0].policy_id = 'policy:different';
    const res = await verifyAuthorizationBundleV2(tampered, verifyOpts(context));
    assert.notEqual(res.verdict, 'SATISFIED');
});
// --- fail-closed on junk -------------------------------------------------------
test('malformed input refuses without throwing', async () => {
    const { context } = await buildV2();
    for (const junk of [null, undefined, 'x', 42, [], {}]) {
        const res = await verifyAuthorizationBundleV2(junk, verifyOpts(context));
        assert.notEqual(res.verdict, 'SATISFIED');
    }
});
