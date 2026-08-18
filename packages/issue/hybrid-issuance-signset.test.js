// SPDX-License-Identifier: Apache-2.0
// Generated from hybrid-issuance-signset.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * createHybridReceiptFromSignSet() in src/hybrid-issuance.ts: minting an
 * EP-RECEIPT-HYBRID-v1 receipt from a CUSTODY SIGNER rather than from raw
 * private key material.
 *
 * Why this entry point has to exist: a deployment whose classical leg is behind
 * a KMS/HSM boundary has no secret bytes to hand to createHybridReceipt(). It
 * has a registered dual signer that will sign(bytes) on request. Without this
 * path, a custody-resolved `dual` default would resolve to a posture that
 * deployment could not execute.
 *
 * What the suite pins:
 *   - The signed bytes are built HERE from the REGISTERED algorithm set. The
 *     signer chooses nothing about what it signs, so the anti-stripping
 *     commitment is a property of this module, not of the signer.
 *   - Byte identity with the key-material path: the same payload under the same
 *     keys yields a byte-identical document either way (ML-DSA-65 signing is
 *     run in its FIPS 204 deterministic variant so the comparison is exact).
 *   - A signer that returns a narrowed, widened, or empty set is a THROW. The
 *     required set is never narrowed to what a signer happened to return, and
 *     a missing ML-DSA backend surfaces as `pq_backend_unavailable`, never as a
 *     classical-only receipt.
 *
 * Real ML-DSA-65 runs here; a green run means the PQ leg actually signed and
 * actually verified. Nothing here is deployed or FIPS validated.
 *
 * Run: node --test packages/issue/hybrid-issuance-signset.test.js
 *  or: npx tsx --test packages/issue/hybrid-issuance-signset.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { HYBRID_RECEIPT_PROFILE, HYBRID_RECEIPT_REQUIRED_ALGORITHMS, createHybridReceipt, createHybridReceiptFromSignSet, generateHybridIssuerKeyBundle, hybridSignedBytes, loadAgilityModule, signingKeysFromHybridBundle, verificationKeysFromHybridBundle, verifyHybridReceipt, } from './dist/hybrid-issuance.js';
import { canonicalize } from './dist/index.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const agility = await loadAgilityModule();
assert.ok(agility, 'EP-SIG-AGILITY-v1 module must resolve; a skipped suite proves nothing');
const bundle = await generateHybridIssuerKeyBundle({
    ed25519KeyId: 'ep:key:signset-ed25519#1',
    mldsaKeyId: 'ep:key:signset-ml-dsa-65#1',
    seed: new Uint8Array(32).fill(5),
});
const signingKeys = signingKeysFromHybridBundle(bundle);
const verificationKeys = verificationKeysFromHybridBundle(bundle);
const ED_PUBLIC = crypto.createPublicKey({
    key: Buffer.from(bundle.ed25519.public_key, 'base64url'),
    format: 'der',
    type: 'spki',
});
const PQ_PUBLIC = new Uint8Array(Buffer.from(bundle['ml-dsa-65'].public_key, 'base64url'));
const PAYLOAD = Object.freeze({
    action: { parameters: { amount: '100.00' }, type: 'wire.transfer.1' },
    issued_at: '2026-08-18T00:00:00Z',
    issuer: 'ep:issuer:signset-test',
});
/** The structural shape of HybridCustodySigner#signSet in lib/key-custody.ts. */
async function signSet(bytes) {
    const buf = Buffer.from(bytes);
    return [
        {
            alg: 'Ed25519',
            sig: crypto.sign(null, buf, signingKeys.ed25519PrivateKey).toString('base64url'),
            key_id: bundle.ed25519.key_id,
        },
        {
            alg: 'ML-DSA-65',
            sig: Buffer.from(ml_dsa65.sign(new Uint8Array(buf), new Uint8Array(Buffer.from(bundle['ml-dsa-65'].private_key, 'base64url')), { extraEntropy: false })).toString('base64url'),
            key_id: bundle['ml-dsa-65'].key_id,
        },
    ];
}
test('mints a verifiable EP-RECEIPT-HYBRID-v1 receipt from a signSet signer', async () => {
    const doc = await createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet });
    assert.equal(doc['@version'], HYBRID_RECEIPT_PROFILE);
    assert.equal(doc.profile.id, HYBRID_RECEIPT_PROFILE);
    assert.deepEqual(doc.profile.required_algorithms, [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS]);
    assert.deepEqual(doc.signatures.map((s) => s.alg), [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS]);
    assert.deepEqual(doc.signatures.map((s) => s.key_id), [bundle.ed25519.key_id, bundle['ml-dsa-65'].key_id]);
    const result = await verifyHybridReceipt(doc, verificationKeys);
    assert.equal(result.verified, true);
    assert.equal(result.reason, null);
    assert.equal(result.checks.signatures_valid, true);
});
test('the required-algorithm SET is inside the bytes the signer was handed', async () => {
    const seen = [];
    const recording = async (bytes) => {
        seen.push(Buffer.from(bytes));
        return signSet(bytes);
    };
    const doc = await createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet: recording });
    assert.equal(seen.length, 1, 'both legs must sign ONE set of bytes, produced once');
    const text = seen[0].toString('utf8');
    assert.ok(text.includes('"required_algorithms":["Ed25519","ML-DSA-65"]'));
    assert.ok(text.includes(`"@version":"${HYBRID_RECEIPT_PROFILE}"`));
    // Those bytes are exactly what this module rebuilds from the REGISTERED set,
    // and both legs verify over them independently of the verifier.
    const rebuilt = hybridSignedBytes(doc.payload, HYBRID_RECEIPT_REQUIRED_ALGORITHMS);
    assert.equal(seen[0].toString('base64'), rebuilt.toString('base64'));
    assert.equal(crypto.verify(null, rebuilt, ED_PUBLIC, Buffer.from(doc.signatures[0].sig, 'base64url')), true);
    assert.equal(ml_dsa65.verify(new Uint8Array(Buffer.from(doc.signatures[1].sig, 'base64url')), new Uint8Array(rebuilt), PQ_PUBLIC), true);
});
test('is byte-identical to the key-material path for the same payload and keys', async () => {
    const fromSigner = await createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet });
    const fromKeys = await createHybridReceipt({
        payload: PAYLOAD,
        keys: signingKeys,
        deterministic: true,
    });
    // key_id is carried by the bundle in both paths, so the documents match byte
    // for byte. If either path ever assembled a different shape, this fails.
    assert.equal(canonicalize(fromSigner), canonicalize(fromKeys));
});
test('carries optional metadata and refuses metadata outside the canonicalization profile', async () => {
    const doc = await createHybridReceiptFromSignSet({
        payload: PAYLOAD,
        signSet,
        metadata: { gate: 'ep:gate:1' },
    });
    assert.deepEqual(doc.metadata, { gate: 'ep:gate:1' });
    assert.equal((await verifyHybridReceipt(doc, verificationKeys)).verified, true);
    await assert.rejects(() => createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet, metadata: { n: 1.5 } }), /outside the EP canonicalization profile/);
});
test('a narrowed, widened, empty, or malformed set is a THROW, never a receipt', async () => {
    // Narrowed: the classical leg alone. The registered set is not narrowed to
    // what the signer returned.
    await assert.rejects(() => createHybridReceiptFromSignSet({
        payload: PAYLOAD,
        signSet: async (bytes) => (await signSet(bytes)).slice(0, 1),
    }), /no ML-DSA-65 leg/);
    // Widened: an algorithm this profile does not commit to must not ride along.
    await assert.rejects(() => createHybridReceiptFromSignSet({
        payload: PAYLOAD,
        signSet: async (bytes) => [...(await signSet(bytes)), { alg: 'Ed448', sig: 'AAAA' }],
    }), /unexpected algorithm: Ed448/);
    await assert.rejects(() => createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet: async () => [] }), /no Ed25519 leg/);
    await assert.rejects(() => createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet: async () => ({ ok: true }) }), /one signature per required algorithm/);
    await assert.rejects(() => createHybridReceiptFromSignSet({ payload: PAYLOAD, signSet: undefined }), /signSet must be a dual-signer/);
});
test('an absent ML-DSA backend propagates as pq_backend_unavailable, never as a classical-only receipt', async () => {
    await assert.rejects(() => createHybridReceiptFromSignSet({
        payload: PAYLOAD,
        // What softwareMldsaSigner does when @noble/post-quantum will not resolve.
        signSet: async () => {
            throw new Error('softwareMldsaSigner: refusing to sign: pq_backend_unavailable');
        },
    }), /pq_backend_unavailable/);
});
test('a payload outside the canonicalization profile refuses BEFORE the signer is called', async () => {
    let called = 0;
    await assert.rejects(() => createHybridReceiptFromSignSet({
        payload: { amount: 1.5 },
        signSet: async (bytes) => { called += 1; return signSet(bytes); },
    }), /outside the EP canonicalization profile/);
    assert.equal(called, 0);
});
