// SPDX-License-Identifier: Apache-2.0
// Generated from jws.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-RECEIPT-JWS-PROFILE-v1 tests.
//
// Run via:
//   npm test            (node --test jws.test.js)
//
// Proves:
//   - round-trip: receipt -> JWS -> receipt (byte-identical canonical payload)
//   - tamper rejection: flipping a payload byte breaks verification
//   - wrong-key rejection
//   - header rejection: alg/typ outside the profile is refused
//   - CROSS-VERIFY: the standard `jose` library accepts our JWS (the whole point
//     of the profile — JOSE interop). `jose` is a dev-only dependency.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { compactVerify, importSPKI } from 'jose';
import { serializeReceiptJws, verifyReceiptJws, deriveKid, JWS_ALG, JWS_TYP, } from './jws.js';
// ── Helpers ─────────────────────────────────────────────────────────────────
// Same recursive JCS canonicalization the profile uses internally.
function canonicalize(v) {
    if (v === null || v === undefined)
        return JSON.stringify(v);
    if (Array.isArray(v))
        return `[${v.map(canonicalize).join(',')}]`;
    if (typeof v === 'object') {
        return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
    }
    return JSON.stringify(v);
}
// Deterministic Ed25519 keypair from a fixed seed (PKCS8 DER prefix + 32-byte seed).
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyFromSeed(byte) {
    const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, byte)]), format: 'der', type: 'pkcs8' });
    const pubDer = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' });
    return { priv, pubB64u: pubDer.toString('base64url'), pubDer };
}
const KEY = keyFromSeed(0xA1);
const OTHER = keyFromSeed(0xB2);
function signedRawJws(headerText, payloadText) {
    const hB64 = Buffer.from(headerText, 'utf8').toString('base64url');
    const pB64 = Buffer.from(payloadText, 'utf8').toString('base64url');
    const sig = crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), KEY.priv).toString('base64url');
    return `${hB64}.${pB64}.${sig}`;
}
function sampleDoc(payload) {
    return { '@version': 'EP-RECEIPT-v1', payload, public_key: KEY.pubB64u };
}
const NESTED_PAYLOAD = {
    receipt_id: 'tr_jws_nested',
    action_type: 'large_payment_release',
    context: {
        amount: 82000,
        currency: 'USD',
        change: { after_bank_hash: 'b'.repeat(64), fields: ['routing', 'account'] },
        risk_signals: ['new_destination', 'after_hours'],
    },
    created_at: '2026-06-29T12:00:00.000Z',
};
// ── Round-trip ────────────────────────────────────────────────────────────────
test('round-trips a receipt: receipt -> JWS -> receipt', () => {
    const doc = sampleDoc(NESTED_PAYLOAD);
    const jws = serializeReceiptJws(doc, KEY.priv, { publicKey: KEY.pubB64u });
    assert.equal(jws.split('.').length, 3, 'compact JWS has three segments');
    const res = verifyReceiptJws(jws, KEY.pubB64u);
    assert.equal(res.valid, true, res.error);
    assert.deepEqual(res.payload, NESTED_PAYLOAD);
    assert.equal(res.header.alg, JWS_ALG);
    assert.equal(res.header.typ, JWS_TYP);
    assert.equal(res.header.kid, deriveKid(KEY.pubB64u));
    // Verified payload bytes are the EP canonical (JCS) form.
    assert.equal(canonicalize(res.payload), canonicalize(NESTED_PAYLOAD));
});
test('accepts a KeyObject and base64url SPKI key interchangeably', () => {
    const doc = sampleDoc({ receipt_id: 'tr_keytypes', issuer: 'ep:demo' });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const ko = crypto.createPublicKey({ key: KEY.pubDer, format: 'der', type: 'spki' });
    assert.equal(verifyReceiptJws(jws, ko).valid, true);
    assert.equal(verifyReceiptJws(jws, KEY.pubB64u).valid, true);
});
// ── Tamper rejection ────────────────────────────────────────────────────────
test('rejects a JWS whose payload byte was flipped', () => {
    const doc = sampleDoc({ receipt_id: 'tr_tamper', context: { amount: 82000 } });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const [h, p, s] = jws.split('.');
    // Flip one byte of the payload segment (decode, mutate, re-encode base64url).
    const payloadBuf = Buffer.from(p, 'base64url');
    payloadBuf[Math.floor(payloadBuf.length / 2)] ^= 0x01;
    const tampered = `${h}.${payloadBuf.toString('base64url')}.${s}`;
    const res = verifyReceiptJws(tampered, KEY.pubB64u);
    assert.equal(res.valid, false);
    // The flip lands in the signed input, so the signature check is what fails.
    assert.equal(res.checks.signature, false);
});
test('rejects a JWS whose signature was truncated/altered', () => {
    const doc = sampleDoc({ receipt_id: 'tr_sig', issuer: 'ep:demo' });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const [h, p, s] = jws.split('.');
    const sigBuf = Buffer.from(s, 'base64url');
    sigBuf[0] ^= 0xff;
    const res = verifyReceiptJws(`${h}.${p}.${sigBuf.toString('base64url')}`, KEY.pubB64u);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// ── Wrong-key rejection ───────────────────────────────────────────────────────
test('rejects a valid JWS verified against an unrelated key', () => {
    const doc = sampleDoc({ receipt_id: 'tr_wrongkey', issuer: 'ep:demo' });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const res = verifyReceiptJws(jws, OTHER.pubB64u);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, false);
});
// ── Header / structure rejection ──────────────────────────────────────────────
test('rejects a JWS with a non-profile alg', () => {
    const header = { alg: 'HS256', typ: JWS_TYP };
    const hB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const pB64 = Buffer.from(canonicalize({ receipt_id: 'x' }), 'utf8').toString('base64url');
    const sig = crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), KEY.priv).toString('base64url');
    const res = verifyReceiptJws(`${hB64}.${pB64}.${sig}`, KEY.pubB64u);
    assert.equal(res.valid, false);
    assert.equal(res.checks.header, false);
});
test('rejects a JWS with the wrong typ', () => {
    const header = { alg: JWS_ALG, typ: 'application/jwt' };
    const hB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const pB64 = Buffer.from(canonicalize({ receipt_id: 'x' }), 'utf8').toString('base64url');
    const sig = crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), KEY.priv).toString('base64url');
    const res = verifyReceiptJws(`${hB64}.${pB64}.${sig}`, KEY.pubB64u);
    assert.equal(res.valid, false);
    assert.equal(res.checks.header, false);
});
test('rejects a malformed compact serialization', () => {
    assert.equal(verifyReceiptJws('only.two', KEY.pubB64u).valid, false);
    assert.equal(verifyReceiptJws('a.b.c.d', KEY.pubB64u).valid, false);
    assert.equal(verifyReceiptJws(42, KEY.pubB64u).valid, false);
});
test('rejects validly signed duplicate protected-header and payload members', () => {
    const duplicateHeader = signedRawJws(`{"alg":"${JWS_ALG}","alg":"${JWS_ALG}","typ":"${JWS_TYP}"}`, '{"receipt_id":"duplicate_header"}');
    const duplicatePayload = signedRawJws(`{"alg":"${JWS_ALG}","typ":"${JWS_TYP}"}`, '{"receipt_id":"first","receipt_id":"first"}');
    assert.equal(verifyReceiptJws(duplicateHeader, KEY.pubB64u).valid, false);
    assert.match(verifyReceiptJws(duplicateHeader, KEY.pubB64u).error, /strict JSON/);
    assert.equal(verifyReceiptJws(duplicatePayload, KEY.pubB64u).valid, false);
    assert.match(verifyReceiptJws(duplicatePayload, KEY.pubB64u).error, /strict JSON/);
});
test('rejects protected members outside the profile and non-canonical base64url', () => {
    const unknownMember = signedRawJws(`{"alg":"${JWS_ALG}","typ":"${JWS_TYP}","jwk":{"kty":"OKP"}}`, '{"receipt_id":"unknown_header"}');
    assert.equal(verifyReceiptJws(unknownMember, KEY.pubB64u).valid, false);
    const valid = serializeReceiptJws(sampleDoc({ receipt_id: 'padded' }), KEY.priv);
    const [h, p, s] = valid.split('.');
    assert.equal(verifyReceiptJws(`${h}=.${p}.${s}`, KEY.pubB64u).valid, false);
    assert.equal(verifyReceiptJws(`${h}.${p}.${Buffer.alloc(63).toString('base64url')}`, KEY.pubB64u).valid, false);
});
test('rejects a payload that is valid-signed but not canonical (round-trip guard)', () => {
    // Hand-build a JWS over NON-canonical payload bytes (keys out of sorted order).
    const header = { alg: JWS_ALG, typ: JWS_TYP };
    const hB64 = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const nonCanonical = '{"z":1,"a":2}'; // sorted JCS would be {"a":2,"z":1}
    const pB64 = Buffer.from(nonCanonical, 'utf8').toString('base64url');
    const sig = crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), KEY.priv).toString('base64url');
    const res = verifyReceiptJws(`${hB64}.${pB64}.${sig}`, KEY.pubB64u);
    assert.equal(res.valid, false);
    assert.equal(res.checks.signature, true, 'signature is genuinely valid');
    assert.equal(res.checks.roundtrip, false, 'but the payload is not EP canonical form');
});
// ── CROSS-VERIFY with the standard `jose` library (the interop requirement) ────
test('the produced JWS verifies with jose.compactVerify (importSPKI)', async () => {
    const doc = sampleDoc(NESTED_PAYLOAD);
    const jws = serializeReceiptJws(doc, KEY.priv, { publicKey: KEY.pubB64u });
    const pem = `-----BEGIN PUBLIC KEY-----\n${KEY.pubDer.toString('base64')}\n-----END PUBLIC KEY-----`;
    const key = await importSPKI(pem, JWS_ALG);
    const { payload, protectedHeader } = await compactVerify(jws, key);
    assert.equal(protectedHeader.alg, JWS_ALG);
    assert.equal(protectedHeader.typ, JWS_TYP);
    // jose hands back the raw payload bytes — they are the EP canonical form.
    assert.equal(Buffer.from(payload).toString('utf8'), canonicalize(NESTED_PAYLOAD));
    assert.deepEqual(JSON.parse(Buffer.from(payload).toString('utf8')), NESTED_PAYLOAD);
});
test('jose.compactVerify also accepts a Node KeyObject', async () => {
    const doc = sampleDoc({ receipt_id: 'tr_jose_ko', issuer: 'ep:demo' });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const ko = crypto.createPublicKey({ key: KEY.pubDer, format: 'der', type: 'spki' });
    const { payload } = await compactVerify(jws, ko);
    assert.equal(Buffer.from(payload).toString('utf8'), canonicalize(doc.payload));
});
test('jose REJECTS a tampered JWS (negative cross-check)', async () => {
    const doc = sampleDoc({ receipt_id: 'tr_jose_neg', context: { amount: 82000 } });
    const jws = serializeReceiptJws(doc, KEY.priv);
    const [h, p, s] = jws.split('.');
    const payloadBuf = Buffer.from(p, 'base64url');
    payloadBuf[0] ^= 0x01;
    const tampered = `${h}.${payloadBuf.toString('base64url')}.${s}`;
    const ko = crypto.createPublicKey({ key: KEY.pubDer, format: 'der', type: 'spki' });
    await assert.rejects(() => compactVerify(tampered, ko));
});
// ── Serialization guards ──────────────────────────────────────────────────────
test('refuses to serialize a non-EP-RECEIPT-v1 document', () => {
    assert.throws(() => serializeReceiptJws({ '@version': 'EP-RECEIPT-v2', payload: {} }, KEY.priv));
    assert.throws(() => serializeReceiptJws({ '@version': 'EP-RECEIPT-v1' }, KEY.priv));
});
test('refuses a non-Ed25519 signing key', () => {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    assert.throws(() => serializeReceiptJws(sampleDoc({ receipt_id: 'x' }), privateKey));
});
