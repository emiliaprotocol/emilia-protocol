// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { b64u, jcs } from '../src/canonical.ts';
import { APPROVAL_TYPE, approvalDigest, buildPayload, keyIdFromSpki, p256PublicKey, parseReceipt, parseReceiptsText, verifyReceiptSignature } from '../src/receipt.ts';
import type { Receipt, WebAuthnProof } from '../src/receipt.ts';
import { hex, newApprover, receiptFor, resign } from './helpers.ts';

const approver = newApprover();
const base = receiptFor(approver, { chunkId: 'chunk-1', token: hex('token-1') });

test('ES256 receipt: signs JCS(payload); D = SHA-256(JCS(payload))', () => {
  assert.equal(base.payload.type, APPROVAL_TYPE);
  assert.equal(base.payload.approver_kid, keyIdFromSpki(approver.spki));
  assert.deepEqual(verifyReceiptSignature(base), { ok: true, kid: base.payload.approver_kid, format: 'es256' });
  const d = crypto.createHash('sha256').update(jcs(base.payload)).digest();
  assert.deepEqual(approvalDigest(base.payload), d);
  // The ES256 signature is ECDSA over exactly D: verifying the prehash agrees.
  const sig = Buffer.from(base.proof.signature, 'base64url');
  assert.ok(crypto.verify('sha256', Buffer.from(jcs(base.payload)), { key: approver.publicKey, dsaEncoding: 'ieee-p1363' }, sig));
  assert.deepEqual(parseReceipt(JSON.parse(JSON.stringify(base))), { ok: true, value: base });
});

test('ES256 receipt: changing any signed field breaks the signature', () => {
  const changes: Record<string, string> = {
    workspace: 'other', sandbox: 'other', chunk_id: 'chunk-2', review_token: hex('token-2'), rule_name: 'other_rule',
    rule_digest: `sha256:${hex('x')}`, candidate_effective_policy_hash: hex('y'), issued_at: '2026-09-29T08:00:00.000Z', nonce: b64u(Buffer.alloc(16, 7)),
  };
  for (const [field, value] of Object.entries(changes)) {
    const tampered = { payload: { ...base.payload, [field]: value }, proof: base.proof } as Receipt;
    const result = verifyReceiptSignature(tampered);
    assert.equal(result.ok, false, field);
    assert.match(result.reason ?? '', /does not verify/);
  }
});

test('ES256 receipt: key substitution and key type are refused', () => {
  const other = newApprover();
  const swapped = { payload: base.payload, proof: { ...base.proof, public_key_spki: other.spkiB64u } } as Receipt;
  assert.match(verifyReceiptSignature(swapped).reason ?? '', /approver_kid does not match/);
  // Re-signed by the other key while still naming the first key's kid.
  const lying = { payload: base.payload, proof: { format: 'es256', public_key_spki: other.spkiB64u, signature: b64u(crypto.sign('sha256', Buffer.from(jcs(base.payload)), { key: other.privateKey, dsaEncoding: 'ieee-p1363' })) } } as Receipt;
  assert.equal(verifyReceiptSignature(lying).ok, false);
  for (const [type, opts] of [['ec', { namedCurve: 'P-384' }], ['ed25519', {}]] as const) {
    const k = crypto.generateKeyPairSync(type as 'ec', opts as { namedCurve: string });
    const spki = b64u(k.publicKey.export({ format: 'der', type: 'spki' }));
    assert.match((p256PublicKey(spki) as { reason: string }).reason, /not an EC P-256 key/);
  }
  const padded = b64u(Buffer.concat([approver.spki, Buffer.from([0])]));
  assert.equal(p256PublicKey(padded).ok, false);
  assert.equal(p256PublicKey('not base64!').ok, false);
});

test('parseReceipt refuses malformed receipts with a reason, never throws', () => {
  const good = JSON.parse(JSON.stringify(base));
  const mutate = (f: (r: Record<string, any>) => void) => { const r = JSON.parse(JSON.stringify(good)); f(r); return r; };
  const cases: [unknown, RegExp][] = [
    [null, /not an object/], [[], /not an object/], ['receipt', /not an object/], [42, /not an object/],
    [mutate((r) => { r.extra = 1; }), /unknown member/],
    [mutate((r) => { delete r.proof; }), /missing: proof/],
    [mutate((r) => { r.payload.extra = 1; }), /unknown member/],
    [mutate((r) => { delete r.payload.nonce; }), /missing: nonce/],
    [mutate((r) => { r.payload.type = 'other'; }), /payload.type/],
    [mutate((r) => { r.payload.decision = 'reject'; }), /decision/],
    [mutate((r) => { r.payload.review_token = 'ABC'; }), /review_token/],
    [mutate((r) => { r.payload.review_token = hex('t').toUpperCase(); }), /review_token/],
    [mutate((r) => { r.payload.rule_digest = hex('r'); }), /rule_digest/],
    [mutate((r) => { r.payload.candidate_effective_policy_hash = 'zz'; }), /candidate_effective_policy_hash/],
    [mutate((r) => { r.payload.approver_kid = 'short'; }), /approver_kid/],
    [mutate((r) => { r.payload.issued_at = '2026-09-29 07:00:00'; }), /issued_at/],
    [mutate((r) => { r.payload.issued_at = '2026-13-45T07:00:00Z'; }), /issued_at/],
    [mutate((r) => { r.payload.nonce = b64u(Buffer.alloc(8)); }), /nonce/],
    [mutate((r) => { r.payload.sandbox = ''; }), /sandbox/],
    [mutate((r) => { r.payload.sandbox = 'has space'; }), /sandbox/],
    [mutate((r) => { r.payload.chunk_id = 5; }), /chunk_id/],
    [mutate((r) => { r.proof.format = 'rs256'; }), /proof.format/],
    [mutate((r) => { r.proof.signature = b64u(Buffer.alloc(63)); }), /64-byte/],
    [mutate((r) => { r.proof.signature = `${r.proof.signature}=`; }), /64-byte/],
    [mutate((r) => { r.proof.public_key_spki = 'x y'; }), /public_key_spki/],
    [JSON.parse(`{"payload":${JSON.stringify(good.payload)},"proof":${JSON.stringify(good.proof)},"__proto__":{"x":1}}`), /unknown member/],
  ];
  for (const [input, reason] of cases) {
    const result = parseReceipt(input);
    assert.equal(result.ok, false, JSON.stringify(input)?.slice(0, 80));
    if (!result.ok) assert.match(result.reason, reason);
  }
});

test('parseReceiptsText: array, single object, JSON lines, and bad lines', () => {
  const one = JSON.stringify(base);
  assert.equal(parseReceiptsText(`[${one},${one}]`).receipts.length, 2);
  assert.equal(parseReceiptsText(one).receipts.length, 1);
  const lines = parseReceiptsText(`${one}\n\n{"payload":1,"payload":2}\n${one}\nnot json`).receipts;
  assert.deepEqual(lines.map((r) => r.ok), [true, false, true, false]);
  assert.match((lines[1] as { reason: string }).reason, /duplicate/);
  assert.deepEqual(parseReceiptsText('   ').receipts, []);
});

test('buildPayload refuses a chunk whose rule was never canonicalized', () => {
  const result = buildPayload({ workspace: 'default', sandbox: 'sb', chunk: { chunk_id: 'c', review_token: hex('t'), rule_name: 'r', rule_digest: null, candidate_effective_policy_hash: '' }, publicKeySpkiDer: approver.spki });
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /refusing to sign/);
});

// WebAuthn: a passkey signs authenticatorData || SHA-256(clientDataJSON), with
// clientDataJSON.challenge = base64url(D). These assertions are synthesized
// with a software P-256 key in the authenticator's format; no real passkey
// was used.
function webauthnReceipt(opts: { flags?: number; type?: string; challengeFor?: Receipt; rpId?: string; origin?: string; clientData?: string } = {}): Receipt {
  const payload = base.payload;
  const challenge = b64u(approvalDigest((opts.challengeFor ?? base).payload));
  const clientData = opts.clientData ?? JSON.stringify({ type: opts.type ?? 'webauthn.get', challenge, origin: opts.origin ?? 'https://approve.example.com', crossOrigin: false });
  const rpIdHash = crypto.createHash('sha256').update(opts.rpId ?? 'approve.example.com').digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([opts.flags ?? 0x05]), Buffer.from([0, 0, 0, 1])]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, approver.privateKey); // DER, as authenticators emit
  const proof: WebAuthnProof = { format: 'webauthn', public_key_spki: approver.spkiB64u, authenticator_data: b64u(authData), client_data_json: b64u(Buffer.from(clientData)), signature: b64u(signature) };
  return { payload, proof };
}

const PINS = { rp_id: 'approve.example.com', origins: ['https://approve.example.com'] };

test('WebAuthn receipt: verified through verifyWebAuthnSignoff; UP and UV required', () => {
  const good = webauthnReceipt();
  assert.ok(parseReceipt(JSON.parse(JSON.stringify(good))).ok);
  assert.deepEqual(verifyReceiptSignature(good), { ok: true, kid: base.payload.approver_kid, format: 'webauthn' });
  assert.equal(verifyReceiptSignature(good, PINS).ok, true);
  assert.match(verifyReceiptSignature(webauthnReceipt({ flags: 0x01 })).reason ?? '', /user_verified/);
  assert.match(verifyReceiptSignature(webauthnReceipt({ flags: 0x04 })).reason ?? '', /user_present/);
  assert.match(verifyReceiptSignature(webauthnReceipt({ type: 'webauthn.create' })).reason ?? '', /client_data_type/);
  const other = resign(base, approver, { chunk_id: 'chunk-9' });
  assert.match(verifyReceiptSignature(webauthnReceipt({ challengeFor: other })).reason ?? '', /challenge_binding/);
  assert.match(verifyReceiptSignature(webauthnReceipt({ clientData: '{"type":"webauthn.get","type":"webauthn.get","challenge":"x","origin":"o"}' })).reason ?? '', /duplicate/);
});

test('WebAuthn receipt: relying-party pins are enforced when given', () => {
  assert.equal(verifyReceiptSignature(webauthnReceipt({ rpId: 'evil.example' }), PINS).ok, false);
  assert.match(verifyReceiptSignature(webauthnReceipt({ origin: 'https://evil.example' }), PINS).reason ?? '', /origin/);
  // Without pins the same assertion still verifies (integrity only).
  assert.equal(verifyReceiptSignature(webauthnReceipt({ rpId: 'evil.example' })).ok, true);
});
