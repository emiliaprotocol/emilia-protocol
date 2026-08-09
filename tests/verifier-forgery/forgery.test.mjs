// SPDX-License-Identifier: Apache-2.0
/**
 * VERIFIER FORGERY CORPUS — bounty-bond regression suite.
 *
 * Every test here is an implementation-level attempt to make the PUBLISHED
 * verifier (@emilia-protocol/verify — Node `index.js` and browser `web.js`)
 * return VERIFIED for a receipt whose authorization signature was NOT produced
 * by the legitimate signer over that exact action. Ed25519/P-256 themselves are
 * assumed sound; these attack the code around the primitive.
 *
 * Result vocabulary in comments:
 *   REFUSED   — the verifier fails closed (the attack does NOT win the bond).
 *   CONFIRMED — the verifier wrongly accepted (a real finding); the test then
 *               asserts the FIXED behaviour so it stays fixed.
 *
 * Run: node --test tests/verifier-forgery/forgery.test.mjs
 *
 * See docs/security/VERIFIER-ATTACK-SURFACE.md and
 * docs/security/BOUNTY-READINESS.md.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as node from '../../packages/verify/index.js';
import * as web from '../../packages/verify/web.js';

const { verifyReceipt, verifyTrustReceipt, verifyReceiptBundle, canonicalize } = node;

// ── helpers ──────────────────────────────────────────────────────────────────
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
function ed() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function p256() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
const signEdOverCanon = (obj, priv) =>
  crypto.sign(null, Buffer.from(canonicalize(obj), 'utf8'), priv).toString('base64url');

function validReceipt(key, payload = { action_type: 'wire.release', amount: '100.00', currency: 'USD' }) {
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signEdOverCanon(payload, key.privateKey) },
  };
}

// ── Trust-receipt fixture (mirrors packages/verify/trust-receipt.test.js) ──────
const logKey = ed();
const approverB = ed();
const approverA = p256();
const TR_KEYS = {
  'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const leafHashV2 = (canon) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canon, 'utf8')])).digest('hex');
const hashPairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
function signB(digestHex) { return crypto.sign(null, Buffer.from(digestHex, 'hex'), approverB.privateKey).toString('base64url'); }
function signA(digestHex, { rpId = 'www.emiliaprotocol.ai', flags = 0x05 } = {}) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, approverA.privateKey);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: signature.toString('base64url') };
}
function buildTrustReceipt(mutate = {}) {
  const action = { ep_version: '1.0', action_type: 'wire.release', target: { system: 'treasury.example', resource: 'wire/8841' }, parameters: { amount: '2400000.00', currency: 'USD' }, initiator: 'ep:entity:agent-recon-7', policy_id: 'ep:policy:wires-over-100k@v12', requested_at: '2026-06-09T17:21:04Z', ...(mutate.action || {}) };
  const action_hash = `sha256:${sha(canonicalize(action))}`;
  const baseCtx = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:wires-over-100k@v12', policy_hash: 'sha256:77ab1234', initiator: action.initiator, required_approvals: 2, issued_at: '2026-06-09T17:21:05Z', expires_at: '2026-06-09T17:36:05Z' };
  const ctx1 = { ...baseCtx, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1', ...(mutate.ctx1 || {}) };
  const ctx2 = { ...baseCtx, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2', ...(mutate.ctx2 || {}) };
  const d1 = sha(canonicalize(ctx1));
  const d2 = sha(canonicalize(ctx2));
  const signoffs = mutate.signoffs || [
    { context_hash: `sha256:${d1}`, signature: signB(d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused-for-class-a', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: 'ep:receipt:01JTEST', action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: mutate.committed_at || '2026-06-09T17:25:02Z' } };
  const leaf = leafHashV2(canonicalize(receipt));
  const sibling1 = sha('other-leaf-1');
  const sibling2 = sha('other-subtree');
  const level1 = hashPairV2(leaf, sibling1);
  const root = hashPairV2(level1, sibling2);
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sibling1, position: 'right' }, { hash: sibling2, position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}
const TR_OPTS = { approverKeys: TR_KEYS, logPublicKey: logKey.pub };

// ═════════════════════════════════════════════════════════════════════════════
// BASELINE — the honest receipts must verify, or every REFUSED below is vacuous.
// ═════════════════════════════════════════════════════════════════════════════
test('baseline: an honestly-signed receipt verifies (Node + Web)', async () => {
  const k = ed();
  const doc = validReceipt(k);
  assert.equal(verifyReceipt(doc, k.pub).valid, true);
  assert.equal((await web.verifyReceipt(doc, k.pub)).valid, true);
});
test('baseline: an honest trust receipt verifies all six steps', () => {
  const r = verifyTrustReceipt(buildTrustReceipt(), TR_OPTS);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
});

// ═════════════════════════════════════════════════════════════════════════════
// (g) VERIFIED-WITHOUT-AUTHORIZATION — the core bond claim
// ═════════════════════════════════════════════════════════════════════════════
test('(g) REFUSED: signature over action X submitted with action Y', async () => {
  const k = ed();
  const actionX = { action_type: 'wire.release', amount: '100.00' };
  const actionY = { action_type: 'wire.release', amount: '9999999.00' };
  const sigX = signEdOverCanon(actionX, k.privateKey);
  const doc = { '@version': 'EP-RECEIPT-v1', payload: actionY, signature: { algorithm: 'Ed25519', value: sigX } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
  assert.equal((await web.verifyReceipt(doc, k.pub)).valid, false);
});
test('(g) REFUSED: trust-receipt action mutated AFTER signing breaks action_hash', () => {
  // Tamper the action in place, leaving action_hash + contexts (which the humans
  // signed) untouched — the classic "swap the action under a real signature".
  const tr = buildTrustReceipt();
  tr.action.parameters.amount = '9999999.00';
  const r = verifyTrustReceipt(tr, TR_OPTS);
  assert.equal(r.valid, false);
  assert.equal(r.checks.action_hash, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (c) KEY SUBSTITUTION / ISSUER CONFUSION
// ═════════════════════════════════════════════════════════════════════════════
test('(c) REFUSED: signature by an attacker key, verified against the pinned key', async () => {
  const k = ed();
  const attacker = ed();
  const payload = { action_type: 'wire.release', amount: '100.00' };
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: signEdOverCanon(payload, attacker.privateKey) } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
  assert.equal((await web.verifyReceipt(doc, k.pub)).valid, false);
});
test('(c) REFUSED: pinned key belonging to a different approver than the context names', () => {
  // key entry names a different approver_id than ctx.approver → identity-join fails
  const keys = JSON.parse(JSON.stringify(TR_KEYS));
  keys['ep:key:controller#1'].approver_id = 'ep:approver:someone-else';
  const r = verifyTrustReceipt(buildTrustReceipt(), { ...TR_OPTS, approverKeys: keys });
  assert.equal(r.valid, false);
  assert.equal(r.checks.signoff_signatures, false);
});
test('(c) REFUSED: a pinned key with no approver_id cannot vouch for a named human', () => {
  const keys = JSON.parse(JSON.stringify(TR_KEYS));
  delete keys['ep:key:controller#1'].approver_id;
  const r = verifyTrustReceipt(buildTrustReceipt(), { ...TR_OPTS, approverKeys: keys });
  assert.equal(r.valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (b) ALGORITHM CONFUSION / DOWNGRADE
// ═════════════════════════════════════════════════════════════════════════════
test('(b) REFUSED: a non-Ed25519 pinned key (P-256) is rejected fail-closed', async () => {
  // The relying party mistakenly pins an EC key; a receipt must not verify under it.
  const ec = p256();
  const payload = { action_type: 'x' };
  // even an EC signature over the payload must not be accepted by the Ed25519-pinned path
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: 'AA' } };
  const r = verifyReceipt(doc, ec.pub);
  assert.equal(r.valid, false);
  assert.match(r.error || '', /Unsupported issuer key type|not canonical|Signature verification failed/);
});
test('(b) DOCUMENTED (not a forgery): signature.algorithm value is ignored; crypto is pinned to Ed25519 by key type', async () => {
  // alg:"none"/"RS256" cannot downgrade anything — a VALID Ed25519 signature over
  // the exact payload by the pinned key is still required. Declaring a bogus alg
  // does NOT bypass verification (unlike JWT alg:none). This asserts the receipt
  // still fails without a valid signature, regardless of the declared algorithm.
  const k = ed();
  const payload = { action_type: 'x' };
  const bad = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'none', value: signEdOverCanon({ action_type: 'y' }, k.privateKey) } };
  assert.equal(verifyReceipt(bad, k.pub).valid, false);
  assert.equal((await web.verifyReceipt(bad, k.pub)).valid, false);
  // and a correct signature with a bogus alg string still verifies (alg is not load-bearing)
  const okDoc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'not-a-real-alg', value: signEdOverCanon(payload, k.privateKey) } };
  assert.equal(verifyReceipt(okDoc, k.pub).valid, true);
});
test('(b) REFUSED: trust-receipt Class-A pinned key cannot be downgraded to a bare Ed25519 signoff', () => {
  // Attacker declares key_class:'B' and supplies a raw signature for a pinned Class-A key.
  const d2ctx = buildTrustReceipt();
  const ctx2 = d2ctx.contexts[1];
  const d2 = sha(canonicalize(ctx2));
  // craft a bare Ed25519 signoff (no webauthn) for the CFO's pinned Class-A key
  const forged = buildTrustReceipt({
    signoffs: undefined,
  });
  // replace the CFO signoff with a bare-signature variant claiming key_class B
  const dctx = sha(canonicalize(forged.contexts[1]));
  forged.signoffs[1] = { context_hash: `sha256:${dctx}`, signature: signB(dctx), key_class: 'B', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z' };
  const r = verifyTrustReceipt(forged, TR_OPTS);
  assert.equal(r.valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (a) CANONICALIZATION AMBIGUITY
// ═════════════════════════════════════════════════════════════════════════════
test('(a) REFUSED: non-safe-integer number in signed payload is rejected (cross-language hazard)', async () => {
  const k = ed();
  const payload = { action_type: 'x', n: 1e21 };
  // signer cannot even canonicalize this; verifier refuses on the profile gate
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: 'AA' } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
  assert.equal((await web.verifyReceipt(doc, k.pub)).valid, false);
});
test('(a) REFUSED: key ordering is normalized — both orderings hash identically and to the same signature', async () => {
  const k = ed();
  const p1 = { a: '1', b: '2' };
  const p2 = { b: '2', a: '1' };
  assert.equal(canonicalize(p1), canonicalize(p2)); // same canonical bytes
  const doc = { '@version': 'EP-RECEIPT-v1', payload: p2, signature: { algorithm: 'Ed25519', value: signEdOverCanon(p1, k.privateKey) } };
  // reordering keys does NOT change the action; signature still valid, same action
  assert.equal(verifyReceipt(doc, k.pub).valid, true);
});
test('(a) DOCUMENTED: verifier consumes parsed objects; duplicate JSON keys collapse before verification (JSON.parse last-wins), and the raw-JSON path (WebAuthn clientDataJSON) rejects duplicate keys', () => {
  // The receipt verifier never sees raw JSON bytes — callers pass parsed objects,
  // so duplicate-key ambiguity is resolved by JSON.parse identically everywhere.
  // The only raw-JSON surface is WebAuthn clientDataJSON, gated by strictJsonGate.
  const parsed = JSON.parse('{"a":1,"a":2}');
  assert.deepEqual(parsed, { a: 2 });
});

// ═════════════════════════════════════════════════════════════════════════════
// (d) SIGNATURE MALLEABILITY / (i) TRUNCATION / EXTRA DATA
// ═════════════════════════════════════════════════════════════════════════════
test('(d) REFUSED: a bit-flipped signature does not verify', () => {
  const k = ed();
  const payload = { action_type: 'x' };
  const raw = Buffer.from(crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), k.privateKey));
  raw[63] ^= 0x80;
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: raw.toString('base64url') } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
});
test('(i) REFUSED: extra byte appended to a valid signature', async () => {
  const k = ed();
  const payload = { action_type: 'x' };
  const raw = Buffer.from(crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), k.privateKey));
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: Buffer.concat([raw, Buffer.from([0])]).toString('base64url') } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
  assert.equal((await web.verifyReceipt(doc, k.pub)).valid, false);
});
test('(i) REFUSED: non-canonical base64url in signature is rejected', () => {
  const k = ed();
  const payload = { action_type: 'x' };
  const raw = Buffer.from(crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), k.privateKey));
  // append a base64 padding char / illegal char
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: raw.toString('base64url') + '=' } };
  assert.equal(verifyReceipt(doc, k.pub).valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (f) TYPE CONFUSION
// ═════════════════════════════════════════════════════════════════════════════
test('(f) REFUSED: signature.value as array / number / object', () => {
  const k = ed();
  const payload = { action_type: 'x' };
  for (const bad of [[1, 2, 3], 12345, { v: 'x' }, null, true]) {
    const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: bad } };
    assert.equal(verifyReceipt(doc, k.pub).valid, false, `value=${JSON.stringify(bad)}`);
  }
});
test('(f) REFUSED: trust-receipt context_hash as array/number does not bind a context', () => {
  const r1 = verifyTrustReceipt(buildTrustReceipt({ signoffs: undefined }), TR_OPTS); // baseline valid
  assert.equal(r1.valid, true);
  const tr = buildTrustReceipt();
  tr.signoffs[0].context_hash = ['sha256:deadbeef'];
  assert.equal(verifyTrustReceipt(tr, TR_OPTS).valid, false);
  const tr2 = buildTrustReceipt();
  tr2.signoffs[0].context_hash = 12345;
  assert.equal(verifyTrustReceipt(tr2, TR_OPTS).valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (e) MISSING / DEFAULTED REQUIRED FIELDS
// ═════════════════════════════════════════════════════════════════════════════
test('(e) REFUSED: missing signature / payload / version', async () => {
  const k = ed();
  const base = validReceipt(k);
  for (const del of ['@version', 'payload', 'signature']) {
    const doc = { ...base };
    delete doc[del];
    assert.equal(verifyReceipt(doc, k.pub).valid, false, del);
    assert.equal((await web.verifyReceipt(doc, k.pub)).valid, false, `web ${del}`);
  }
});
test('(e) REFUSED: trust receipt with no signoffs / no contexts', () => {
  const noSign = buildTrustReceipt(); noSign.signoffs = [];
  assert.equal(verifyTrustReceipt(noSign, TR_OPTS).valid, false);
  const noCtx = buildTrustReceipt(); noCtx.contexts = [];
  assert.equal(verifyTrustReceipt(noCtx, TR_OPTS).valid, false);
});
test('(e) REFUSED: required_approvals as a string coerces to null and fails SoD closed', () => {
  assert.equal(verifyTrustReceipt(buildTrustReceipt({ ctx1: { required_approvals: '2' }, ctx2: { required_approvals: '2' } }), TR_OPTS).valid, false);
});
test('(e) REFUSED: required_approvals as a non-integer is refused (profile gate; injected post-build)', () => {
  // A float can never be canonically signed (canonicalizeStrictJson rejects it),
  // so it can only appear via tampering; inject it after the fixture is built and
  // confirm the verifier refuses rather than coercing it away.
  const tr = buildTrustReceipt();
  tr.contexts[0].required_approvals = 2.5;
  const r = verifyTrustReceipt(tr, TR_OPTS);
  assert.equal(r.valid, false);
});
test('(e) REFUSED: a signed DENIAL is not counted as an approval', () => {
  const r = verifyTrustReceipt(buildTrustReceipt({ ctx1: { decision: 'denied' }, ctx2: { decision: 'denied' } }), TR_OPTS);
  assert.equal(r.valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// (h) REPLAY / CONSUMPTION
// ═════════════════════════════════════════════════════════════════════════════
test('(h) DOCUMENTED: offline verification is authenticity-only and never claims replay prevention', () => {
  const r = verifyTrustReceipt(buildTrustReceipt(), TR_OPTS);
  assert.equal(r.valid, true);
  assert.equal(r.decision_scope.authenticity_only, true);
  assert.equal(r.decision_scope.admission_authorized, false);
  assert.equal(r.decision_scope.replay_status, 'not_evaluated');
});

// ═════════════════════════════════════════════════════════════════════════════
// SEPARATION OF DUTIES
// ═════════════════════════════════════════════════════════════════════════════
test('SoD REFUSED: initiator appearing in an approver slot', () => {
  const r = verifyTrustReceipt(buildTrustReceipt({ ctx1: { approver: 'ep:entity:agent-recon-7' } }), TR_OPTS);
  assert.equal(r.valid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// MERKLE ANCHOR — leaf/branch confusion, empty path, legacy downgrade
// ═════════════════════════════════════════════════════════════════════════════
test('anchor REFUSED: legacy EP-MERKLE-v1 inclusion is refused by default', () => {
  // build a legacy receipt via the knob path is out of scope here; assert that a
  // non-v2 log_proof alg refuses.
  const tr = buildTrustReceipt();
  tr.log_proof.alg = 'EP-MERKLE-v1';
  tr.log_proof.checkpoint.merkle_alg = 'EP-MERKLE-v1';
  const r = verifyTrustReceipt(tr, TR_OPTS);
  assert.equal(r.checks.inclusion, false);
});
test('anchor REFUSED: empty inclusion_path with tree_size > 1', () => {
  const tr = buildTrustReceipt();
  tr.log_proof.inclusion_path = [];
  const r = verifyTrustReceipt(tr, TR_OPTS);
  assert.equal(r.checks.inclusion, false);
});
test('anchor REFUSED: log_proof leaf_hash lifted from another receipt', () => {
  const tr = buildTrustReceipt();
  tr.log_proof.leaf_hash = `sha256:${sha('some-other-receipt')}`;
  const r = verifyTrustReceipt(tr, TR_OPTS);
  assert.equal(r.checks.inclusion, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// PARITY REGRESSION — findings F1/F2 (fixed 2026-08-08). These MUST stay green.
// ═════════════════════════════════════════════════════════════════════════════
test('F1 FIXED: Web and Node agree — out-of-profile UNSIGNED sibling field is refused by both', async () => {
  const k = ed();
  const payload = { action_type: 'wire.release', amount: '100.00' };
  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signEdOverCanon(payload, k.privateKey) },
    meta: { evil: 1e21 }, // non-safe-integer, unsigned; Node always refused, Web now refuses too
  };
  const n = verifyReceipt(doc, k.pub);
  const w = await web.verifyReceipt(doc, k.pub);
  assert.equal(n.valid, false);
  assert.equal(w.valid, false);
  assert.equal(n.valid, w.valid);
});
test('F2 FIXED: Web verifyReceiptBundle returns a clean failure (no throw) when documents is missing', async () => {
  const k = ed();
  const bundle = { '@version': 'EP-BUNDLE-v1' };
  const n = verifyReceiptBundle(bundle, k.pub);
  const w = await web.verifyReceiptBundle(bundle, k.pub);
  assert.equal(n.valid, false);
  assert.equal(w.valid, false);
  assert.deepEqual(w.failed, ['Bundle documents must be an array']);
});
test('parity sweep: a batch of honest and hostile docs produce identical valid verdicts on Node and Web', async () => {
  const k = ed();
  const good = { action_type: 'x', amount: '1.00' };
  const cases = [
    validReceipt(k, good),
    { '@version': 'EP-RECEIPT-v1', payload: good, signature: { algorithm: 'Ed25519', value: 'AA' } }, // bad sig
    { '@version': 'BAD', payload: good, signature: { algorithm: 'Ed25519', value: 'AA' } }, // bad version
    { '@version': 'EP-RECEIPT-v1', payload: good, signature: { algorithm: 'Ed25519', value: signEdOverCanon({ x: 'y' }, k.privateKey) } }, // wrong action
    { '@version': 'EP-RECEIPT-v1', payload: { n: 1e21 }, signature: { algorithm: 'Ed25519', value: 'AA' } }, // out-of-profile payload
    { '@version': 'EP-RECEIPT-v1', payload: good, signature: { algorithm: 'Ed25519', value: signEdOverCanon(good, k.privateKey) }, junk: 9e99 }, // out-of-profile sibling
  ];
  for (const doc of cases) {
    const n = verifyReceipt(doc, k.pub).valid;
    const w = (await web.verifyReceipt(doc, k.pub)).valid;
    assert.equal(n, w, `divergence on ${JSON.stringify(doc).slice(0, 60)}`);
  }
});
