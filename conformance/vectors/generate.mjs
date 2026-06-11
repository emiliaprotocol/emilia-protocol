// SPDX-License-Identifier: Apache-2.0
// Deterministic generator for the EP-RECEIPT-v1 cross-language conformance
// vectors. Fixed Ed25519 seeds → reproducible keys + signatures, so re-running
// this regenerates byte-identical receipts.v1.json. Run: node generate.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';

const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hashPair = (a, b) => { const s = [a, b].sort(); return sha(s[0] + s[1]); };

// Deterministic Ed25519 keypair from a fixed 32-byte seed (PKCS8 DER prefix + seed).
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyFromSeed(byte) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, byte)]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64url');
  return { priv, pub };
}
const KEY = keyFromSeed(0xA1);        // the canonical signer
const OTHER = keyFromSeed(0xB2);      // an unrelated key (wrong-key vector)
const sign = (payload, k = KEY) => crypto.sign(null, Buffer.from(canon(payload), 'utf8'), k.priv).toString('base64url');
const receipt = (payload, extra = {}) => ({ '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: sign(payload) }, ...extra });

// A valid Merkle anchor for a receipt: leaf folds through one sibling to the root.
const leaf = sha('ep-leaf-0001');
const sibling = sha('ep-sibling-0001');
const root = hashPair(leaf, sibling);
const goodAnchor = { leaf_hash: leaf, merkle_proof: [{ hash: sibling, position: 'right' }], merkle_root: root };

const V = [];
const add = (id, description, expectValid, reason, public_key, document) =>
  V.push({ id, description, expect: { valid: expectValid }, ...(reason ? { reason } : {}), public_key, document });

// ── ACCEPT class ────────────────────────────────────────────────────────────
add('accept_minimal', 'Minimal valid receipt', true, null, KEY.pub,
  receipt({ receipt_id: 'tr_min', issuer: 'ep:demo', created_at: '2026-06-11T00:00:00Z' }));

add('accept_nested_context', 'Deeply nested payload — recursive canonicalization must match across implementations', true, null, KEY.pub,
  receipt({
    receipt_id: 'tr_nested', action_type: 'large_payment_release',
    context: { amount: 82000, currency: 'USD', change: { after_bank_hash: 'b'.repeat(64), fields: ['routing', 'account'] }, risk_signals: ['new_destination', 'after_hours'] },
    issued_at: '2026-06-09T17:21:05.000Z',
  }));

// Key-order-independence: sign one object, present the SAME logical payload with keys reversed.
{
  const logical = { receipt_id: 'tr_order', a: 1, z: 26, nested: { y: 2, b: 3 } };
  const sig = sign(logical);
  const reordered = { nested: { b: 3, y: 2 }, z: 26, a: 1, receipt_id: 'tr_order' };
  add('accept_key_order_independent', 'Reordered keys verify identically (canonical JSON is order-independent)', true, null, KEY.pub,
    { '@version': 'EP-RECEIPT-v1', payload: reordered, signature: { algorithm: 'Ed25519', value: sig } });
}

add('accept_with_merkle_anchor', 'Valid receipt with a valid Merkle inclusion proof', true, null, KEY.pub,
  receipt({ receipt_id: 'tr_anchored', issuer: 'ep:demo' }, { anchor: goodAnchor }));

// ── REJECT class (each targets one invariant) ────────────────────────────────
add('reject_unsupported_version', 'Unknown document version is refused', false, 'unsupported_version', KEY.pub,
  { '@version': 'EP-RECEIPT-v2', payload: { receipt_id: 'tr_v2' }, signature: { algorithm: 'Ed25519', value: sign({ receipt_id: 'tr_v2' }) } });

add('reject_missing_signature', 'Missing signature value is refused', false, 'missing_signature', KEY.pub,
  { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: 'tr_nosig' }, signature: { algorithm: 'Ed25519' } });

{
  const payload = { receipt_id: 'tr_tamper', context: { amount: 82000 } };
  const doc = receipt(payload);
  doc.payload = { receipt_id: 'tr_tamper', context: { amount: 820000 } }; // mutate after signing
  add('reject_tampered_payload', 'Payload mutated after signing — signature no longer matches', false, 'tampered_payload', KEY.pub, doc);
}

add('reject_wrong_key', 'Valid signature, but verified against an unrelated public key', false, 'wrong_key', OTHER.pub,
  receipt({ receipt_id: 'tr_wrongkey', issuer: 'ep:demo' }));

add('reject_malformed_signature', 'Signature value is not a valid signature', false, 'malformed_signature', KEY.pub,
  { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: 'tr_bad' }, signature: { algorithm: 'Ed25519', value: 'bm90LWEtc2lnbmF0dXJl' } });

add('reject_tampered_anchor', 'Receipt signature is valid but the Merkle proof does not reconstruct the claimed root', false, 'tampered_anchor', KEY.pub,
  receipt({ receipt_id: 'tr_badanchor', issuer: 'ep:demo' }, { anchor: { leaf_hash: leaf, merkle_proof: [{ hash: sha('evil-sibling'), position: 'right' }], merkle_root: root } }));

const out = {
  suite: 'EP-RECEIPT-v1',
  vectors_version: '1.0.0',
  description: 'Canonical cross-language conformance vectors for the EMILIA Protocol authorization-receipt format (EP-RECEIPT-v1). An EP-conformant verifier MUST return expect.valid for every vector. Used to prove the JS, Python, and Go reference verifiers agree.',
  algorithm: { signature: 'Ed25519', canonicalization: 'recursive key-sorted JSON (RFC 8785-style)', anchor: 'SHA-256 sorted-pair Merkle' },
  count: V.length,
  vectors: V,
};
writeFileSync(new URL('./receipts.v1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote receipts.v1.json — ${V.length} vectors (${V.filter(v => v.expect.valid).length} accept, ${V.filter(v => !v.expect.valid).length} reject)`);
