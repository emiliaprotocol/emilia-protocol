// SPDX-License-Identifier: Apache-2.0
//
// Deterministic generator for the EP-RECEIPT-JWS-PROFILE-v1 cross-language
// conformance vectors. Fixed Ed25519 seeds -> reproducible keys + JWS, so
// re-running regenerates byte-identical jws.json.
//
// Each vector is a COMPACT JWS (RFC 7515) over the JCS-canonical bytes of an
// EP-RECEIPT-v1 payload, signed with EdDSA/Ed25519 (RFC 8037). An EP-conformant
// (or any standard JOSE) verifier MUST return expect.valid for every vector.
//
//   node generate-jws.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);
const b64u = (buf) => Buffer.from(buf).toString('base64url');

// Deterministic Ed25519 keypair from a fixed 32-byte seed (PKCS8 DER prefix + seed).
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
function keyFromSeed(byte) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, byte)]), format: 'der', type: 'pkcs8' });
  // Node's crypto.createPublicKey accepts a private KeyObject at runtime (it derives
  // the public key), but @types/node's overloads don't include KeyObject — cast only.
  const pub = crypto.createPublicKey(/** @type {any} */ (priv)).export({ type: 'spki', format: 'der' }).toString('base64url');
  return { priv, pub };
}
const KEY = keyFromSeed(0xA1);        // the canonical signer (same seed as receipts.v1.json)
const OTHER = keyFromSeed(0xB2);      // an unrelated key (wrong-key vector)

const TYP = 'application/ep-receipt+jws';
const deriveKid = (pub) => crypto.createHash('sha256').update(pub, 'utf8').digest('hex').slice(0, 32);

/**
 * @typedef {Object} JwsOptions
 * @property {{ priv: import('node:crypto').KeyObject, pub: string }} [key]
 * @property {string|null} [kid]
 * @property {{ alg: string, typ: string, kid?: string }} [header]
 * @property {(parts: string[]) => string[]} [mutate]
 */

// Build a compact JWS over canon(payload). `mutate` optionally rewrites a
// segment AFTER signing to produce a reject vector.
/**
 * @param {unknown} payload
 * @param {JwsOptions} [options]
 */
function jws(payload, { key = KEY, kid = deriveKid(KEY.pub), header, mutate } = {}) {
  const hdr = header || { alg: 'EdDSA', typ: TYP, ...(kid ? { kid } : {}) };
  const hB64 = b64u(Buffer.from(JSON.stringify(hdr), 'utf8'));
  const pB64 = b64u(Buffer.from(canon(payload), 'utf8'));
  const sig = b64u(crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), key.priv));
  let parts = [hB64, pB64, sig];
  if (mutate) parts = mutate(parts);
  return parts.join('.');
}

const V = [];
const add = (id, description, expectValid, reason, public_key, compact_jws) =>
  V.push({ id, description, expect: { valid: expectValid }, ...(reason ? { reason } : {}), public_key, compact_jws });

// ── ACCEPT class ──────────────────────────────────────────────────────────────
add('accept_minimal', 'Minimal valid receipt JWS', true, null, KEY.pub,
  jws({ receipt_id: 'tr_min', issuer: 'ep:demo', created_at: '2026-06-11T00:00:00Z' }));

add('accept_nested_context', 'Deeply nested payload — JCS canonicalization must match across implementations', true, null, KEY.pub,
  jws({
    receipt_id: 'tr_nested', action_type: 'large_payment_release',
    context: { amount: 82000, currency: 'USD', change: { after_bank_hash: 'b'.repeat(64), fields: ['routing', 'account'] }, risk_signals: ['new_destination', 'after_hours'] },
    issued_at: '2026-06-09T17:21:05.000Z',
  }));

add('accept_no_kid', 'Valid JWS with no kid in the protected header', true, null, KEY.pub,
  jws({ receipt_id: 'tr_nokid', issuer: 'ep:demo' }, { kid: null }));

// ── REJECT class (each targets one invariant) ────────────────────────────────
add('reject_tampered_payload', 'A payload byte was flipped after signing — signature no longer matches', false, 'tampered_payload', KEY.pub,
  jws({ receipt_id: 'tr_tamper', context: { amount: 82000 } }, {
    mutate: ([h, p, s]) => { const b = Buffer.from(p, 'base64url'); b[Math.floor(b.length / 2)] ^= 0x01; return [h, b.toString('base64url'), s]; },
  }));

add('reject_wrong_key', 'Valid signature, but verified against an unrelated public key', false, 'wrong_key', OTHER.pub,
  jws({ receipt_id: 'tr_wrongkey', issuer: 'ep:demo' }));

add('reject_tampered_signature', 'The signature segment was altered', false, 'tampered_signature', KEY.pub,
  jws({ receipt_id: 'tr_badsig', issuer: 'ep:demo' }, {
    mutate: ([h, p, s]) => { const b = Buffer.from(s, 'base64url'); b[0] ^= 0xff; return [h, p, b.toString('base64url')]; },
  }));

add('reject_unsupported_alg', 'Protected header alg is not EdDSA', false, 'unsupported_alg', KEY.pub,
  jws({ receipt_id: 'tr_alg', issuer: 'ep:demo' }, { header: { alg: 'HS256', typ: TYP } }));

add('reject_wrong_typ', 'Protected header typ is not application/ep-receipt+jws', false, 'wrong_typ', KEY.pub,
  jws({ receipt_id: 'tr_typ', issuer: 'ep:demo' }, { header: { alg: 'EdDSA', typ: 'application/jwt' } }));

add('reject_non_canonical_payload', 'Signature valid but payload bytes are not EP canonical (JCS) form', false, 'non_canonical_payload', KEY.pub,
  (() => {
    const hB64 = b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: TYP }), 'utf8'));
    const pB64 = b64u(Buffer.from('{"z":1,"a":2}', 'utf8')); // sorted JCS = {"a":2,"z":1}
    const sig = b64u(crypto.sign(null, Buffer.from(`${hB64}.${pB64}`, 'ascii'), KEY.priv));
    return `${hB64}.${pB64}.${sig}`;
  })());

add('reject_malformed_compact', 'Not a well-formed three-segment compact JWS', false, 'malformed_compact', KEY.pub,
  // Build a two-segment (header.body, no signature) string so this is a genuine
  // malformed-compact vector without embedding a literal token.
  `${b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: TYP }), 'utf8'))}.${b64u(Buffer.from('only-two-segments', 'utf8'))}`);

const out = {
  suite: 'EP-RECEIPT-JWS-PROFILE-v1',
  vectors_version: '1.0.0',
  description: 'Canonical cross-language conformance vectors for EP-RECEIPT-JWS-PROFILE-v1 — a JWS (RFC 7515) serialization of EMILIA authorization receipts. Each vector is a compact JWS over the JCS-canonical bytes of an EP-RECEIPT-v1 payload, signed EdDSA/Ed25519 (RFC 8037). A conformant verifier (EP or any standard JOSE library) MUST return expect.valid for every vector.',
  algorithm: {
    serialization: 'JWS Compact Serialization (RFC 7515)',
    alg: 'EdDSA (Ed25519, RFC 8037 / RFC 8032)',
    typ: TYP,
    payload: 'RFC 8785 (JCS) canonical bytes of the EP-RECEIPT-v1 payload',
    kid: 'first 16 bytes of SHA-256(base64url SPKI public key), hex (advisory)',
  },
  note: 'The JWS signature is a PARALLEL envelope over the SAME canonical payload as the native EP-RECEIPT-v1 Ed25519 signature; it is NOT byte-equal to that native signature value (JWS signs base64url(header).base64url(payload) per RFC 7515 §5.1).',
  count: V.length,
  vectors: V,
};

const path = resolve(here, 'jws.json');
writeFileSync(path, `${JSON.stringify(out, null, 2)}\n`);
console.log(`Wrote ${V.length} vectors -> ${path}`);
