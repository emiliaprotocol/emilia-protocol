// SPDX-License-Identifier: Apache-2.0
/**
 * EP-COSE-ENCODING-v0.1 - encoding-equivalence profile for EP receipts.
 *
 * Proves that the CAID join survives re-encoding. Two legs:
 *
 *  1. A total value mapping between the EP strict-JSON receipt domain and a
 *     deterministically encoded CBOR subset (RFC 8949 Section 4.2.1). The
 *     mapping uses TEXT map keys: the EP receipt payload is an OPEN strict-JSON
 *     document domain, so a closed integer-key table cannot be total over it
 *     without freezing the payload schema. Text keys keep the mapping total,
 *     bijective on the domain, and auditable byte-for-byte.
 *
 *  2. A COSE_Sign1 (RFC 9052, tag 18) TRANSPORT/REGISTRATION envelope whose
 *     payload is the original receipt's canonical JSON bytes (RFC 8785 profile,
 *     the same bytes the receipt's own Ed25519 signature covers). Protected
 *     headers carry the content type and the receipt action's CAID string.
 *
 * TRUST SEMANTICS (the load-bearing statement):
 *   The COSE_Sign1 signature is a NEW attestation, made by whoever holds the
 *   envelope key, over the carried bytes. It is a transport/registration
 *   signature ONLY. It is NOT the approval signature and confers NO approval,
 *   authorization, or trust semantics. Approval is proven exclusively by the
 *   receipt's own signature inside the payload, verified under the relying
 *   party's pinned issuer key over exactly the payload bytes. Because the
 *   payload is the canonical JSON receipt itself, wrapping and unwrapping the
 *   envelope changes nothing the original signature covers. The alternative
 *   profile (re-signing a CBOR-mapped receipt as a first-class COSE receipt)
 *   would mint a second first-class attestation and is deliberately NOT
 *   implemented here; it is documented as future work in the profile README.
 *
 * DETERMINISTIC ENCODING (verified by experiment, recorded in the README):
 *   RFC 8949 Section 4.2.1 - shortest-form arguments, no indefinite lengths,
 *   and map keys sorted in the bytewise lexicographic order of their
 *   deterministic encodings (NOT the older RFC 7049 length-first ordering).
 *   The strict decoder REFUSES any non-deterministic encoding with the named
 *   reason `non_deterministic_encoding` instead of accepting semantically
 *   equal bytes. Both installed CBOR libraries failed this bar by experiment
 *   (`cbor` v10 truncates output on Node 26; `cbor-x` emits non-shortest map
 *   length headers), so the encoder and strict decoder are implemented here
 *   inline, keeping this package zero-dependency. The sibling McGraw adapter's
 *   `encodeDeterministicCbor` now implements the SAME RFC 8949 Section 4.2.1
 *   bytewise-encoded-key ordering (it was historically RFC 7049 length-first;
 *   that divergence lives on only as a regression test in the McGraw suite).
 *   This module still ships its own codec under distinct names because it is a
 *   Result-typed API (refusal reasons instead of throws) with its own strict
 *   decoder, not because the orderings differ.
 *
 * NOTE ON KEY ORDER ACROSS ENCODINGS: JCS sorts object keys by UTF-16 code
 * units; CBOR deterministic order sorts by the bytes of the UTF-8 encoded key.
 * These orders can differ for keys mixing U+E000..U+FFFF with supplementary
 * characters. Equivalence in this profile is at the VALUE level: each encoding
 * applies its own deterministic order, and decoding recovers the identical
 * value, so re-canonicalizing yields identical JCS bytes and an identical CAID.
 *
 * Fail-closed: malformed or hostile input returns a refusal with a reason.
 * Nothing here throws on untrusted input.
 */

import crypto from 'node:crypto';
import { canonicalize, verifyReceipt } from './index.js';
import {
  signAgile,
  verifyAgileSignature,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, any>;

export const COSE_ENCODING_PROFILE = 'EP-COSE-ENCODING-v0.1';
/** The map-key ordering this profile ships (see module doc + README). */
export const CBOR_DETERMINISTIC_ORDER = 'rfc8949-4.2.1-bytewise-encoded-key';
export const COSE_RECEIPT_CONTENT_TYPE = 'application/emilia-receipt+json';
/** COSE alg value for EdDSA (RFC 9053 Section 2.2). */
export const COSE_ALG_EDDSA = -8;
/** Private (non-IANA-registered) protected-header label carrying the CAID. */
export const COSE_HEADER_EP_CAID = 'ep.caid';
/** COSE `crit` header label (RFC 9052 Section 3.1 / Section 5.4). */
const COSE_HEADER_CRIT = 2;
/** COSE `alg` (1), `crit` (2), `content type` (3), `kid` (4) generic labels. */
const COSE_HEADER_ALG = 1;
const COSE_HEADER_CONTENT_TYPE = 3;
const COSE_HEADER_KID = 4;
/**
 * The EXACT protected-header label set this closed profile understands. A
 * protected header carrying any label outside this set is refused: the profile
 * defines no extension semantics, so an unknown protected label is not an
 * optional extra but an unverified instruction. `crit` (2) is handled
 * separately per RFC 9052 Section 5.4 -- it is not in this set because the
 * profile understands no critical extensions, so any `crit` present refuses.
 */
const COSE_PROFILE_PROTECTED_LABELS: ReadonlySet<unknown> = new Set<unknown>([
  COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID, COSE_HEADER_EP_CAID,
]);
const COSE_SIGN1_TAG_BYTE = 0xd2; // tag 18, shortest form
const MAX_DEPTH = 64;
const MAX_ITEMS = 1 << 20;

const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
const UTF8 = new TextEncoder();

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

export interface CborOk<T> { ok: true; value: T }
export interface CborRefusal { ok: false; reason: string }
export type CborResult<T> = CborOk<T> | CborRefusal;

function refuse(reason: string): CborRefusal {
  return { ok: false, reason };
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function isPlainObject(v: unknown): v is Obj {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

// ---------------------------------------------------------------------------
// Deterministic CBOR encoder (RFC 8949 Section 4.2.1 over the EP domain)
//
// Domain: null, boolean, safe integers, text strings (well-formed),
// Uint8Array (byte strings), arrays, plain objects (text-keyed maps), and
// Map instances (for COSE header maps with integer or text labels).
// ---------------------------------------------------------------------------

function encodeHead(major: number, arg: number): Uint8Array {
  if (arg < 24) return Uint8Array.of((major << 5) | arg);
  if (arg <= 0xff) return Uint8Array.of((major << 5) | 24, arg);
  if (arg <= 0xffff) return Uint8Array.of((major << 5) | 25, arg >> 8, arg & 0xff);
  if (arg <= 0xffffffff) {
    return Uint8Array.of(
      (major << 5) | 26,
      (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff,
    );
  }
  // Safe integers above 2^32-1 need the 8-byte form.
  const big = BigInt(arg);
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  for (let i = 0; i < 8; i += 1) {
    out[8 - i] = Number((big >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

function encodeValue(value: unknown, depth: number, out: Uint8Array[]): CborRefusal | null {
  if (depth > MAX_DEPTH) return refuse('unsupported_item');
  if (value === null) { out.push(Uint8Array.of(0xf6)); return null; }
  if (value === true) { out.push(Uint8Array.of(0xf5)); return null; }
  if (value === false) { out.push(Uint8Array.of(0xf4)); return null; }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) return refuse('unsupported_item');
    // -0 canonicalizes to 0 in the strict JSON domain (JCS behavior).
    if (Object.is(value, -0)) { out.push(Uint8Array.of(0x00)); return null; }
    if (value >= 0) { out.push(encodeHead(0, value)); return null; }
    out.push(encodeHead(1, -1 - value));
    return null;
  }
  if (typeof value === 'string') {
    if (hasUnpairedSurrogate(value)) return refuse('unsupported_item');
    const bytes = UTF8.encode(value);
    out.push(encodeHead(3, bytes.length), bytes);
    return null;
  }
  if (value instanceof Uint8Array) {
    out.push(encodeHead(2, value.length), value);
    return null;
  }
  if (Array.isArray(value)) {
    out.push(encodeHead(4, value.length));
    for (const item of value) {
      const err = encodeValue(item, depth + 1, out);
      if (err) return err;
    }
    return null;
  }
  if (value instanceof Map || isPlainObject(value)) {
    const entries: Array<[unknown, unknown]> = value instanceof Map
      ? [...value.entries()]
      : Object.keys(value).map((k) => [k, (value as Obj)[k]]);
    const encoded: Array<{ key: Uint8Array; val: Uint8Array }> = [];
    for (const [k, v] of entries) {
      const keyParts: Uint8Array[] = [];
      const keyErr = encodeValue(k, depth + 1, keyParts);
      if (keyErr) return keyErr;
      const valParts: Uint8Array[] = [];
      const valErr = encodeValue(v, depth + 1, valParts);
      if (valErr) return valErr;
      encoded.push({ key: concatBytes(keyParts), val: concatBytes(valParts) });
    }
    encoded.sort((a, b) => compareBytes(a.key, b.key));
    for (let i = 1; i < encoded.length; i += 1) {
      if (compareBytes(encoded[i - 1].key, encoded[i].key) === 0) {
        return refuse('duplicate_map_key');
      }
    }
    out.push(encodeHead(5, encoded.length));
    for (const e of encoded) out.push(e.key, e.val);
    return null;
  }
  return refuse('unsupported_item');
}

/**
 * Deterministically encode a value from the profile domain.
 * Never throws; refuses out-of-domain values with `unsupported_item`.
 */
export function encodeDeterministicCbor8949(value: unknown): CborResult<Uint8Array> {
  const out: Uint8Array[] = [];
  const err = encodeValue(value, 0, out);
  if (err) return err;
  return { ok: true, value: concatBytes(out) };
}

// ---------------------------------------------------------------------------
// Strict deterministic CBOR decoder
//
// Refusal reasons:
//   malformed_cbor             - truncated input, invalid UTF-8, duplicate
//                                map keys, reserved additional-info values
//   non_deterministic_encoding - non-shortest argument, indefinite length,
//                                map keys not in bytewise order of their
//                                deterministic encodings
//   unsupported_item           - floats, simple values outside true/false/
//                                null, tags, integers beyond +/-(2^53-1)
//   trailing_bytes             - well-formed item followed by extra bytes
// ---------------------------------------------------------------------------

interface DecodeState {
  bytes: Uint8Array;
  offset: number;
  items: number;
  textKeysOnly: boolean;
}

interface Refused { refused: string }

function isRefused(v: unknown): v is Refused {
  return typeof v === 'object' && v !== null && 'refused' in (v as Obj);
}

function readHead(s: DecodeState): { major: number; arg: number } | Refused {
  if (s.offset >= s.bytes.length) return { refused: 'malformed_cbor' };
  const initial = s.bytes[s.offset];
  const major = initial >> 5;
  const ai = initial & 0x1f;
  s.offset += 1;
  if (ai < 24) return { major, arg: ai };
  if (ai === 31) {
    // Indefinite lengths are forbidden by RFC 8949 Section 4.2.1.
    return { refused: 'non_deterministic_encoding' };
  }
  if (ai > 27) return { refused: 'malformed_cbor' };
  const lengths: Record<number, number> = { 24: 1, 25: 2, 26: 4, 27: 8 };
  const n = lengths[ai];
  if (s.offset + n > s.bytes.length) return { refused: 'malformed_cbor' };
  let arg: number;
  if (n === 8) {
    let big = 0n;
    for (let i = 0; i < 8; i += 1) big = (big << 8n) | BigInt(s.bytes[s.offset + i]);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      s.offset += 8;
      return { refused: 'unsupported_item' };
    }
    arg = Number(big);
  } else {
    arg = 0;
    for (let i = 0; i < n; i += 1) arg = arg * 256 + s.bytes[s.offset + i];
  }
  s.offset += n;
  // Shortest-form check (RFC 8949 Section 4.2.1): the argument MUST use the
  // smallest encoding that fits.
  const shortest = arg < 24 ? 0 : arg <= 0xff ? 1 : arg <= 0xffff ? 2 : arg <= 0xffffffff ? 4 : 8;
  if (n !== shortest) return { refused: 'non_deterministic_encoding' };
  return { major, arg };
}

function decodeItem(s: DecodeState, depth: number): unknown | Refused {
  s.items += 1;
  if (s.items > MAX_ITEMS) return { refused: 'unsupported_item' };
  if (depth > MAX_DEPTH) return { refused: 'unsupported_item' };
  const start = s.offset;
  if (s.offset < s.bytes.length) {
    const initial = s.bytes[s.offset];
    const major = initial >> 5;
    const ai = initial & 0x1f;
    if (major === 7) {
      s.offset += 1;
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      // undefined (23), extended simple values (24), floats (25-27), break
      // (31), and reserved values are all outside the profile domain.
      if (ai >= 28 && ai <= 30) return { refused: 'malformed_cbor' };
      return { refused: 'unsupported_item' };
    }
    if (major === 6) {
      // No tags inside the profile domain; the COSE_Sign1 tag is handled
      // explicitly by the envelope parser before generic decoding.
      return { refused: 'unsupported_item' };
    }
  }
  const head = readHead(s);
  if (isRefused(head)) return head;
  const { major, arg } = head;
  if (major === 0) return arg;
  if (major === 1) return -1 - arg;
  if (major === 2) {
    if (s.offset + arg > s.bytes.length) return { refused: 'malformed_cbor' };
    const out = s.bytes.slice(s.offset, s.offset + arg);
    s.offset += arg;
    return out;
  }
  if (major === 3) {
    if (s.offset + arg > s.bytes.length) return { refused: 'malformed_cbor' };
    let text: string;
    try {
      text = FATAL_UTF8.decode(s.bytes.subarray(s.offset, s.offset + arg));
    } catch {
      return { refused: 'malformed_cbor' };
    }
    s.offset += arg;
    return text;
  }
  if (major === 4) {
    const out: unknown[] = [];
    for (let i = 0; i < arg; i += 1) {
      const item = decodeItem(s, depth + 1);
      if (isRefused(item)) return item;
      out.push(item);
    }
    return out;
  }
  if (major === 5) {
    const asObject = s.textKeysOnly;
    const object: Obj = {};
    const map = new Map<unknown, unknown>();
    let prevKeyBytes: Uint8Array | null = null;
    for (let i = 0; i < arg; i += 1) {
      const keyStart = s.offset;
      const key = decodeItem(s, depth + 1);
      if (isRefused(key)) return key;
      const keyBytes = s.bytes.slice(keyStart, s.offset);
      if (prevKeyBytes !== null) {
        const cmp = compareBytes(prevKeyBytes, keyBytes);
        if (cmp === 0) return { refused: 'malformed_cbor' }; // duplicate key
        if (cmp > 0) return { refused: 'non_deterministic_encoding' };
      }
      prevKeyBytes = keyBytes;
      const val = decodeItem(s, depth + 1);
      if (isRefused(val)) return val;
      if (asObject) {
        if (typeof key !== 'string') return { refused: 'unsupported_item' };
        object[key] = val;
      } else {
        map.set(key, val);
      }
    }
    return asObject ? object : map;
  }
  // Unreachable (majors 6 and 7 handled above), kept fail-closed.
  void start;
  return { refused: 'malformed_cbor' };
}

/**
 * Strictly decode one deterministically encoded CBOR item.
 *
 * With `textKeysOnly: true` (the receipt mapping) maps become plain objects
 * and any non-text map key refuses. With `textKeysOnly: false` (COSE header
 * maps) maps decode to Map instances preserving integer labels.
 */
export function decodeDeterministicCbor8949(
  bytes: Uint8Array,
  opts: { textKeysOnly?: boolean } = {},
): CborResult<unknown> {
  if (!(bytes instanceof Uint8Array)) return refuse('malformed_cbor');
  const s: DecodeState = {
    bytes,
    offset: 0,
    items: 0,
    textKeysOnly: opts.textKeysOnly !== false,
  };
  const item = decodeItem(s, 0);
  if (isRefused(item)) return refuse(item.refused);
  if (s.offset !== bytes.length) return refuse('trailing_bytes');
  return { ok: true, value: item };
}

// ---------------------------------------------------------------------------
// Receipt JSON <-> CBOR value mapping
// ---------------------------------------------------------------------------

/**
 * Map an EP receipt document (or any strict-JSON value) to deterministic
 * CBOR map bytes with text keys. Total over the EP canonicalization domain.
 */
export function receiptToCborBytes(receipt: unknown): CborResult<Uint8Array> {
  // The strict canonical gate first: values outside the EP profile (floats,
  // non-plain objects, cycles, unpaired surrogates) refuse before encoding.
  try {
    canonicalize(receipt);
  } catch {
    return refuse('outside_canonical_profile');
  }
  return encodeDeterministicCbor8949(receipt);
}

/**
 * Recover the receipt value from deterministic CBOR bytes. Refuses
 * non-deterministic encodings rather than accepting semantically equal bytes.
 */
export function receiptFromCborBytes(bytes: Uint8Array): CborResult<unknown> {
  const decoded = decodeDeterministicCbor8949(bytes, { textKeysOnly: true });
  if (!decoded.ok) return decoded;
  try {
    canonicalize(decoded.value);
  } catch {
    return refuse('outside_canonical_profile');
  }
  return decoded;
}

// ---------------------------------------------------------------------------
// CAID (jcs-sha256) over the receipt's action object
// ---------------------------------------------------------------------------

// Same action-type grammar as caid/impl (DESIGN.md Section 2).
const TYPE_SEGMENT_RE = /^[a-z][a-z0-9-]*$/;
const TYPE_VERSION_RE = /^[1-9][0-9]*$/;

function isValidActionType(t: unknown): t is string {
  if (typeof t !== 'string') return false;
  const segments = t.split('.');
  if (segments.length < 2) return false;
  if (!TYPE_VERSION_RE.test(segments[segments.length - 1])) return false;
  for (let i = 0; i < segments.length - 1; i += 1) {
    if (!TYPE_SEGMENT_RE.test(segments[i])) return false;
  }
  return true;
}

/**
 * Compute the jcs-sha256 CAID string for a receipt action object.
 *
 * SCOPE LIMIT: this helper exists to prove ENCODING INVARIANCE of the CAID -
 * the identifier is a digest of the action's canonical JCS bytes, so it is
 * identical no matter which envelope encoding carried the receipt. It checks
 * the action_type grammar and the canonicalization domain only. Material-field
 * validation against a pinned type definition is the CAID core's job
 * (caid/impl); a caller minting production identifiers must use that.
 */
export function receiptActionCaid(action: unknown): CborResult<{ caid: string; digest: string }> {
  if (!isPlainObject(action)) return refuse('invalid_action_object');
  if (!isValidActionType(action.action_type)) return refuse('invalid_action_type');
  let canonical: string;
  try {
    canonical = canonicalize(action);
  } catch {
    return refuse('outside_canonical_profile');
  }
  const digestBytes = crypto.createHash('sha256').update(canonical, 'utf8').digest();
  return {
    ok: true,
    value: {
      caid: `caid:1:${action.action_type}:jcs-sha256:${digestBytes.toString('base64url')}`,
      digest: `sha256:${digestBytes.toString('hex')}`,
    },
  };
}

// ---------------------------------------------------------------------------
// COSE_Sign1 transport/registration envelope
// ---------------------------------------------------------------------------

function decodeSpkiBase64url(value: unknown): crypto.KeyObject | null {
  if (typeof value !== 'string' || value.length === 0
      || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  try {
    const der = Buffer.from(value, 'base64url');
    if (der.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return null;
    return key;
  } catch {
    return null;
  }
}

function sigStructureBytes(protectedBytes: Uint8Array, payload: Uint8Array): CborResult<Uint8Array> {
  // COSE Sig_structure for COSE_Sign1 (RFC 9052 Section 4.4):
  //   ["Signature1", body_protected, external_aad, payload]
  return encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payload]);
}

export interface BuildCoseOptions {
  /** Ed25519 private key of the ENVELOPE signer (transport leg only). */
  envelopePrivateKey: crypto.KeyObject;
  /** Key identifier placed in the protected headers (COSE label 4, bstr). */
  kid: string;
}

/**
 * Wrap an EP receipt in a deterministically encoded COSE_Sign1 (tag 18)
 * transport/registration envelope.
 *
 * payload           = UTF-8 bytes of the receipt's canonical JSON (the exact
 *                     bytes the receipt's own signature already travels with)
 * protected headers = { 1: -8 (EdDSA), 3: content type, 4: kid,
 *                       "ep.caid": jcs-sha256 CAID of receipt.payload.action }
 * signature         = Ed25519 by the ENVELOPE key over Sig_structure.
 *                     A new transport attestation; NOT the approval signature.
 */
export function buildReceiptCoseSign1(receipt: unknown, opts: BuildCoseOptions): CborResult<{
  cose: Uint8Array;
  payload: Uint8Array;
  protectedHeaderBytes: Uint8Array;
  caid: string;
}> {
  if (!isPlainObject(receipt) || !isPlainObject((receipt as Obj).payload)) {
    return refuse('invalid_receipt_document');
  }
  let canonical: string;
  try {
    canonical = canonicalize(receipt);
  } catch {
    return refuse('outside_canonical_profile');
  }
  const caidResult = receiptActionCaid((receipt as Obj).payload.action);
  if (!caidResult.ok) return caidResult;
  if (typeof opts?.kid !== 'string' || opts.kid.length === 0) return refuse('invalid_kid');

  const payload = UTF8.encode(canonical);
  const protectedMap = new Map<unknown, unknown>([
    [1, COSE_ALG_EDDSA],
    [3, COSE_RECEIPT_CONTENT_TYPE],
    [4, UTF8.encode(opts.kid)],
    [COSE_HEADER_EP_CAID, caidResult.value.caid],
  ]);
  const protectedEncoded = encodeDeterministicCbor8949(protectedMap);
  if (!protectedEncoded.ok) return protectedEncoded;
  const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
  if (!sigStruct.ok) return sigStruct;

  let signature: Uint8Array;
  try {
    const key = opts.envelopePrivateKey;
    if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
      return refuse('invalid_envelope_key');
    }
    signature = new Uint8Array(crypto.sign(null, sigStruct.value, key));
  } catch {
    return refuse('invalid_envelope_key');
  }

  const body = encodeDeterministicCbor8949([
    protectedEncoded.value,
    // Unprotected headers: ALWAYS an empty map in this profile. The verifier
    // refuses any content here (unprotected_headers_present), so the encoder
    // must never populate it -- every header this profile defines is protected
    // (signed). Keeping it empty also forecloses the RFC 9052 Section 3
    // duplicate-label-across-buckets error class by construction.
    new Map(),
    payload,
    signature,
  ]);
  if (!body.ok) return body;
  return {
    ok: true,
    value: {
      cose: concatBytes([Uint8Array.of(COSE_SIGN1_TAG_BYTE), body.value]),
      payload,
      protectedHeaderBytes: protectedEncoded.value,
      caid: caidResult.value.caid,
    },
  };
}

export interface VerifyCoseOptions {
  /** SPKI-DER base64url Ed25519 public key pinned for the ENVELOPE signer. */
  envelopePublicKeyBase64url: string;
  /** SPKI-DER base64url Ed25519 public key pinned for the RECEIPT issuer. */
  receiptIssuerPublicKeyBase64url: string;
  /** Optional caller-pinned CAID; refuses on mismatch when supplied. */
  expectedCaid?: string;
  /**
   * Optional caller-pinned kid. `kid` is ALWAYS required in the envelope; when
   * this is supplied the envelope's kid must match it byte-for-byte, else the
   * envelope is refused (`kid_mismatch`).
   */
  expectedKid?: string;
}

export interface VerifyCoseResult {
  valid: boolean;
  checks: {
    deterministic_encoding: boolean;
    cose_structure: boolean;
    envelope_signature: boolean;
    payload_canonical: boolean;
    receipt_signature: boolean;
    caid_consistent: boolean;
  };
  reason?: string;
  receipt?: unknown;
  caid?: string;
  payloadSha256?: string;
}

/**
 * Verify a COSE_Sign1 transport envelope carrying an EP receipt, fail-closed.
 *
 * A `valid: true` result establishes, under the two PINNED keys the caller
 * supplied: the envelope bytes are deterministically encoded; the envelope
 * signer attested to exactly these payload bytes (transport attestation, no
 * approval semantics); the payload is the receipt's canonical JSON form; the
 * receipt verifies under its OWN signature and the pinned issuer key; and the
 * CAID in the protected headers recomputes from the carried action object.
 * It does NOT establish acceptance, authorization, execution, or currency.
 *
 * PROFILE STRICTNESS (closed profile, RFC 9052). The protected headers MUST be
 * exactly { alg (1), content type (3), kid (4), ep.caid } and nothing else;
 * an unknown protected label refuses (`unexpected_protected_header`). `kid` is
 * REQUIRED (`kid_missing`) and, when the caller pins one, must match byte-for-
 * byte (`kid_mismatch`). Any `crit` header refuses (`crit_unsupported`, RFC
 * 9052 Section 5.4: this profile marks no header critical). The unprotected
 * bucket MUST be empty (`unprotected_headers_present`); RFC 9052 Section 3
 * warns that labels duplicated across the protected and unprotected buckets are
 * an error, and the unprotected bucket is unsigned, so this profile authorizes
 * nothing from it.
 */
export function verifyReceiptCoseSign1(coseBytes: Uint8Array, opts: VerifyCoseOptions): VerifyCoseResult {
  const checks: VerifyCoseResult['checks'] = {
    deterministic_encoding: false,
    cose_structure: false,
    envelope_signature: false,
    payload_canonical: false,
    receipt_signature: false,
    caid_consistent: false,
  };
  const fail = (reason: string): VerifyCoseResult => ({ valid: false, checks, reason });

  if (!(coseBytes instanceof Uint8Array) || coseBytes.length < 2) return fail('malformed_cbor');
  if (coseBytes[0] !== COSE_SIGN1_TAG_BYTE) return fail('cose_structure_invalid');
  const decoded = decodeDeterministicCbor8949(coseBytes.subarray(1), { textKeysOnly: false });
  if (!decoded.ok) return fail(decoded.reason);
  checks.deterministic_encoding = true;

  const arr = decoded.value;
  if (!Array.isArray(arr) || arr.length !== 4) return fail('cose_structure_invalid');
  const [protectedBytes, unprotected, payload, signature] = arr;
  if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
      || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
    return fail('cose_structure_invalid');
  }
  // The unprotected bucket MUST be empty in this profile. RFC 9052 Section 3
  // warns that a label appearing in BOTH buckets is an error, and the
  // unprotected bucket is unauthenticated (outside the signature) -- so any
  // content there is either a conflicting/duplicate label or an unsigned
  // instruction. Refusing all unprotected content closes the whole class:
  // an attacker cannot slip a conflicting `alg` past the signed headers, and
  // there is nothing for a duplicate-across-buckets label to duplicate.
  if (unprotected.size !== 0) return fail('unprotected_headers_present');

  const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
  if (!headerResult.ok) return fail(headerResult.reason);
  if (!(headerResult.value instanceof Map)) return fail('cose_structure_invalid');
  const headers = headerResult.value;

  // `crit` (RFC 9052 Section 5.4): every label listed MUST be present and
  // understood by this profile. This is a CLOSED profile that marks no header
  // critical, so any `crit` at all names a label we do not understand.
  if (headers.has(COSE_HEADER_CRIT)) return fail('crit_unsupported');

  // Exact protected-header set: alg, content type, kid, ep.caid and nothing
  // else. An unknown protected label is a refusal, not an ignorable extra.
  for (const label of headers.keys()) {
    if (!COSE_PROFILE_PROTECTED_LABELS.has(label)) return fail('unexpected_protected_header');
  }

  if (headers.get(COSE_HEADER_ALG) !== COSE_ALG_EDDSA) return fail('unsupported_envelope_alg');
  if (headers.get(COSE_HEADER_CONTENT_TYPE) !== COSE_RECEIPT_CONTENT_TYPE) return fail('content_type_mismatch');

  // kid is REQUIRED (bstr, label 4). When the caller pins a kid it must match
  // byte-for-byte.
  const headerKid = headers.get(COSE_HEADER_KID);
  if (!(headerKid instanceof Uint8Array) || headerKid.length === 0) return fail('kid_missing');
  if (typeof opts?.expectedKid === 'string') {
    const pinned = UTF8.encode(opts.expectedKid);
    if (compareBytes(headerKid, pinned) !== 0) return fail('kid_mismatch');
  }

  const headerCaid = headers.get(COSE_HEADER_EP_CAID);
  if (typeof headerCaid !== 'string') return fail('caid_missing');
  checks.cose_structure = true;

  const envelopeKey = decodeSpkiBase64url(opts?.envelopePublicKeyBase64url);
  if (envelopeKey === null) return fail('invalid_public_key');
  const sigStruct = sigStructureBytes(protectedBytes, payload);
  if (!sigStruct.ok) return fail(sigStruct.reason);
  let envelopeSigOk = false;
  try {
    envelopeSigOk = crypto.verify(null, sigStruct.value, envelopeKey, signature);
  } catch {
    envelopeSigOk = false;
  }
  if (!envelopeSigOk) return fail('envelope_signature_invalid');
  checks.envelope_signature = true;

  // The payload must BE canonical JSON: parse, then require byte equality
  // with its own re-canonicalization. Refuses any non-canonical JSON form.
  let payloadText: string;
  try {
    payloadText = FATAL_UTF8.decode(payload);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let receipt: unknown;
  try {
    receipt = JSON.parse(payloadText);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let recanonical: string;
  try {
    recanonical = canonicalize(receipt);
  } catch {
    return fail('payload_not_canonical_json');
  }
  if (recanonical !== payloadText) return fail('payload_not_canonical_json');
  checks.payload_canonical = true;

  const receiptResult = verifyReceipt(receipt, opts?.receiptIssuerPublicKeyBase64url);
  if (!receiptResult.valid) return fail('receipt_invalid');
  checks.receipt_signature = true;

  const recomputed = receiptActionCaid((receipt as Obj).payload?.action);
  if (!recomputed.ok) return fail(recomputed.reason);
  if (recomputed.value.caid !== headerCaid) return fail('caid_mismatch');
  if (opts?.expectedCaid !== undefined && opts.expectedCaid !== headerCaid) {
    return fail('caid_mismatch');
  }
  checks.caid_consistent = true;

  return {
    valid: true,
    checks,
    receipt,
    caid: headerCaid,
    payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
  };
}

// ===========================================================================
// EP-COSE-ENCODING-v0.2 -- the hybrid (EdDSA + ML-DSA-65) transport pair
// ===========================================================================
/**
 * WHERE THE ML-DSA-65 ALGORITHM IDENTIFIER COMES FROM. It is not invented here
 * and it is not recalled from memory. COSE_ALG_ML_DSA_65 below is the value
 * this repository already carries and already verifies against:
 * `packages/verify/src/aeb-mcgraw-delegation-adapter.ts` exports
 * `MCGRAW_BUDGET_COSE_ALGORITHM = -49` under the comment "RFC 9964 COSE
 * Algorithms registry value for ML-DSA-65", and that adapter parses real
 * foreign COSE_Sign1 objects signed under it. The classical value -8 (EdDSA,
 * RFC 9053 Section 2.2) is the one this module already used. Both are
 * in-repository-traceable, so this profile adds a real PQ leg rather than a
 * registration-gated placeholder.
 *
 * WHY A PAIR OF COSE_Sign1 OBJECTS AND NOT ONE MULTI-SIGNATURE OBJECT. A
 * COSE_Sign1 (RFC 9052, tag 18) carries exactly one signature. The standard
 * multi-signer container is COSE_Sign, and this repository contains no
 * definition of it: no tag value, no COSE_Signature structure, no
 * "Signature" Sig_structure context string. Hand-rolling that container from
 * memory is exactly the mistake this profile refuses to make. So v0.2 is an
 * EP-DEFINED PAIRING of two individually conforming COSE_Sign1 objects over
 * the SAME payload bytes, one per registered algorithm. Stated plainly: the
 * pair is EP's composition, not a COSE object. A generic COSE implementation
 * handed one half sees one ordinary, valid COSE_Sign1 and learns nothing about
 * the other half; requiring both is a relying-party decision this verifier
 * makes for you, and it is the only place the hybrid property lives.
 *
 * The five moves from EP-REVOCATION-v2:
 *
 * 1. VERSION BUMP. New profile marker EP-COSE-ENCODING-v0.2. The v0.1
 *    verifier `verifyReceiptCoseSign1` is UNTOUCHED and refuses either half of
 *    a v0.2 pair with `unexpected_protected_header`, because its closed
 *    protected-label set does not contain `ep.required_algs` -- and it refuses
 *    there BEFORE it checks any signature. Asserted by test.
 * 2. SET SHAPE. The required set is the COSE algorithm VALUES [-8, -49], in
 *    registered order, so the commitment stays COSE-native integers rather
 *    than a second EP naming scheme on the wire.
 * 3. ANTI-STRIPPING BYTES. `ep.required_algs` is a PROTECTED (signed) header in
 *    BOTH halves, so it is inside each half's Sig_structure. Drop the ML-DSA
 *    half and narrow the surviving header's set and that half's signature stops
 *    verifying, because the protected bytes changed. Leave it intact and the
 *    missing half is a structural refusal. The verifier rebuilds the expected
 *    protected header from the REGISTERED set and from the CAID it recomputed
 *    itself, and requires byte equality with both presented headers.
 * 4. V1 COMPATIBILITY. `buildReceiptCoseSign1` and `verifyReceiptCoseSign1`
 *    are unchanged and stay SYNCHRONOUS. ML-DSA verification is asynchronous,
 *    so v0.2 is a separate async entry point.
 * 5. NAMED REFUSALS. Every path returns a named reason; nothing throws on
 *    untrusted input; an absent ML-DSA backend is `pq_backend_unavailable`
 *    and never a pass on the EdDSA half.
 *
 * TRUST SEMANTICS, UNCHANGED FROM v0.1 AND LOAD-BEARING. Both envelope
 * signatures are TRANSPORT/REGISTRATION attestations by the envelope key
 * holder. Neither is the approval signature and neither confers approval,
 * authorization, or trust semantics. Approval is still proven exclusively by
 * the receipt's own signature inside the payload -- which is Ed25519 only, so a
 * v0.2 pair does NOT make the carried receipt post-quantum protected. It makes
 * the TRANSPORT leg hybrid and nothing more. Opt-in; not deployed, default, or
 * certified anywhere.
 */

/**
 * RFC 9964 COSE Algorithms registry value for ML-DSA-65. Traced in-repository
 * to packages/verify/src/aeb-mcgraw-delegation-adapter.ts
 * (MCGRAW_BUDGET_COSE_ALGORITHM), which verifies foreign COSE_Sign1 objects
 * under it. Not recalled from memory, not invented here.
 */
export const COSE_ALG_ML_DSA_65 = -49;

export const COSE_HYBRID_ENCODING_PROFILE = 'EP-COSE-ENCODING-v0.2';

/** Private (non-IANA-registered) protected-header label carrying the required set. */
export const COSE_HEADER_EP_REQUIRED_ALGS = 'ep.required_algs';

/** The registered required COSE algorithm set, in canonical order. */
export const COSE_HYBRID_REQUIRED_ALGORITHMS = Object.freeze([
  COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65,
] as const);

const COSE_HYBRID_PROTECTED_LABELS: ReadonlySet<unknown> = new Set<unknown>([
  COSE_HEADER_ALG, COSE_HEADER_CONTENT_TYPE, COSE_HEADER_KID,
  COSE_HEADER_EP_CAID, COSE_HEADER_EP_REQUIRED_ALGS,
]);

function coseHybridSetMatchesRegistered(algorithms: unknown): algorithms is number[] {
  return Array.isArray(algorithms)
    && algorithms.length === COSE_HYBRID_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === COSE_HYBRID_REQUIRED_ALGORITHMS[i]);
}

/**
 * The protected header of one half of a v0.2 pair. `ep.required_algs` is a
 * member, so it lands inside the Sig_structure that half signs.
 */
export function coseHybridProtectedHeader(
  alg: number,
  kid: string,
  caid: string,
  requiredAlgorithms: readonly number[] = COSE_HYBRID_REQUIRED_ALGORITHMS,
): Map<unknown, unknown> {
  if (!coseHybridSetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('coseHybridProtectedHeader: algorithm set is not the registered EP-COSE-ENCODING-v0.2 set');
  }
  return new Map<unknown, unknown>([
    [COSE_HEADER_ALG, alg],
    [COSE_HEADER_CONTENT_TYPE, COSE_RECEIPT_CONTENT_TYPE],
    [COSE_HEADER_KID, UTF8.encode(kid)],
    [COSE_HEADER_EP_CAID, caid],
    [COSE_HEADER_EP_REQUIRED_ALGS, [...requiredAlgorithms]],
  ]);
}

export interface BuildCoseHybridOptions {
  /** Ed25519 private key of the ENVELOPE signer (transport leg only). */
  envelopePrivateKey: crypto.KeyObject;
  /** ML-DSA-65 raw 4032-byte secret key of the ENVELOPE signer, or base64url. */
  envelopePqSecretKey: Uint8Array | string;
  /** Key identifier placed in both protected headers (COSE label 4, bstr). */
  kid: string;
}

export interface BuiltCoseHybridPair {
  /** Tagged COSE_Sign1 with alg -8 (EdDSA). */
  classical: Uint8Array;
  /** Tagged COSE_Sign1 with alg -49 (ML-DSA-65). */
  pq: Uint8Array;
  /** The identical payload bytes both halves carry and sign over. */
  payload: Uint8Array;
  caid: string;
}

/**
 * Build an EP-COSE-ENCODING-v0.2 hybrid transport pair over one receipt.
 * Issuer-side misuse and an unavailable ML-DSA backend REFUSE (Result-typed,
 * like the rest of this module) rather than emitting a one-legged pair.
 */
export async function buildReceiptCoseHybrid(
  receipt: unknown,
  opts: BuildCoseHybridOptions,
  agility: AgilityOptions = {},
): Promise<CborResult<BuiltCoseHybridPair>> {
  if (!isPlainObject(receipt) || !isPlainObject((receipt as Obj).payload)) {
    return refuse('invalid_receipt_document');
  }
  let canonical: string;
  try {
    canonical = canonicalize(receipt);
  } catch {
    return refuse('outside_canonical_profile');
  }
  const caidResult = receiptActionCaid((receipt as Obj).payload.action);
  if (!caidResult.ok) return caidResult;
  if (typeof opts?.kid !== 'string' || opts.kid.length === 0) return refuse('invalid_kid');
  const key = opts?.envelopePrivateKey;
  if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
    return refuse('invalid_envelope_key');
  }

  const payload = UTF8.encode(canonical);
  const halves: Uint8Array[] = [];
  for (const alg of COSE_HYBRID_REQUIRED_ALGORITHMS) {
    const protectedEncoded = encodeDeterministicCbor8949(
      coseHybridProtectedHeader(alg, opts.kid, caidResult.value.caid),
    );
    if (!protectedEncoded.ok) return protectedEncoded;
    const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
    if (!sigStruct.ok) return sigStruct;
    let signature: Uint8Array;
    try {
      const agile = await signAgile(
        new Uint8Array(sigStruct.value),
        alg === COSE_ALG_EDDSA
          ? { alg: 'Ed25519', private_key: key }
          : { alg: 'ML-DSA-65', private_key: opts.envelopePqSecretKey },
        agility,
      );
      signature = new Uint8Array(Buffer.from(agile.sig, 'base64url'));
    } catch {
      return refuse(alg === COSE_ALG_EDDSA ? 'invalid_envelope_key' : 'pq_backend_unavailable');
    }
    const body = encodeDeterministicCbor8949([
      protectedEncoded.value, new Map(), payload, signature,
    ]);
    if (!body.ok) return body;
    halves.push(concatBytes([Uint8Array.of(COSE_SIGN1_TAG_BYTE), body.value]));
  }

  return {
    ok: true,
    value: { classical: halves[0], pq: halves[1], payload, caid: caidResult.value.caid },
  };
}

export interface VerifyCoseHybridOptions {
  /** SPKI-DER base64url Ed25519 public key pinned for the ENVELOPE signer. */
  envelopePublicKeyBase64url: string;
  /** base64url raw 1952-byte ML-DSA-65 public key pinned for the ENVELOPE signer. */
  envelopePqPublicKeyBase64url: string;
  /** SPKI-DER base64url Ed25519 public key pinned for the RECEIPT issuer. */
  receiptIssuerPublicKeyBase64url: string;
  /** REQUIRED in v0.2: both halves must carry exactly this kid. */
  expectedKid: string;
  expectedCaid?: string;
  agility?: AgilityOptions;
}

export interface VerifyCoseHybridResult {
  valid: boolean;
  checks: {
    pair_present: boolean;
    deterministic_encoding: boolean;
    cose_structure: boolean;
    algorithm_set: boolean;
    payload_identical: boolean;
    envelope_signatures: boolean;
    payload_canonical: boolean;
    receipt_signature: boolean;
    caid_consistent: boolean;
  };
  reason?: string;
  receipt?: unknown;
  caid?: string;
  payloadSha256?: string;
}

interface ParsedHybridHalf {
  protectedBytes: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
  alg: number;
  caid: string;
}

function parseHybridHalf(
  coseBytes: unknown,
  expectedAlg: number,
  expectedKid: string,
): CborResult<ParsedHybridHalf> {
  if (!(coseBytes instanceof Uint8Array) || coseBytes.length < 2) return refuse('malformed_cbor');
  if (coseBytes[0] !== COSE_SIGN1_TAG_BYTE) return refuse('cose_structure_invalid');
  const decoded = decodeDeterministicCbor8949(coseBytes.subarray(1), { textKeysOnly: false });
  if (!decoded.ok) return decoded;
  const arr = decoded.value;
  if (!Array.isArray(arr) || arr.length !== 4) return refuse('cose_structure_invalid');
  const [protectedBytes, unprotected, payload, signature] = arr;
  if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
      || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
    return refuse('cose_structure_invalid');
  }
  if (unprotected.size !== 0) return refuse('unprotected_headers_present');

  const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
  if (!headerResult.ok) return headerResult;
  if (!(headerResult.value instanceof Map)) return refuse('cose_structure_invalid');
  const headers = headerResult.value;
  if (headers.has(COSE_HEADER_CRIT)) return refuse('crit_unsupported');
  for (const label of headers.keys()) {
    if (!COSE_HYBRID_PROTECTED_LABELS.has(label)) return refuse('unexpected_protected_header');
  }
  if (headers.get(COSE_HEADER_ALG) !== expectedAlg) return refuse('unsupported_envelope_alg');
  if (headers.get(COSE_HEADER_CONTENT_TYPE) !== COSE_RECEIPT_CONTENT_TYPE) {
    return refuse('content_type_mismatch');
  }
  const headerKid = headers.get(COSE_HEADER_KID);
  if (!(headerKid instanceof Uint8Array) || headerKid.length === 0) return refuse('kid_missing');
  if (compareBytes(headerKid, UTF8.encode(expectedKid)) !== 0) return refuse('kid_mismatch');
  const headerCaid = headers.get(COSE_HEADER_EP_CAID);
  if (typeof headerCaid !== 'string') return refuse('caid_missing');
  if (!coseHybridSetMatchesRegistered(headers.get(COSE_HEADER_EP_REQUIRED_ALGS))) {
    return refuse('algorithm_set_mismatch');
  }
  return {
    ok: true,
    value: { protectedBytes, payload, signature, alg: expectedAlg, caid: headerCaid },
  };
}

/**
 * Verify an EP-COSE-ENCODING-v0.2 hybrid transport pair, fail-closed.
 *
 * A `valid: true` result establishes, under the THREE pinned keys supplied:
 * both halves are deterministically encoded conforming COSE_Sign1 objects over
 * BYTE-IDENTICAL payloads; each half's protected header equals the header
 * rebuilt from the REGISTERED algorithm set, the pinned kid, and the CAID the
 * verifier recomputed itself; the envelope signer attested to those payload
 * bytes under BOTH EdDSA and ML-DSA-65; the payload is the receipt's canonical
 * JSON form; and the receipt verifies under its OWN Ed25519 signature and the
 * pinned issuer key.
 *
 * It does NOT establish acceptance, authorization, execution, currency, or any
 * post-quantum property of the CARRIED RECEIPT: the receipt's own approval
 * signature remains Ed25519.
 */
export async function verifyReceiptCoseHybrid(
  pair: { classical?: unknown; pq?: unknown } | null | undefined,
  opts: VerifyCoseHybridOptions,
): Promise<VerifyCoseHybridResult> {
  const checks: VerifyCoseHybridResult['checks'] = {
    pair_present: false,
    deterministic_encoding: false,
    cose_structure: false,
    algorithm_set: false,
    payload_identical: false,
    envelope_signatures: false,
    payload_canonical: false,
    receipt_signature: false,
    caid_consistent: false,
  };
  const fail = (reason: string): VerifyCoseHybridResult => ({ valid: false, checks, reason });

  if (!pair || typeof pair !== 'object'
      || !(pair.classical instanceof Uint8Array) || !(pair.pq instanceof Uint8Array)) {
    return fail('hybrid_pair_incomplete');
  }
  if (typeof opts?.expectedKid !== 'string' || opts.expectedKid.length === 0) {
    return fail('invalid_kid');
  }
  checks.pair_present = true;

  const classical = parseHybridHalf(pair.classical, COSE_ALG_EDDSA, opts.expectedKid);
  if (!classical.ok) return fail(classical.reason);
  const pq = parseHybridHalf(pair.pq, COSE_ALG_ML_DSA_65, opts.expectedKid);
  if (!pq.ok) return fail(pq.reason);
  checks.deterministic_encoding = true;
  checks.cose_structure = true;
  checks.algorithm_set = true;

  if (compareBytes(classical.value.payload, pq.value.payload) !== 0) {
    return fail('hybrid_payload_mismatch');
  }
  if (classical.value.caid !== pq.value.caid) return fail('caid_mismatch');
  checks.payload_identical = true;
  const payload = classical.value.payload;

  // The payload must BE canonical JSON, byte for byte, before anything derived
  // from it (the CAID the protected headers are rebuilt against) is trusted.
  let payloadText: string;
  try {
    payloadText = FATAL_UTF8.decode(payload);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let receipt: unknown;
  try {
    receipt = JSON.parse(payloadText);
  } catch {
    return fail('payload_not_canonical_json');
  }
  let recanonical: string;
  try {
    recanonical = canonicalize(receipt);
  } catch {
    return fail('payload_not_canonical_json');
  }
  if (recanonical !== payloadText) return fail('payload_not_canonical_json');
  checks.payload_canonical = true;

  const recomputed = receiptActionCaid((receipt as Obj).payload?.action);
  if (!recomputed.ok) return fail(recomputed.reason);
  if (recomputed.value.caid !== classical.value.caid) return fail('caid_mismatch');
  if (opts.expectedCaid !== undefined && opts.expectedCaid !== classical.value.caid) {
    return fail('caid_mismatch');
  }

  // Rebuild both protected headers from the REGISTERED set, the pinned kid, and
  // the CAID this verifier recomputed. The presented halves never choose what
  // they are checked against.
  for (const [half, alg] of [
    [classical.value, COSE_ALG_EDDSA] as const,
    [pq.value, COSE_ALG_ML_DSA_65] as const,
  ]) {
    let expected;
    try {
      expected = encodeDeterministicCbor8949(
        coseHybridProtectedHeader(alg, opts.expectedKid, recomputed.value.caid),
      );
    } catch {
      return fail('algorithm_set_mismatch');
    }
    if (!expected.ok) return fail(expected.reason);
    if (compareBytes(expected.value, half.protectedBytes) !== 0) {
      return fail('protected_header_mismatch');
    }
  }
  checks.caid_consistent = true;

  // Both envelope legs over their OWN Sig_structure, under the PINNED keys.
  // Policy hybrid_all with the full registry: a missing leg can never pass.
  const classicalSig = sigStructureBytes(classical.value.protectedBytes, payload);
  if (!classicalSig.ok) return fail(classicalSig.reason);
  const pqSig = sigStructureBytes(pq.value.protectedBytes, payload);
  if (!pqSig.ok) return fail(pqSig.reason);

  const legs = [
    await verifyAgileSignature(
      classicalSig.value,
      { alg: 'Ed25519', sig: Buffer.from(classical.value.signature).toString('base64url') },
      { alg: 'Ed25519', public_key: opts.envelopePublicKeyBase64url },
      opts.agility ?? {},
    ),
    await verifyAgileSignature(
      pqSig.value,
      { alg: 'ML-DSA-65', sig: Buffer.from(pq.value.signature).toString('base64url') },
      { alg: 'ML-DSA-65', public_key: opts.envelopePqPublicKeyBase64url },
      opts.agility ?? {},
    ),
  ];
  const failedLeg = legs.find((leg) => leg.verified !== true);
  if (failedLeg) return fail(`envelope_signature_invalid:${failedLeg.alg}:${failedLeg.reason}`);
  checks.envelope_signatures = true;

  const receiptResult = verifyReceipt(receipt, opts.receiptIssuerPublicKeyBase64url);
  if (!receiptResult.valid) return fail('receipt_invalid');
  checks.receipt_signature = true;

  return {
    valid: true,
    checks,
    receipt,
    caid: classical.value.caid,
    payloadSha256: crypto.createHash('sha256').update(payload).digest('hex'),
  };
}
