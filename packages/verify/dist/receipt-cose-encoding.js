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
 *   `encodeDeterministicCbor` sorts map keys length-first (RFC 7049 Section
 *   3.9); the orders coincide for its own small positive integer labels but
 *   diverge in general (e.g. keys -1 and 100), so this module ships its own
 *   RFC 8949 codec under distinct names rather than reusing it.
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
export const COSE_ENCODING_PROFILE = 'EP-COSE-ENCODING-v0.1';
/** The map-key ordering this profile ships (see module doc + README). */
export const CBOR_DETERMINISTIC_ORDER = 'rfc8949-4.2.1-bytewise-encoded-key';
export const COSE_RECEIPT_CONTENT_TYPE = 'application/emilia-receipt+json';
/** COSE alg value for EdDSA (RFC 9053 Section 2.2). */
export const COSE_ALG_EDDSA = -8;
/** Private (non-IANA-registered) protected-header label carrying the CAID. */
export const COSE_HEADER_EP_CAID = 'ep.caid';
const COSE_SIGN1_TAG_BYTE = 0xd2; // tag 18, shortest form
const MAX_DEPTH = 64;
const MAX_ITEMS = 1 << 20;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
const UTF8 = new TextEncoder();
function refuse(reason) {
    return { ok: false, reason };
}
function hasUnpairedSurrogate(value) {
    for (let i = 0; i < value.length; i += 1) {
        const code = value.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(i + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return true;
            i += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            return true;
        }
    }
    return false;
}
function isPlainObject(v) {
    if (typeof v !== 'object' || v === null || Array.isArray(v))
        return false;
    const proto = Object.getPrototypeOf(v);
    return proto === Object.prototype || proto === null;
}
function compareBytes(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
        if (a[i] !== b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return a.length === b.length ? 0 : (a.length < b.length ? -1 : 1);
}
function concatBytes(parts) {
    let total = 0;
    for (const p of parts)
        total += p.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}
// ---------------------------------------------------------------------------
// Deterministic CBOR encoder (RFC 8949 Section 4.2.1 over the EP domain)
//
// Domain: null, boolean, safe integers, text strings (well-formed),
// Uint8Array (byte strings), arrays, plain objects (text-keyed maps), and
// Map instances (for COSE header maps with integer or text labels).
// ---------------------------------------------------------------------------
function encodeHead(major, arg) {
    if (arg < 24)
        return Uint8Array.of((major << 5) | arg);
    if (arg <= 0xff)
        return Uint8Array.of((major << 5) | 24, arg);
    if (arg <= 0xffff)
        return Uint8Array.of((major << 5) | 25, arg >> 8, arg & 0xff);
    if (arg <= 0xffffffff) {
        return Uint8Array.of((major << 5) | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
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
function encodeValue(value, depth, out) {
    if (depth > MAX_DEPTH)
        return refuse('unsupported_item');
    if (value === null) {
        out.push(Uint8Array.of(0xf6));
        return null;
    }
    if (value === true) {
        out.push(Uint8Array.of(0xf5));
        return null;
    }
    if (value === false) {
        out.push(Uint8Array.of(0xf4));
        return null;
    }
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value))
            return refuse('unsupported_item');
        // -0 canonicalizes to 0 in the strict JSON domain (JCS behavior).
        if (Object.is(value, -0)) {
            out.push(Uint8Array.of(0x00));
            return null;
        }
        if (value >= 0) {
            out.push(encodeHead(0, value));
            return null;
        }
        out.push(encodeHead(1, -1 - value));
        return null;
    }
    if (typeof value === 'string') {
        if (hasUnpairedSurrogate(value))
            return refuse('unsupported_item');
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
            if (err)
                return err;
        }
        return null;
    }
    if (value instanceof Map || isPlainObject(value)) {
        const entries = value instanceof Map
            ? [...value.entries()]
            : Object.keys(value).map((k) => [k, value[k]]);
        const encoded = [];
        for (const [k, v] of entries) {
            const keyParts = [];
            const keyErr = encodeValue(k, depth + 1, keyParts);
            if (keyErr)
                return keyErr;
            const valParts = [];
            const valErr = encodeValue(v, depth + 1, valParts);
            if (valErr)
                return valErr;
            encoded.push({ key: concatBytes(keyParts), val: concatBytes(valParts) });
        }
        encoded.sort((a, b) => compareBytes(a.key, b.key));
        for (let i = 1; i < encoded.length; i += 1) {
            if (compareBytes(encoded[i - 1].key, encoded[i].key) === 0) {
                return refuse('duplicate_map_key');
            }
        }
        out.push(encodeHead(5, encoded.length));
        for (const e of encoded)
            out.push(e.key, e.val);
        return null;
    }
    return refuse('unsupported_item');
}
/**
 * Deterministically encode a value from the profile domain.
 * Never throws; refuses out-of-domain values with `unsupported_item`.
 */
export function encodeDeterministicCbor8949(value) {
    const out = [];
    const err = encodeValue(value, 0, out);
    if (err)
        return err;
    return { ok: true, value: concatBytes(out) };
}
function isRefused(v) {
    return typeof v === 'object' && v !== null && 'refused' in v;
}
function readHead(s) {
    if (s.offset >= s.bytes.length)
        return { refused: 'malformed_cbor' };
    const initial = s.bytes[s.offset];
    const major = initial >> 5;
    const ai = initial & 0x1f;
    s.offset += 1;
    if (ai < 24)
        return { major, arg: ai };
    if (ai === 31) {
        // Indefinite lengths are forbidden by RFC 8949 Section 4.2.1.
        return { refused: 'non_deterministic_encoding' };
    }
    if (ai > 27)
        return { refused: 'malformed_cbor' };
    const lengths = { 24: 1, 25: 2, 26: 4, 27: 8 };
    const n = lengths[ai];
    if (s.offset + n > s.bytes.length)
        return { refused: 'malformed_cbor' };
    let arg;
    if (n === 8) {
        let big = 0n;
        for (let i = 0; i < 8; i += 1)
            big = (big << 8n) | BigInt(s.bytes[s.offset + i]);
        if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
            s.offset += 8;
            return { refused: 'unsupported_item' };
        }
        arg = Number(big);
    }
    else {
        arg = 0;
        for (let i = 0; i < n; i += 1)
            arg = arg * 256 + s.bytes[s.offset + i];
    }
    s.offset += n;
    // Shortest-form check (RFC 8949 Section 4.2.1): the argument MUST use the
    // smallest encoding that fits.
    const shortest = arg < 24 ? 0 : arg <= 0xff ? 1 : arg <= 0xffff ? 2 : arg <= 0xffffffff ? 4 : 8;
    if (n !== shortest)
        return { refused: 'non_deterministic_encoding' };
    return { major, arg };
}
function decodeItem(s, depth) {
    s.items += 1;
    if (s.items > MAX_ITEMS)
        return { refused: 'unsupported_item' };
    if (depth > MAX_DEPTH)
        return { refused: 'unsupported_item' };
    const start = s.offset;
    if (s.offset < s.bytes.length) {
        const initial = s.bytes[s.offset];
        const major = initial >> 5;
        const ai = initial & 0x1f;
        if (major === 7) {
            s.offset += 1;
            if (ai === 20)
                return false;
            if (ai === 21)
                return true;
            if (ai === 22)
                return null;
            // undefined (23), extended simple values (24), floats (25-27), break
            // (31), and reserved values are all outside the profile domain.
            if (ai >= 28 && ai <= 30)
                return { refused: 'malformed_cbor' };
            return { refused: 'unsupported_item' };
        }
        if (major === 6) {
            // No tags inside the profile domain; the COSE_Sign1 tag is handled
            // explicitly by the envelope parser before generic decoding.
            return { refused: 'unsupported_item' };
        }
    }
    const head = readHead(s);
    if (isRefused(head))
        return head;
    const { major, arg } = head;
    if (major === 0)
        return arg;
    if (major === 1)
        return -1 - arg;
    if (major === 2) {
        if (s.offset + arg > s.bytes.length)
            return { refused: 'malformed_cbor' };
        const out = s.bytes.slice(s.offset, s.offset + arg);
        s.offset += arg;
        return out;
    }
    if (major === 3) {
        if (s.offset + arg > s.bytes.length)
            return { refused: 'malformed_cbor' };
        let text;
        try {
            text = FATAL_UTF8.decode(s.bytes.subarray(s.offset, s.offset + arg));
        }
        catch {
            return { refused: 'malformed_cbor' };
        }
        s.offset += arg;
        return text;
    }
    if (major === 4) {
        const out = [];
        for (let i = 0; i < arg; i += 1) {
            const item = decodeItem(s, depth + 1);
            if (isRefused(item))
                return item;
            out.push(item);
        }
        return out;
    }
    if (major === 5) {
        const asObject = s.textKeysOnly;
        const object = {};
        const map = new Map();
        let prevKeyBytes = null;
        for (let i = 0; i < arg; i += 1) {
            const keyStart = s.offset;
            const key = decodeItem(s, depth + 1);
            if (isRefused(key))
                return key;
            const keyBytes = s.bytes.slice(keyStart, s.offset);
            if (prevKeyBytes !== null) {
                const cmp = compareBytes(prevKeyBytes, keyBytes);
                if (cmp === 0)
                    return { refused: 'malformed_cbor' }; // duplicate key
                if (cmp > 0)
                    return { refused: 'non_deterministic_encoding' };
            }
            prevKeyBytes = keyBytes;
            const val = decodeItem(s, depth + 1);
            if (isRefused(val))
                return val;
            if (asObject) {
                if (typeof key !== 'string')
                    return { refused: 'unsupported_item' };
                object[key] = val;
            }
            else {
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
export function decodeDeterministicCbor8949(bytes, opts = {}) {
    if (!(bytes instanceof Uint8Array))
        return refuse('malformed_cbor');
    const s = {
        bytes,
        offset: 0,
        items: 0,
        textKeysOnly: opts.textKeysOnly !== false,
    };
    const item = decodeItem(s, 0);
    if (isRefused(item))
        return refuse(item.refused);
    if (s.offset !== bytes.length)
        return refuse('trailing_bytes');
    return { ok: true, value: item };
}
// ---------------------------------------------------------------------------
// Receipt JSON <-> CBOR value mapping
// ---------------------------------------------------------------------------
/**
 * Map an EP receipt document (or any strict-JSON value) to deterministic
 * CBOR map bytes with text keys. Total over the EP canonicalization domain.
 */
export function receiptToCborBytes(receipt) {
    // The strict canonical gate first: values outside the EP profile (floats,
    // non-plain objects, cycles, unpaired surrogates) refuse before encoding.
    try {
        canonicalize(receipt);
    }
    catch {
        return refuse('outside_canonical_profile');
    }
    return encodeDeterministicCbor8949(receipt);
}
/**
 * Recover the receipt value from deterministic CBOR bytes. Refuses
 * non-deterministic encodings rather than accepting semantically equal bytes.
 */
export function receiptFromCborBytes(bytes) {
    const decoded = decodeDeterministicCbor8949(bytes, { textKeysOnly: true });
    if (!decoded.ok)
        return decoded;
    try {
        canonicalize(decoded.value);
    }
    catch {
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
function isValidActionType(t) {
    if (typeof t !== 'string')
        return false;
    const segments = t.split('.');
    if (segments.length < 2)
        return false;
    if (!TYPE_VERSION_RE.test(segments[segments.length - 1]))
        return false;
    for (let i = 0; i < segments.length - 1; i += 1) {
        if (!TYPE_SEGMENT_RE.test(segments[i]))
            return false;
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
export function receiptActionCaid(action) {
    if (!isPlainObject(action))
        return refuse('invalid_action_object');
    if (!isValidActionType(action.action_type))
        return refuse('invalid_action_type');
    let canonical;
    try {
        canonical = canonicalize(action);
    }
    catch {
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
function decodeSpkiBase64url(value) {
    if (typeof value !== 'string' || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return null;
    try {
        const der = Buffer.from(value, 'base64url');
        if (der.toString('base64url') !== value)
            return null;
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (key.asymmetricKeyType !== 'ed25519')
            return null;
        return key;
    }
    catch {
        return null;
    }
}
function sigStructureBytes(protectedBytes, payload) {
    // COSE Sig_structure for COSE_Sign1 (RFC 9052 Section 4.4):
    //   ["Signature1", body_protected, external_aad, payload]
    return encodeDeterministicCbor8949(['Signature1', protectedBytes, new Uint8Array(0), payload]);
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
export function buildReceiptCoseSign1(receipt, opts) {
    if (!isPlainObject(receipt) || !isPlainObject(receipt.payload)) {
        return refuse('invalid_receipt_document');
    }
    let canonical;
    try {
        canonical = canonicalize(receipt);
    }
    catch {
        return refuse('outside_canonical_profile');
    }
    const caidResult = receiptActionCaid(receipt.payload.action);
    if (!caidResult.ok)
        return caidResult;
    if (typeof opts?.kid !== 'string' || opts.kid.length === 0)
        return refuse('invalid_kid');
    const payload = UTF8.encode(canonical);
    const protectedMap = new Map([
        [1, COSE_ALG_EDDSA],
        [3, COSE_RECEIPT_CONTENT_TYPE],
        [4, UTF8.encode(opts.kid)],
        [COSE_HEADER_EP_CAID, caidResult.value.caid],
    ]);
    const protectedEncoded = encodeDeterministicCbor8949(protectedMap);
    if (!protectedEncoded.ok)
        return protectedEncoded;
    const sigStruct = sigStructureBytes(protectedEncoded.value, payload);
    if (!sigStruct.ok)
        return sigStruct;
    let signature;
    try {
        const key = opts.envelopePrivateKey;
        if (!(key instanceof crypto.KeyObject) || key.asymmetricKeyType !== 'ed25519') {
            return refuse('invalid_envelope_key');
        }
        signature = new Uint8Array(crypto.sign(null, sigStruct.value, key));
    }
    catch {
        return refuse('invalid_envelope_key');
    }
    const body = encodeDeterministicCbor8949([
        protectedEncoded.value,
        new Map(), // unprotected headers: empty
        payload,
        signature,
    ]);
    if (!body.ok)
        return body;
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
 */
export function verifyReceiptCoseSign1(coseBytes, opts) {
    const checks = {
        deterministic_encoding: false,
        cose_structure: false,
        envelope_signature: false,
        payload_canonical: false,
        receipt_signature: false,
        caid_consistent: false,
    };
    const fail = (reason) => ({ valid: false, checks, reason });
    if (!(coseBytes instanceof Uint8Array) || coseBytes.length < 2)
        return fail('malformed_cbor');
    if (coseBytes[0] !== COSE_SIGN1_TAG_BYTE)
        return fail('cose_structure_invalid');
    const decoded = decodeDeterministicCbor8949(coseBytes.subarray(1), { textKeysOnly: false });
    if (!decoded.ok)
        return fail(decoded.reason);
    checks.deterministic_encoding = true;
    const arr = decoded.value;
    if (!Array.isArray(arr) || arr.length !== 4)
        return fail('cose_structure_invalid');
    const [protectedBytes, unprotected, payload, signature] = arr;
    if (!(protectedBytes instanceof Uint8Array) || !(payload instanceof Uint8Array)
        || !(signature instanceof Uint8Array) || !(unprotected instanceof Map)) {
        return fail('cose_structure_invalid');
    }
    const headerResult = decodeDeterministicCbor8949(protectedBytes, { textKeysOnly: false });
    if (!headerResult.ok)
        return fail(headerResult.reason);
    if (!(headerResult.value instanceof Map))
        return fail('cose_structure_invalid');
    const headers = headerResult.value;
    if (headers.get(1) !== COSE_ALG_EDDSA)
        return fail('unsupported_envelope_alg');
    if (headers.get(3) !== COSE_RECEIPT_CONTENT_TYPE)
        return fail('content_type_mismatch');
    const headerCaid = headers.get(COSE_HEADER_EP_CAID);
    if (typeof headerCaid !== 'string')
        return fail('caid_missing');
    checks.cose_structure = true;
    const envelopeKey = decodeSpkiBase64url(opts?.envelopePublicKeyBase64url);
    if (envelopeKey === null)
        return fail('invalid_public_key');
    const sigStruct = sigStructureBytes(protectedBytes, payload);
    if (!sigStruct.ok)
        return fail(sigStruct.reason);
    let envelopeSigOk = false;
    try {
        envelopeSigOk = crypto.verify(null, sigStruct.value, envelopeKey, signature);
    }
    catch {
        envelopeSigOk = false;
    }
    if (!envelopeSigOk)
        return fail('envelope_signature_invalid');
    checks.envelope_signature = true;
    // The payload must BE canonical JSON: parse, then require byte equality
    // with its own re-canonicalization. Refuses any non-canonical JSON form.
    let payloadText;
    try {
        payloadText = FATAL_UTF8.decode(payload);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    let receipt;
    try {
        receipt = JSON.parse(payloadText);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    let recanonical;
    try {
        recanonical = canonicalize(receipt);
    }
    catch {
        return fail('payload_not_canonical_json');
    }
    if (recanonical !== payloadText)
        return fail('payload_not_canonical_json');
    checks.payload_canonical = true;
    const receiptResult = verifyReceipt(receipt, opts?.receiptIssuerPublicKeyBase64url);
    if (!receiptResult.valid)
        return fail('receipt_invalid');
    checks.receipt_signature = true;
    const recomputed = receiptActionCaid(receipt.payload?.action);
    if (!recomputed.ok)
        return fail(recomputed.reason);
    if (recomputed.value.caid !== headerCaid)
        return fail('caid_mismatch');
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
//# sourceMappingURL=receipt-cose-encoding.js.map