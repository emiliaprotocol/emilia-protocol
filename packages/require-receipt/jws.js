/**
 * @emilia-protocol/require-receipt/jws — EP-RECEIPT-JWS-PROFILE-v1
 * @license Apache-2.0
 *
 * A JWS (RFC 7515) serialization profile for EMILIA authorization receipts, so
 * that ANY standard JOSE verifier (e.g. the `jose` npm library) can consume an
 * EP receipt with no EP-specific code.
 *
 * This is a PARALLEL / ALTERNATE envelope. It does NOT replace the native
 * EP-RECEIPT-v1 signature (Ed25519 over JCS(payload), per @emilia-protocol/verify).
 * Instead it re-signs the SAME canonical receipt payload as a compact JWS:
 *
 *   protected header = { "alg": "EdDSA", "typ": "application/ep-receipt+jws", "kid"? }
 *   JWS payload      = the RFC 8785 (JCS) canonical bytes of the receipt payload
 *   signature        = Ed25519 (RFC 8037 / RFC 8032) over ASCII(b64u(header) "." b64u(payload))
 *
 * Note the JWS signature value is NOT equal to the native EP signature value:
 * JWS signs `b64u(header).b64u(payload)` (RFC 7515 §5.1), whereas the native EP
 * signature signs the canonical payload bytes directly. They are two independent
 * envelopes over the same canonical material; both bind the exact same receipt.
 *
 * Algorithm: EdDSA with Ed25519 keys (RFC 8037 §3.1). Issuer keys are the same
 * base64url SPKI-DER Ed25519 public keys used everywhere else in EP.
 *
 * Runtime path uses ONLY Node's built-in crypto (no heavyweight deps). The
 * `jose` library is a dev-only cross-verification dependency for the test suite.
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';

export const JWS_PROFILE_VERSION = 'EP-RECEIPT-JWS-PROFILE-v1';
export const JWS_ALG = 'EdDSA';
export const JWS_TYP = 'application/ep-receipt+jws';
const RECEIPT_VERSION = 'EP-RECEIPT-v1';
const MAX_COMPACT_JWS_CHARS = 12 * 1024 * 1024;
const MAX_PROTECTED_HEADER_BYTES = 4096;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

// Single canonicalization source of truth — byte-identical to
// @emilia-protocol/verify and @emilia-protocol/require-receipt: recursive,
// depth-first key sort (RFC 8785 JCS over the EP I-JSON value subset).
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

function decodeCanonicalB64u(value, maxBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('non-canonical base64url');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== value) {
    throw new Error('non-canonical base64url');
  }
  return bytes;
}

function decodeStrictJson(bytes, label) {
  let text;
  try {
    text = UTF8_DECODER.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
  const strict = strictJsonGate(text);
  if (!strict.ok) throw new Error(`${label} is not strict JSON: ${strict.reason}`);
  return { text, value: JSON.parse(text) };
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Deterministic key id for an issuer Ed25519 public key: the first 16 bytes of
 * SHA-256 over the base64url SPKI-DER key, hex-encoded. EP receipts do not carry
 * a native `kid`; this gives JOSE consumers a stable, reproducible identifier
 * derived from the key itself (a JWK thumbprint-style fingerprint). Purely
 * advisory — verification trusts the supplied key, never the `kid`.
 *
 * @param {string} publicKeyBase64url base64url SPKI-DER Ed25519 public key
 * @returns {string} hex key id
 */
export function deriveKid(publicKeyBase64url) {
  return crypto
    .createHash('sha256')
    .update(String(publicKeyBase64url), 'utf8')
    .digest('hex')
    .slice(0, 32);
}

function ed25519PrivateFromKey(privateKey) {
  if (privateKey instanceof crypto.KeyObject) return privateKey;
  if (Buffer.isBuffer(privateKey)) {
    return crypto.createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
  }
  if (typeof privateKey === 'string') {
    // PEM if it looks like one, else base64url PKCS8 DER.
    if (privateKey.includes('-----BEGIN')) {
      return crypto.createPrivateKey(privateKey);
    }
    return crypto.createPrivateKey({ key: Buffer.from(privateKey, 'base64url'), format: 'der', type: 'pkcs8' });
  }
  throw new TypeError('privateKey must be a KeyObject, PEM string, base64url PKCS8 DER, or DER Buffer');
}

function ed25519PublicFromKey(publicKey) {
  if (publicKey instanceof crypto.KeyObject) return publicKey;
  if (Buffer.isBuffer(publicKey)) {
    return crypto.createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
  }
  if (typeof publicKey === 'string') {
    if (publicKey.includes('-----BEGIN')) {
      return crypto.createPublicKey(publicKey);
    }
    return crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64url'), format: 'der', type: 'spki' });
  }
  throw new TypeError('publicKey must be a KeyObject, PEM string, or base64url SPKI DER');
}

/**
 * Serialize an EP-RECEIPT-v1 document as a COMPACT JWS (RFC 7515 §3.1, §7.1).
 *
 * The JWS payload is the canonical (JCS) bytes of `doc.payload` — the exact same
 * bytes the native EP signature covers — so a JWS verifier and an EP verifier
 * authenticate identical receipt material.
 *
 * @param {object} doc EP-RECEIPT-v1 document ({ '@version', payload, signature?, public_key? })
 * @param {crypto.KeyObject|string|Buffer} privateKey issuer Ed25519 private key
 *   (KeyObject, PEM, base64url PKCS8 DER, or DER Buffer)
 * @param {object} [opts]
 * @param {string} [opts.kid] explicit JWS `kid`; otherwise derived from
 *   opts.publicKey or doc.public_key when available (else omitted)
 * @param {string} [opts.publicKey] issuer base64url SPKI key, used only to derive `kid`
 * @returns {string} compact JWS: b64u(protected).b64u(payload).b64u(signature)
 */
export function serializeReceiptJws(doc, privateKey, opts = {}) {
  if (!isPlainObject(doc)) throw new TypeError('doc must be an EP-RECEIPT-v1 object');
  if (doc['@version'] !== RECEIPT_VERSION) {
    throw new Error(`Unsupported receipt version: ${doc['@version']} (expected ${RECEIPT_VERSION})`);
  }
  if (!isPlainObject(doc.payload)) throw new Error('doc.payload must be an object');

  const priv = ed25519PrivateFromKey(privateKey);
  if (priv.asymmetricKeyType !== 'ed25519') {
    throw new Error(`EP-RECEIPT-JWS-PROFILE-v1 requires an Ed25519 key (got ${priv.asymmetricKeyType})`);
  }

  const kidSource = opts.kid !== undefined ? null : (opts.publicKey || doc.public_key);
  const kid = opts.kid !== undefined ? opts.kid : (kidSource ? deriveKid(kidSource) : undefined);

  const header = { alg: JWS_ALG, typ: JWS_TYP, ...(kid ? { kid } : {}) };
  const protectedB64 = b64u(Buffer.from(JSON.stringify(header), 'utf8'));
  const payloadB64 = b64u(Buffer.from(canonicalize(doc.payload), 'utf8'));
  const signingInput = `${protectedB64}.${payloadB64}`;
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), priv);
  return `${signingInput}.${b64u(signature)}`;
}

/**
 * Verify an EP-RECEIPT-JWS-PROFILE-v1 compact JWS and reconstruct the receipt.
 *
 * Steps (RFC 7515 §5.2 + the EP profile):
 *   1. Parse the three compact segments and the protected header.
 *   2. Enforce the profile header: alg === "EdDSA", typ === "application/ep-receipt+jws".
 *   3. Verify the Ed25519 signature over ASCII(b64u(header) "." b64u(payload)).
 *   4. Parse the payload bytes back to the receipt payload object.
 *   5. Round-trip check: canonicalize(parsedPayload) MUST equal the verified
 *      payload bytes byte-for-byte. This rejects any non-canonical re-encoding
 *      and guarantees the JWS authenticated the EP canonical form.
 *
 * Fails closed: any structural, header, signature, or round-trip mismatch
 * returns { valid: false, ... } and never throws on attacker-controlled input.
 *
 * @param {string} jws compact JWS string
 * @param {crypto.KeyObject|string|Buffer} publicKey issuer Ed25519 public key
 *   (KeyObject, PEM, or base64url SPKI DER)
 * @returns {{ valid: boolean, checks: { structure: boolean, header: boolean, signature: boolean, roundtrip: boolean }, payload?: object, header?: object, error?: string }}
 */
export function verifyReceiptJws(jws, publicKey) {
  const checks = { structure: false, header: false, signature: false, roundtrip: false };

  if (typeof jws !== 'string') {
    return { valid: false, checks, error: 'jws must be a compact JWS string' };
  }
  if (jws.length > MAX_COMPACT_JWS_CHARS) {
    return { valid: false, checks, error: 'jws exceeds the profile size limit' };
  }
  const parts = jws.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    return { valid: false, checks, error: 'jws is not a well-formed compact serialization' };
  }
  const [protectedB64, payloadB64, sigB64] = parts;

  let header;
  let payloadBytes;
  let sigBytes;
  try {
    const protectedBytes = decodeCanonicalB64u(protectedB64, MAX_PROTECTED_HEADER_BYTES);
    header = decodeStrictJson(protectedBytes, 'protected header').value;
    payloadBytes = decodeCanonicalB64u(payloadB64, 8 * 1024 * 1024);
    sigBytes = decodeCanonicalB64u(sigB64, 64);
  } catch (e) {
    return { valid: false, checks, error: `Malformed JWS segment: ${e.message}` };
  }
  if (sigBytes.length !== 64) {
    return { valid: false, checks, error: 'JWS Ed25519 signature must be exactly 64 bytes' };
  }
  if (!isPlainObject(header)) {
    return { valid: false, checks, error: 'protected header is not a JSON object' };
  }
  checks.structure = true;

  const headerNames = Object.keys(header);
  if (headerNames.some((name) => !['alg', 'typ', 'kid'].includes(name))) {
    return { valid: false, checks, header, error: 'protected header contains a member outside the EP JWS profile' };
  }
  if (header.kid !== undefined && (typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 256)) {
    return { valid: false, checks, header, error: 'protected header kid is invalid' };
  }

  if (header.alg !== JWS_ALG) {
    return { valid: false, checks, header, error: `Unsupported alg: ${header.alg} (expected ${JWS_ALG})` };
  }
  if (header.typ !== JWS_TYP) {
    return { valid: false, checks, header, error: `Unexpected typ: ${header.typ} (expected ${JWS_TYP})` };
  }
  checks.header = true;

  try {
    const keyObject = ed25519PublicFromKey(publicKey);
    if (keyObject.asymmetricKeyType !== 'ed25519') {
      return { valid: false, checks, header, error: `EP JWS requires an Ed25519 key (got ${keyObject.asymmetricKeyType})` };
    }
    const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, 'ascii');
    checks.signature = crypto.verify(null, signingInput, keyObject, sigBytes);
  } catch (e) {
    return { valid: false, checks, header, error: `Signature verification failed: ${e.message}` };
  }
  if (!checks.signature) {
    return { valid: false, checks, header, error: 'JWS signature does not verify against the issuer key' };
  }

  let payload;
  try {
    payload = decodeStrictJson(payloadBytes, 'payload').value;
  } catch (e) {
    return { valid: false, checks, header, error: `Payload is not valid JSON: ${e.message}` };
  }
  if (!isPlainObject(payload)) {
    return { valid: false, checks, header, error: 'JWS payload must be a JSON object' };
  }

  // Round-trip: the verified bytes MUST already be the EP canonical (JCS) form.
  const recanonicalized = Buffer.from(canonicalize(payload), 'utf8');
  checks.roundtrip = recanonicalized.equals(payloadBytes);
  if (!checks.roundtrip) {
    return { valid: false, checks, header, payload, error: 'JWS payload is not byte-identical to EP canonical (JCS) form' };
  }

  return { valid: true, checks, header, payload };
}

export { canonicalize as canonicalizeReceiptPayload };
