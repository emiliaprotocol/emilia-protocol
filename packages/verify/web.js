/**
 * @emilia-protocol/verify/web — Zero-Dependency Trust Verification (Web Crypto)
 *
 * The browser/edge/Deno counterpart to index.js. Identical verification
 * semantics, but built on the W3C Web Crypto API (globalThis.crypto.subtle)
 * instead of Node's `crypto` module — so a receipt can be verified entirely
 * inside the relying party's own browser tab, with nothing uploaded and no
 * server trusted. Same input, same `{ valid, checks }` output as index.js
 * (proven byte-for-byte in web.test.js).
 *
 * Pure ESM, zero dependencies. Functions are async because Web Crypto is.
 *
 * @license Apache-2.0
 */

import { strictJsonGate } from './strict-json.js';

const SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'];
const SUPPORTED_PROOF_VERSIONS = ['EP-PROOF-v1'];

const subtle = globalThis.crypto?.subtle;

// =============================================================================
// PRIMITIVES (pure — no Node Buffer, no Node crypto)
// =============================================================================

const ENC = new TextEncoder();
const DEC = new TextDecoder('utf-8', { fatal: true });

/**
 * @param {string} str
 * @returns {Uint8Array<ArrayBuffer>}
 */
function utf8(str) {
  return ENC.encode(str);
}

/**
 * Canonical, unpadded base64url → Uint8Array.
 * @param {string} b64u
 * @returns {Uint8Array<ArrayBuffer>}
 */
function b64uToBytes(b64u) {
  if (typeof b64u !== 'string' || b64u.length === 0
      || !/^[A-Za-z0-9_-]+$/.test(b64u) || b64u.length % 4 === 1) {
    throw new Error('value is not canonical base64url');
  }
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (bytesToB64u(out) !== b64u) throw new Error('value is not canonical base64url');
  return out;
}

/**
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @returns {string}
 */
function bytesToB64u(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

/**
 * Same recursive canonical JSON as index.js / lib/guard-policies.js — depth-first
 * key sort at every level. Signer and verifier MUST compute byte-identical bytes.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(/** @type {Record<string, unknown>} */ (value)[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * @param {Uint8Array<ArrayBuffer>} bytes
 * @returns {Promise<Uint8Array<ArrayBuffer>>}
 */
async function sha256Bytes(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

/**
 * @param {string} str
 * @returns {Promise<string>}
 */
async function sha256Hex(str) {
  return bytesToHex(await sha256Bytes(utf8(str)));
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {Promise<string>}
 */
async function hashPairHex(a, b) {
  const sorted = [a, b].sort();
  return sha256Hex(sorted[0] + sorted[1]);
}

// EP-MERKLE-v2: domain-separated + positional (matches index.js / Py / Go).
export const MERKLE_V2_ALG = 'EP-MERKLE-v2';
/**
 * @param {string} canonicalPayload
 * @returns {Promise<string>}
 */
async function leafHashV2(canonicalPayload) {
  return bytesToHex(await sha256Bytes(concatBytes(new Uint8Array([0x00]), utf8(canonicalPayload))));
}
/**
 * @param {string} left
 * @param {string} right
 * @returns {Promise<string>}
 */
async function hashPairV2Hex(left, right) {
  return bytesToHex(await sha256Bytes(concatBytes(new Uint8Array([0x01]), utf8(left + right))));
}

/**
 * @param {Uint8Array<ArrayBuffer>} a
 * @param {Uint8Array<ArrayBuffer>} b
 * @returns {Uint8Array<ArrayBuffer>}
 */
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * @param {Uint8Array<ArrayBuffer>} a
 * @param {Uint8Array<ArrayBuffer>} b
 * @returns {boolean}
 */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// WebAuthn ECDSA signatures are ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }.
// Web Crypto's ECDSA verify wants raw r‖s (two fixed-width 32-byte integers).
// Node's crypto.verify accepts DER directly, which is why index.js needs no
// conversion — the browser does. Returns a 64-byte Uint8Array, or null if the
// DER is malformed.
/**
 * @param {Uint8Array<ArrayBuffer>} der
 * @returns {Uint8Array<ArrayBuffer>|null}
 */
function derEcdsaToRawP256(der) {
  let i = 0;
  // A P-256 ECDSA signature always fits in DER's short length form. Enforce
  // canonical DER so the browser cannot accept an encoding Node rejects (for
  // example, a valid signature with ignored trailing bytes).
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > 72) return null;
  if (der[i++] !== 0x30) return null; // SEQUENCE
  const sequenceLength = der[i++];
  if ((sequenceLength & 0x80) !== 0 || sequenceLength !== der.length - i) return null;

  const readInt = () => {
    if (der[i++] !== 0x02) return null; // INTEGER
    const len = der[i++];
    if (!Number.isInteger(len) || len < 1 || len > 33 || i + len > der.length) return null;
    let val = der.subarray(i, i + len);
    i += len;
    // DER INTEGERs are signed. ECDSA components are positive and minimally
    // encoded: one 0x00 is allowed only when needed to clear the sign bit.
    if ((val[0] & 0x80) !== 0) return null;
    if (val.length > 1 && val[0] === 0x00) {
      if ((val[1] & 0x80) === 0) return null;
      val = val.subarray(1);
    }
    if (val.length > 32) return null; // not a P-256 component
    const padded = new Uint8Array(32);
    padded.set(val, 32 - val.length); // left-pad to 32 bytes
    return padded;
  };

  const r = readInt();
  if (!r) return null;
  const s = readInt();
  if (!s) return null;
  if (i !== der.length) return null;
  return concatBytes(r, s);
}

// =============================================================================
// RECEIPT VERIFICATION (Ed25519)
// =============================================================================

/**
 * @typedef {{hash: string, position: 'left'|'right'}} MerkleProofStep
 */

/**
 * EP-RECEIPT-v1 document shape, as accessed by verifyReceipt below (every
 * member is read defensively via optional chaining, so every member here is
 * optional — this mirrors what the function body already assumes).
 * @typedef {{
 *   '@version'?: string,
 *   payload?: unknown,
 *   signature?: {value?: string, algorithm?: string},
 *   anchor?: {
 *     alg?: string,
 *     merkle_proof?: MerkleProofStep[],
 *     leaf_hash?: string,
 *     merkle_root?: string,
 *   },
 * }} EPReceiptDoc
 */

/**
 * Verify an EP receipt document in the browser. Mirrors index.js verifyReceipt.
 * @param {EPReceiptDoc} doc
 * @param {string} publicKeyBase64url - Ed25519 public key (SPKI DER, base64url)
 * @param {{allowLegacyMerkle?: boolean}} [opts]
 * @returns {Promise<{valid:boolean, checks:{version:boolean,signature:boolean,anchor:boolean|null}, error?:string}>}
 */
export async function verifyReceipt(doc, publicKeyBase64url, opts = {}) {
  /** @type {{version: boolean, signature: boolean, anchor: boolean|null}} */
  const checks = { version: false, signature: false, anchor: null };

  if (!doc?.['@version'] || !SUPPORTED_VERSIONS.includes(doc['@version'])) {
    return { valid: false, checks, error: `Unsupported version: ${doc?.['@version']}` };
  }
  checks.version = true;

  if (!doc.payload || !doc.signature?.value || !doc.signature?.algorithm) {
    return { valid: false, checks, error: 'Missing payload or signature' };
  }

  try {
    const payloadBytes = utf8(canonicalize(doc.payload));
    const key = await subtle.importKey(
      'spki', b64uToBytes(publicKeyBase64url), { name: 'Ed25519' }, false, ['verify'],
    );
    checks.signature = await subtle.verify(
      { name: 'Ed25519' }, key, b64uToBytes(doc.signature.value), payloadBytes,
    );
  } catch (e) {
    return { valid: false, checks, error: `Signature verification failed: ${e.message}` };
  }

  if (doc.anchor?.merkle_proof && doc.anchor?.leaf_hash && doc.anchor?.merkle_root) {
    if (doc.anchor.alg === MERKLE_V2_ALG) {
      const expectedLeaf = await leafHashV2(canonicalize(doc.payload));
      checks.anchor = doc.anchor.leaf_hash === expectedLeaf
        && await verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root, { v2: true });
    } else if (opts.allowLegacyMerkle === true) {
      // Dormant legacy path: pre-v2 anchors verify only on explicit opt-in
      // (old artifacts / compat). Never the default, never a production gate.
      checks.anchor = await verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
    } else {
      // Default requires EP-MERKLE-v2; a legacy v1 anchor is refused.
      checks.anchor = false;
    }
  }

  const valid = checks.version && checks.signature && (checks.anchor === null || checks.anchor === true);
  return { valid, checks };
}

// =============================================================================
// MERKLE ANCHOR VERIFICATION
// =============================================================================

/**
 * @param {string} leafHash
 * @param {MerkleProofStep[]} proof
 * @param {string} expectedRoot
 * @param {{v2?: boolean}} [opts]
 * @returns {Promise<boolean>}
 */
export async function verifyMerkleAnchor(leafHash, proof, expectedRoot, opts = {}) {
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 20) return false;

  const pair = opts.v2 === true ? hashPairV2Hex : hashPairHex;
  let current = leafHash;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string') return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
    current = step.position === 'left'
      ? await pair(step.hash, current)
      : await pair(current, step.hash);
  }
  return current === expectedRoot;
}

// =============================================================================
// CLASS A SIGNOFF VERIFICATION (WebAuthn, offline, ECDSA P-256)
// =============================================================================

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;

/**
 * Verify a Class A (approver-held key) signoff fully offline, in the browser.
 * Mirrors index.js verifyWebAuthnSignoff.
 * @param {{
 *   context?: Record<string, unknown>,
 *   webauthn?: {authenticator_data?: string, client_data_json?: string, signature?: string},
 * }} signoff
 * @param {string} approverPublicKeySpkiB64u
 * @param {{rpId?: string, allowedOrigins?: string[]}} [opts]
 * @returns {Promise<{valid:boolean, checks:object, error?:string}>}
 */
export async function verifyWebAuthnSignoff(signoff, approverPublicKeySpkiB64u, opts = {}) {
  /**
   * @type {{challenge_binding: boolean, client_data_type: boolean,
   *   user_present: boolean, user_verified: boolean,
   *   rp_id_hash: boolean|null, signature: boolean}}
   */
  const checks = {
    challenge_binding: false,
    client_data_type: false,
    user_present: false,
    user_verified: false,
    rp_id_hash: null,
    signature: false,
  };

  try {
    if (!signoff?.context || !signoff?.webauthn) {
      return { valid: false, checks, error: 'Missing context or webauthn evidence' };
    }
    const { authenticator_data, client_data_json, signature } = signoff.webauthn;
    if (!authenticator_data || !client_data_json || !signature) {
      return { valid: false, checks, error: 'Missing webauthn fields' };
    }

    // 1. Challenge binding: clientData.challenge === b64u(SHA-256(canonical(context))).
    const clientDataBytes = b64uToBytes(client_data_json);
    const clientDataText = DEC.decode(clientDataBytes);
    const clientDataGate = strictJsonGate(clientDataText);
    if (!clientDataGate.ok) {
      return { valid: false, checks, error: `Invalid clientDataJSON: ${clientDataGate.reason}` };
    }
    const clientData = JSON.parse(clientDataText);
    const expectedChallenge = bytesToB64u(await sha256Bytes(utf8(canonicalize(signoff.context))));
    checks.challenge_binding = clientData.challenge === expectedChallenge;

    // 2. Ceremony type must be an assertion.
    checks.client_data_type = clientData.type === 'webauthn.get';

    if (Array.isArray(opts.allowedOrigins)) {
      if (opts.allowedOrigins.length === 0
          || !opts.allowedOrigins.includes(clientData.origin)
          || clientData.crossOrigin === true) {
        return { valid: false, checks, error: 'WebAuthn origin is not allowed' };
      }
    }

    // 3. Authenticator flags: user present + user verified.
    const authData = b64uToBytes(authenticator_data);
    if (authData.length < 37) {
      return { valid: false, checks, error: 'authenticator_data too short' };
    }
    const flags = authData[32];
    checks.user_present = (flags & FLAG_UP) === FLAG_UP;
    checks.user_verified = (flags & FLAG_UV) === FLAG_UV;

    // 4. Optional rpId scope check.
    if (opts.rpId) {
      const expectedRpIdHash = await sha256Bytes(utf8(opts.rpId));
      checks.rp_id_hash = bytesEqual(expectedRpIdHash, authData.subarray(0, 32));
    }

    // 5. Signature: ECDSA P-256/SHA-256 over authData ‖ SHA-256(clientDataJSON).
    const signedData = concatBytes(authData, await sha256Bytes(clientDataBytes));
    const rawSig = derEcdsaToRawP256(b64uToBytes(signature));
    if (!rawSig) {
      return { valid: false, checks, error: 'Malformed ECDSA signature' };
    }
    const key = await subtle.importKey(
      'spki', b64uToBytes(approverPublicKeySpkiB64u),
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    checks.signature = await subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signedData,
    );
  } catch (e) {
    return { valid: false, checks, error: `WebAuthn verification failed: ${e.message}` };
  }

  const valid = checks.challenge_binding
    && checks.client_data_type
    && checks.user_present
    && checks.user_verified
    && checks.signature
    && (checks.rp_id_hash === null || checks.rp_id_hash === true);
  return { valid, checks };
}

// =============================================================================
// COMMITMENT PROOF VERIFICATION (Ed25519)
// =============================================================================

/**
 * @param {{
 *   '@version'?: string,
 *   expires_at?: string,
 *   claim?: object|null,
 *   signature?: {value?: string},
 *   commitment?: unknown,
 * }} proof
 * @param {string} [publicKeyBase64url]
 * @param {{allowUnsigned?: boolean}} [options]
 * @returns {Promise<{valid:boolean, claim:object|null, error?:string}>}
 */
export async function verifyCommitmentProof(proof, publicKeyBase64url, options = {}) {
  if (!proof?.['@version'] || !SUPPORTED_PROOF_VERSIONS.includes(proof['@version'])) {
    return { valid: false, claim: null, error: `Unsupported version: ${proof?.['@version']}` };
  }
  if (proof.expires_at && new Date(proof.expires_at) < new Date()) {
    return { valid: false, claim: /** @type {object|null} */ (proof.claim), error: 'Proof has expired' };
  }

  const hasPublicKey = !!publicKeyBase64url;
  const hasSignature = !!proof.signature?.value;

  if (!hasPublicKey || !hasSignature) {
    if (options.allowUnsigned === true && !hasPublicKey && !hasSignature) {
      return { valid: true, claim: /** @type {object|null} */ (proof.claim) };
    }
    const error = !hasPublicKey && !hasSignature
      ? 'Signature and public key are required'
      : !hasPublicKey
        ? 'Public key is required to verify signature'
        : 'Signature is required';
    return { valid: false, claim: /** @type {object|null} */ (proof.claim), error };
  }

  try {
    const key = await subtle.importKey(
      'spki', b64uToBytes(publicKeyBase64url), { name: 'Ed25519' }, false, ['verify'],
    );
    const ok = await subtle.verify(
      { name: 'Ed25519' }, key,
      b64uToBytes(/** @type {{value: string}} */ (proof.signature).value),
      utf8(canonicalize(proof.commitment)),
    );
    if (!ok) return { valid: false, claim: /** @type {object|null} */ (proof.claim), error: 'Invalid signature' };
  } catch (e) {
    return { valid: false, claim: /** @type {object|null} */ (proof.claim), error: `Signature check failed: ${e.message}` };
  }
  return { valid: true, claim: /** @type {object|null} */ (proof.claim) };
}

// =============================================================================
// BUNDLE VERIFICATION
// =============================================================================

/**
 * @param {{'@version'?: string, documents: EPReceiptDoc[]}} bundle
 * @param {string} publicKeyBase64url
 * @returns {Promise<{valid:boolean, total:number, verified:number, failed:string[]}>}
 */
export async function verifyReceiptBundle(bundle, publicKeyBase64url) {
  if (bundle?.['@version'] !== 'EP-BUNDLE-v1') {
    return { valid: false, total: 0, verified: 0, failed: ['Invalid bundle version'] };
  }
  const failed = [];
  let verified = 0;
  for (let i = 0; i < bundle.documents.length; i++) {
    const result = await verifyReceipt(bundle.documents[i], publicKeyBase64url);
    if (result.valid) verified++;
    else failed.push(`doc[${i}]: ${result.error || 'verification failed'}`);
  }
  return { valid: failed.length === 0, total: bundle.documents.length, verified, failed };
}

/** True if Web Crypto with the algorithms EP needs is available in this runtime. */
export function isSupported() {
  return Boolean(subtle && typeof atob === 'function' && typeof btoa === 'function');
}
