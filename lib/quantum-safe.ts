// SPDX-License-Identifier: Apache-2.0

/**
 * Opt-in hybrid receipt signatures.
 *
 * Existing EP receipts remain Ed25519-compatible. This module defines a
 * separate envelope for long-lived artifacts that need a classical signature
 * and an ML-DSA-65 signature over the exact same bytes. Verification requires
 * both signatures; accepting either one would not provide a hybrid security
 * bound if one algorithm is compromised.
 */

import crypto from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const TYPE = 'EP-HYBRID-SIGNATURE-v1';
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/u;
const ED25519_RAW_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const ML_DSA_PUBLIC_BYTES = ml_dsa65.lengths.publicKey;
const ML_DSA_SECRET_BYTES = ml_dsa65.lengths.secretKey;
const ML_DSA_SIGNATURE_BYTES = ml_dsa65.lengths.signature;
const KEY_ID_MAX_LENGTH = 256;
const ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);

function asBytes(value, label) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) {
    throw new TypeError(`${label} must be bytes or unpadded base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (!bytes.length || bytes.toString('base64url') !== value) {
    throw new TypeError(`${label} is not canonical base64url`);
  }
  return new Uint8Array(bytes);
}

function asBase64url(value) {
  return Buffer.from(value).toString('base64url');
}

function payloadBytes(payload) {
  if (typeof payload === 'string') return Buffer.from(payload, 'utf8');
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  throw new TypeError('payload must be a UTF-8 string or Uint8Array');
}

function hashPayload(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function normalizeKeyIds(value) {
  if (value == null) value = {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('keyIds must be an object');
  }
  const unknown = Object.keys(value).filter((key) => !['ed25519', 'mlDsa65'].includes(key));
  if (unknown.length) throw new TypeError(`unknown key id fields: ${unknown.join(', ')}`);
  const normalize = (key) => {
    const id = value[key] ?? null;
    if (id !== null && (typeof id !== 'string' || id.length > KEY_ID_MAX_LENGTH)) {
      throw new TypeError(`${key} key id must be null or a bounded string`);
    }
    return id;
  };
  return { ed25519: normalize('ed25519'), ml_dsa65: normalize('mlDsa65') };
}

function signingInput(payload, keyIds) {
  const transcript = Buffer.from(`${TYPE}\u0000${JSON.stringify({ algorithms: ALGORITHMS, key_ids: keyIds })}\u0000`, 'utf8');
  return Buffer.concat([transcript, payload]);
}

function ed25519Spki(rawKey) {
  const raw = Buffer.from(rawKey);
  const oid = Buffer.from('300506032b6570', 'hex');
  const bitString = Buffer.concat([Buffer.from([0x03, raw.length + 1, 0x00]), raw]);
  const body = Buffer.concat([oid, bitString]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function trustedEd25519Key(value) {
  if (value?.type === 'public' || value?.type === 'private') {
    const publicKey = value.type === 'private' ? crypto.createPublicKey(value) : value;
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('trusted Ed25519 key must be Ed25519');
    return publicKey;
  }
  if (typeof value === 'string' && value.includes('BEGIN')) {
    const publicKey = crypto.createPublicKey(value);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('trusted Ed25519 key must be Ed25519');
    return publicKey;
  }
  const raw = asBytes(value, 'trusted Ed25519 public key');
  if (raw.length !== ED25519_RAW_BYTES) throw new TypeError('trusted Ed25519 public key must be 32 raw bytes');
  return crypto.createPublicKey({ key: ed25519Spki(raw), format: 'der', type: 'spki' });
}

function signingEd25519Key(value) {
  const key = value?.type === 'private' && typeof value.export === 'function'
    ? value
    : crypto.createPrivateKey(value);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('ed25519PrivateKey must be an Ed25519 private key');
  }
  return key;
}

function verifyLength(bytes, expected, label) {
  if (bytes.length !== expected) throw new TypeError(`${label} must be ${expected} bytes`);
}

interface HybridSigningKeys {
  ed25519PrivateKey?: crypto.KeyObject | string;
  mlDsaSecretKey?: Uint8Array | string;
  keyIds?: { ed25519?: string; mlDsa65?: string };
}

// Sign exact payload bytes with Ed25519 and ML-DSA-65.
export function signHybrid(payload: string | Uint8Array, keys: HybridSigningKeys = {}) {
  const bytes = payloadBytes(payload);
  if (!keys.ed25519PrivateKey) throw new TypeError('ed25519PrivateKey is required');
  const edPrivateKey = signingEd25519Key(keys.ed25519PrivateKey);
  const mlSecret = asBytes(keys.mlDsaSecretKey, 'mlDsaSecretKey');
  verifyLength(mlSecret, ML_DSA_SECRET_BYTES, 'mlDsaSecretKey');
  const keyIds = normalizeKeyIds(keys.keyIds);
  const input = signingInput(bytes, keyIds);

  const edSignature = crypto.sign(null, input, edPrivateKey);
  verifyLength(edSignature, ED25519_SIGNATURE_BYTES, 'Ed25519 signature');
  const mlSignature = ml_dsa65.sign(input, mlSecret);

  return {
    type: TYPE,
    payload_sha256: hashPayload(bytes),
    key_ids: {
      ed25519: keyIds.ed25519,
      ml_dsa65: keyIds.ml_dsa65,
    },
    signatures: {
      ed25519: edSignature.toString('base64url'),
      ml_dsa65: asBase64url(mlSignature),
    },
  };
}

/**
 * Verify a hybrid envelope. Both algorithms must pass and the envelope must
 * bind to the supplied payload. This function fails closed and never throws
 * for attacker-controlled envelope material.
 */
interface HybridTrustedKeys {
  ed25519?: crypto.KeyObject | string | Uint8Array;
  mlDsa65?: Uint8Array | string;
}

export function verifyHybrid(payload: string | Uint8Array, envelope, trustedKeys: HybridTrustedKeys = {}) {
  try {
    const bytes = payloadBytes(payload);
    if (!envelope || envelope.type !== TYPE) return { valid: false, reason: 'unsupported hybrid signature type' };
    const envelopeKeys = Object.keys(envelope).sort().join('|');
    if (envelopeKeys !== 'key_ids|payload_sha256|signatures|type') return { valid: false, reason: 'invalid hybrid envelope' };
    if (envelope.payload_sha256 !== hashPayload(bytes)) return { valid: false, reason: 'payload hash mismatch' };
    const keyIds = normalizeKeyIds({
      ed25519: envelope.key_ids?.ed25519,
      mlDsa65: envelope.key_ids?.ml_dsa65,
    });
    if (!envelope.key_ids || Object.keys(envelope.key_ids).sort().join('|') !== 'ed25519|ml_dsa65') {
      return { valid: false, reason: 'invalid hybrid key ids' };
    }
    if (!envelope.signatures || Object.keys(envelope.signatures).sort().join('|') !== 'ed25519|ml_dsa65') {
      return { valid: false, reason: 'invalid hybrid signatures' };
    }
    if (!envelope.signatures?.ed25519 || !envelope.signatures?.ml_dsa65) {
      return { valid: false, reason: 'both hybrid signatures are required' };
    }
    if (!trustedKeys.ed25519 || !trustedKeys.mlDsa65) {
      return { valid: false, reason: 'both trusted public keys are required' };
    }

    const edSignature = asBytes(envelope.signatures.ed25519, 'Ed25519 signature');
    const mlSignature = asBytes(envelope.signatures.ml_dsa65, 'ML-DSA signature');
    verifyLength(edSignature, ED25519_SIGNATURE_BYTES, 'Ed25519 signature');
    verifyLength(mlSignature, ML_DSA_SIGNATURE_BYTES, 'ML-DSA signature');
    const mlPublic = asBytes(trustedKeys.mlDsa65, 'trusted ML-DSA public key');
    verifyLength(mlPublic, ML_DSA_PUBLIC_BYTES, 'trusted ML-DSA public key');
    const input = signingInput(bytes, keyIds);

    const ed25519 = crypto.verify(null, input, trustedEd25519Key(trustedKeys.ed25519), Buffer.from(edSignature));
    const mlDsa = ml_dsa65.verify(mlSignature, input, mlPublic);
    return { valid: ed25519 && mlDsa, hybrid: ed25519 && mlDsa, checks: { ed25519, ml_dsa65: mlDsa } };
  } catch (error) {
    return { valid: false, reason: `verification error: ${error.message}` };
  }
}

export const HYBRID_SIGNATURE_TYPE = TYPE;
export const HYBRID_LENGTHS = Object.freeze({
  ed25519PublicKey: ED25519_RAW_BYTES,
  ed25519Signature: ED25519_SIGNATURE_BYTES,
  mlDsa65PublicKey: ML_DSA_PUBLIC_BYTES,
  mlDsa65SecretKey: ML_DSA_SECRET_BYTES,
  mlDsa65Signature: ML_DSA_SIGNATURE_BYTES,
});
