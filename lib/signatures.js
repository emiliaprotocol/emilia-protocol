/**
 * EMILIA Protocol — Receipt Signature Verification
 *
 * The `identified_signed` provenance tier (0.5x weight) requires that the
 * submitter cryptographically sign the receipt payload with their ed25519 key.
 * This module verifies those signatures and downgrades unverified claims to
 * `self_attested` (0.3x weight) — preventing fraudulent tier inflation.
 *
 * Key design:
 * - Submitters include a `signature` in the evidence field
 * - The signature covers the canonical receipt hash (same SHA-256 used for chain-linking)
 * - Public keys are stored in entity metadata or provided inline with proof
 * - Verification is deterministic and stateless
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

/**
 * Verify an ed25519 signature over a receipt hash.
 *
 * @param {string} receiptHash - The SHA-256 receipt hash (hex)
 * @param {string} signature - The base64-encoded ed25519 signature
 * @param {string} publicKey - The base64-encoded ed25519 public key (32 bytes)
 * @returns {{ valid: boolean, reason?: string }}
 */
export function verifyReceiptSignature(receiptHash, signature, publicKey) {
  if (!receiptHash || typeof receiptHash !== 'string') {
    return { valid: false, reason: 'receiptHash is required and must be a string' };
  }
  if (!signature || typeof signature !== 'string') {
    return { valid: false, reason: 'signature is required and must be a string' };
  }
  if (!publicKey || typeof publicKey !== 'string') {
    return { valid: false, reason: 'publicKey is required and must be a string' };
  }

  try {
    // Decode base64 signature
    const sigBuffer = Buffer.from(signature, 'base64');
    // Ed25519 signatures are always 64 bytes
    if (sigBuffer.length !== 64) {
      return { valid: false, reason: `invalid signature length: expected 64 bytes, got ${sigBuffer.length}` };
    }

    // Decode base64 public key
    const keyBuffer = Buffer.from(publicKey, 'base64');
    // Ed25519 public keys are always 32 bytes
    if (keyBuffer.length !== 32) {
      return { valid: false, reason: `invalid public key length: expected 32 bytes, got ${keyBuffer.length}` };
    }

    // Construct the KeyObject from raw DER-encoded SPKI
    const spkiDer = buildEd25519SpkiDer(keyBuffer);
    const keyObject = crypto.createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki',
    });

    // The data being verified is the raw receipt hash bytes (hex-decoded)
    const dataBuffer = Buffer.from(receiptHash, 'hex');

    const valid = crypto.verify(null, dataBuffer, keyObject, sigBuffer);
    return { valid };
  /* c8 ignore next 3 -- crypto.verify returns false rather than throwing; catch is defensive */
  } catch (err) {
    return { valid: false, reason: `verification error: ${err.message}` };
  }
}

/**
 * Build the DER-encoded SubjectPublicKeyInfo structure for an Ed25519 raw public key.
 * Ed25519 OID: 1.3.101.112
 * DER prefix for Ed25519 SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00
 *
 * @param {Buffer} rawKey - 32-byte raw Ed25519 public key
 * @returns {Buffer} DER-encoded SPKI
 */
function buildEd25519SpkiDer(rawKey) {
  // ASN.1 DER structure for Ed25519 SubjectPublicKeyInfo:
  // SEQUENCE {
  //   SEQUENCE { OID 1.3.101.112 }
  //   BIT STRING { 0x00 || rawKey }
  // }
  const oidSeq = Buffer.from('300506032b6570', 'hex');       // SEQUENCE { OID 1.3.101.112 }
  const bitStringContent = Buffer.concat([Buffer.from([0x00]), rawKey]); // prepend unused-bits byte
  const bitString = Buffer.concat([
    Buffer.from([0x03, bitStringContent.length]),
    bitStringContent,
  ]);
  const inner = Buffer.concat([oidSeq, bitString]);
  const spki = Buffer.concat([
    Buffer.from([0x30, inner.length]),
    inner,
  ]);
  return spki;
}

/**
 * Resolve the effective provenance tier for a receipt, verifying any
 * claimed identified_signed tier against the provided signature material.
 *
 * If claimedTier is 'identified_signed' and:
 *   - evidence.signature and evidence.public_key are present → verify signature
 *   - Verification passes → return 'identified_signed'
 *   - Verification fails → downgrade to 'self_attested', include warning
 *   - Signature fields absent → downgrade to 'self_attested'
 *
 * All other tiers pass through unchanged.
 *
 * @param {string} claimedTier - The requested provenance_tier
 * @param {string} receiptHash - The canonical receipt hash
 * @param {Object} evidence - The evidence object from the receipt submission
 * @returns {{ tier: string, warning?: string }}
 */
export function resolveProvenanceTier(claimedTier, receiptHash, evidence) {
  if (claimedTier !== 'identified_signed') {
    return { tier: claimedTier };
  }

  const sig = evidence?.signature;
  const pubKey = evidence?.public_key;

  if (!sig || !pubKey) {
    return {
      tier: 'self_attested',
      warning: 'identified_signed tier claimed but signature and/or public_key missing from evidence; downgraded to self_attested',
    };
  }

  let sigBuffer;
  let keyBuffer;

  try {
    sigBuffer = Buffer.from(sig, 'base64');
    if (sigBuffer.length !== 64) {
      return {
        tier: 'self_attested',
        warning: `identified_signed signature has invalid length (${sigBuffer.length} bytes, expected 64); downgraded to self_attested`,
      };
    }
  /* c8 ignore next 5 -- Buffer.from(s,'base64') never throws in Node.js; catch is defensive */
  } catch {
    return {
      tier: 'self_attested',
      warning: 'identified_signed signature is not valid base64; downgraded to self_attested',
    };
  }

  try {
    keyBuffer = Buffer.from(pubKey, 'base64');
    if (keyBuffer.length !== 32) {
      return {
        tier: 'self_attested',
        warning: `identified_signed public_key has invalid length (${keyBuffer.length} bytes, expected 32); downgraded to self_attested`,
      };
    }
  /* c8 ignore next 5 -- Buffer.from(s,'base64') never throws in Node.js; catch is defensive */
  } catch {
    return {
      tier: 'self_attested',
      warning: 'identified_signed public_key is not valid base64; downgraded to self_attested',
    };
  }

  try {
    const spkiDer = buildEd25519SpkiDer(keyBuffer);
    const keyObject = crypto.createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki',
    });

    const dataBuffer = Buffer.from(receiptHash, 'hex');
    const valid = crypto.verify(null, dataBuffer, keyObject, sigBuffer);

    if (valid) {
      return { tier: 'identified_signed' };
    } else {
      return {
        tier: 'self_attested',
        warning: 'identified_signed signature verification failed; downgraded to self_attested',
      };
    }
  /* c8 ignore next 5 -- crypto.verify returns false rather than throwing; catch is defensive */
  } catch (err) {
    return {
      tier: 'self_attested',
      warning: `identified_signed signature verification error: ${err.message}; downgraded to self_attested`,
    };
  }
}
