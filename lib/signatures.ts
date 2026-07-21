/**
 * EMILIA Protocol — Receipt Signature Verification
 *
 * The `identified_signed` provenance tier (0.5x weight) requires that the
 * authenticated submitter cryptographically sign the receipt submission with
 * the Ed25519 key enrolled on that entity.
 * This module verifies those signatures and downgrades unverified claims to
 * `self_attested` (0.3x weight) — preventing fraudulent tier inflation.
 *
 * Key design:
 * - Submitters include a `signature` in the evidence field
 * - The signature covers a canonical, non-circular submission digest
 * - Public keys come from authenticated entity metadata; an inline key is only
 *   a consistency hint and never establishes identity
 * - Verification is deterministic and stateless
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { canonicalize } from './canonical-json.js';

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const AUTH_EVIDENCE_FIELDS = new Set([
  'signature',
  'public_key',
  'signature_input_digest',
  'signature_version',
]);

function decodeBase64Strict(value: string, label: string): Buffer {
  if (typeof value !== 'string' || !value || !BASE64_RE.test(value)) {
    throw new Error(`${label} is not canonical base64/base64url`);
  }
  const normalized = value
    .replace(/=+$/u, '')
    .replace(/\+/gu, '-')
    .replace(/\//gu, '_');
  const bytes = Buffer.from(normalized, 'base64url');
  if (!bytes.length || bytes.toString('base64url') !== normalized) {
    throw new Error(`${label} is not canonical base64/base64url`);
  }
  return bytes;
}

function ed25519PublicKey(publicKey: string): {
  keyObject: any;
  canonicalDer: Buffer;
} {
  const bytes = decodeBase64Strict(publicKey, 'publicKey');
  if (bytes.length !== 32 && bytes.length !== 44) {
    throw new Error(
      `publicKey must be a 32-byte raw key or 44-byte SPKI DER, got ${bytes.length} bytes`,
    );
  }
  const der = bytes.length === 32 ? buildEd25519SpkiDer(bytes) : bytes;
  const keyObject = crypto.createPublicKey({
    key: der,
    format: 'der',
    type: 'spki',
  });
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    throw new Error('publicKey is not Ed25519');
  }
  const canonicalDer = keyObject.export({ format: 'der', type: 'spki' });
  if (bytes.length !== 32 && !Buffer.from(canonicalDer).equals(bytes)) {
    throw new Error('publicKey is not canonical Ed25519 SPKI DER');
  }
  return { keyObject, canonicalDer: Buffer.from(canonicalDer) };
}

function unsignedEvidence(evidence: any): Record<string, any> {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence))
    return {};
  return Object.fromEntries(
    Object.entries(evidence).filter(([key]) => !AUTH_EVIDENCE_FIELDS.has(key)),
  );
}

/**
 * Build the exact client-signable input for the legacy identified-signed
 * receipt tier. This is deliberately separate from the final chain hash: the
 * final hash includes the signature and server-derived scoring fields, so using
 * it as the signature input would be circular and impossible for a client to
 * construct.
 */
export function buildIdentifiedSubmissionDigest(input: any = {}): {
  payload: any;
  canonical: string;
  digest: string;
} {
  const payload = {
    type: 'EP-IDENTIFIED-RECEIPT-SUBMISSION-v1',
    target_entity_ref: input.targetEntityRef ?? null,
    transaction_ref: input.transactionRef ?? null,
    transaction_type: input.transactionType ?? null,
    signals: {
      delivery_accuracy: input.signals?.delivery_accuracy ?? null,
      product_accuracy: input.signals?.product_accuracy ?? null,
      price_integrity: input.signals?.price_integrity ?? null,
      return_processing: input.signals?.return_processing ?? null,
      agent_satisfaction: input.signals?.agent_satisfaction ?? null,
    },
    agent_behavior: input.agentBehavior ?? null,
    claims: input.claims ?? null,
    evidence: unsignedEvidence(input.evidence),
    context: input.context ?? null,
    request_bilateral: input.requestBilateral === true,
  };
  const canonical = canonicalize(payload);
  if (typeof canonical !== 'string')
    throw new Error('identified submission is not canonical JSON');
  return {
    payload,
    canonical,
    digest: crypto
      .createHash('sha256')
      .update(canonical, 'utf8')
      .digest('hex'),
  };
}

/**
 * Verify an ed25519 signature over a receipt hash.
 */
export function verifyReceiptSignature(
  receiptHash: string,
  signature: string,
  publicKey: string,
): { valid: boolean; reason?: string } {
  if (typeof receiptHash !== 'string' || !SHA256_HEX_RE.test(receiptHash)) {
    return {
      valid: false,
      reason: 'receiptHash must be a lowercase SHA-256 hex digest',
    };
  }
  if (!signature || typeof signature !== 'string') {
    return {
      valid: false,
      reason: 'signature is required and must be a string',
    };
  }
  if (!publicKey || typeof publicKey !== 'string') {
    return {
      valid: false,
      reason: 'publicKey is required and must be a string',
    };
  }

  try {
    const sigBuffer = decodeBase64Strict(signature, 'signature');
    // Ed25519 signatures are always 64 bytes
    if (sigBuffer.length !== 64) {
      return {
        valid: false,
        reason: `invalid signature length: expected 64 bytes, got ${sigBuffer.length}`,
      };
    }

    const { keyObject } = ed25519PublicKey(publicKey);

    // The data being verified is the raw receipt hash bytes (hex-decoded)
    const dataBuffer = Buffer.from(receiptHash, 'hex');

    const valid = crypto.verify(null, dataBuffer, keyObject, sigBuffer);
    return { valid };
    /* c8 ignore next 3 -- crypto.verify returns false rather than throwing; catch is defensive */
  } catch (err) {
    return {
      valid: false,
      reason: `verification error: ${(err as any).message}`,
    };
  }
}

/**
 * Build the DER-encoded SubjectPublicKeyInfo structure for an Ed25519 raw public key.
 * Ed25519 OID: 1.3.101.112
 * DER prefix for Ed25519 SPKI: 30 2a 30 05 06 03 2b 65 70 03 21 00
 */
function buildEd25519SpkiDer(rawKey: Buffer): Buffer {
  // ASN.1 DER structure for Ed25519 SubjectPublicKeyInfo:
  // SEQUENCE {
  //   SEQUENCE { OID 1.3.101.112 }
  //   BIT STRING { 0x00 || rawKey }
  // }
  const oidSeq = Buffer.from('300506032b6570', 'hex'); // SEQUENCE { OID 1.3.101.112 }
  const bitStringContent = Buffer.concat([Buffer.from([0x00]), rawKey]); // prepend unused-bits byte
  const bitString = Buffer.concat([
    Buffer.from([0x03, bitStringContent.length]),
    bitStringContent,
  ]);
  const inner = Buffer.concat([oidSeq, bitString]);
  const spki = Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
  return spki;
}

/**
 * Resolve the effective provenance tier for a receipt, verifying any
 * claimed identified_signed tier against the provided signature material and
 * a public key supplied by the authenticated relying-party context.
 *
 * If claimedTier is 'identified_signed' and:
 *   - evidence.signature and trustedPublicKey are present → verify signature
 *   - an evidence.public_key, if present, must name the same trusted key
 *   - Verification passes → return 'identified_signed'
 *   - Verification fails → downgrade to 'self_attested', include warning
 *   - Signature fields absent → downgrade to 'self_attested'
 *
 * All other tiers pass through unchanged.
 */
export function resolveProvenanceTier(
  claimedTier: string,
  receiptHash: string,
  evidence: any,
  trustedPublicKey: string,
): { tier: string; warning?: string } {
  if (claimedTier !== 'identified_signed') {
    return { tier: claimedTier };
  }

  const sig = evidence?.signature;
  if (!sig) {
    return {
      tier: 'self_attested',
      warning:
        'identified_signed tier claimed but signature is missing from evidence; downgraded to self_attested',
    };
  }

  if (!trustedPublicKey) {
    return {
      tier: 'self_attested',
      warning:
        'identified_signed tier has no enrolled submitter key; downgraded to self_attested',
    };
  }

  try {
    const trusted = ed25519PublicKey(trustedPublicKey);
    if (evidence?.public_key) {
      const presented = ed25519PublicKey(evidence.public_key);
      if (!presented.canonicalDer.equals(trusted.canonicalDer)) {
        return {
          tier: 'self_attested',
          warning:
            'identified_signed evidence key does not match the authenticated submitter key; downgraded to self_attested',
        };
      }
    }
    const result = verifyReceiptSignature(receiptHash, sig, trustedPublicKey);
    if (result.valid) return { tier: 'identified_signed' };
    return {
      tier: 'self_attested',
      warning: `identified_signed signature verification failed${
        result.reason ? `: ${result.reason}` : ''
      }; downgraded to self_attested`,
    };
  } catch (err) {
    return {
      tier: 'self_attested',
      warning: `identified_signed key verification error: ${
        (err as any).message
      }; downgraded to self_attested`,
    };
  }
}
