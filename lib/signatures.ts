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
  // The EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 proof lives here. It is excluded
  // from the v1 signature input for the same non-circularity reason as
  // `signature` itself: a submission carrying BOTH proofs would otherwise have
  // its v1 digest depend on its v2 signatures. This exclusion is byte-safe for
  // every submission signed to date, because no producer emitted the field
  // before the v2 profile existed.
  'signature_v2',
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

// ── EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 (hybrid submission signature) ────────
//
// WHY A VERSION BUMP AND NOT A SECOND FIELD. A second signature changes the
// SHAPE of the submitted proof, which is a wire-format change. So v2 takes its
// own profile marker and the v1 path above is left exactly as it was:
// buildIdentifiedSubmissionDigest(), verifyReceiptSignature(), and
// resolveProvenanceTier() are byte-for-byte unchanged, still synchronous, and
// still accept precisely the submissions they accepted before. A v1 verifier
// cannot be handed a v2 proof by accident because the v2 proof is a different
// object read by a different function, and a v2 proof presented to
// resolveProvenanceTier() as `evidence.signature` is a string check that fails
// closed (an object is not a base64 signature) and downgrades to self_attested.
//
// WHY THE SIGNED BYTES CHANGED. v1 signs the raw 32 bytes of the receipt hash.
// There is nowhere in 32 bytes of digest to commit an algorithm set, so a v1
// signature carries no anti-stripping property at all: drop a leg from a set of
// v1-style signatures and each surviving one still verifies over the same 32
// bytes. v2 therefore signs a domain-separated canonical object that CONTAINS
// the profile marker, the receipt hash, and the required algorithm SET:
//
//   { "@version": "EP-IDENTIFIED-RECEIPT-SUBMISSION-v2",
//     "receipt_hash": "<64 lowercase hex>",
//     "required_algorithms": ["Ed25519", "ML-DSA-65"] }
//
// Drop the ML-DSA leg and narrow the declared set, and the surviving Ed25519
// signature no longer verifies because the bytes changed. Leave the set intact
// and the missing leg is a structural refusal. The verifier rebuilds these bytes
// from the receipt hash IT holds and from the REGISTERED set, never from
// anything the submission declares.
//
// HONEST BOUNDARY. This raises the provenance tier's resistance to a future
// break of Ed25519 for submissions signed FROM NOW ON. It does not retroactively
// protect submissions already signed under v1, and it says nothing about whether
// the submitted claims are true — the tier has always been about who signed, not
// about what they asserted.

/** The v2 profile marker; it is INSIDE the signed bytes. */
export const IDENTIFIED_SUBMISSION_V2_PROFILE = 'EP-IDENTIFIED-RECEIPT-SUBMISSION-v2';

/** The registered required algorithm set, in canonical order. */
export const IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

/** The public halves a relying party PINS for one submitter. */
export interface IdentifiedSubmissionV2Keys {
  /** Ed25519: base64url SPKI DER (44 bytes) or a raw 32-byte key, as elsewhere here. */
  ed25519PublicKey?: string;
  ed25519KeyId?: string;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  mldsaPublicKey?: string;
  mldsaKeyId?: string;
}

export interface IdentifiedSubmissionV2Result {
  valid: boolean;
  reason: string | null;
  failed_algorithm: string | null;
  checks: {
    algorithm_set: boolean | null;
    legs_present: boolean | null;
    signatures_valid: boolean | null;
  };
}

function v2SetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS[i]);
}

/**
 * The exact bytes every leg of a v2 submission signature covers. Exported so a
 * submitting client, a conformance vector, or an independent implementation can
 * rebuild them without reading this module's internals.
 *
 * @throws on a malformed receipt hash or a non-registered algorithm set. The
 *   verifier catches this and refuses by name, so caller input never throws.
 */
export function identifiedSubmissionV2SignedBytes(
  receiptHash: string,
  requiredAlgorithms: readonly string[] = IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (typeof receiptHash !== 'string' || !SHA256_HEX_RE.test(receiptHash)) {
    throw new Error('identifiedSubmissionV2SignedBytes: receiptHash must be a lowercase SHA-256 hex digest');
  }
  if (!v2SetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('identifiedSubmissionV2SignedBytes: algorithm set is not the registered EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 set');
  }
  const canonical = canonicalize({
    '@version': IDENTIFIED_SUBMISSION_V2_PROFILE,
    receipt_hash: receiptHash,
    required_algorithms: [...requiredAlgorithms],
  });
  if (typeof canonical !== 'string') {
    throw new Error('identifiedSubmissionV2SignedBytes: signed material is not canonical JSON');
  }
  return Buffer.from(canonical, 'utf8');
}

/**
 * Verify a v2 submission signature SET over the receipt hash the verifier holds.
 * FAIL-CLOSED and asynchronous (ML-DSA-65 verification is async); never throws
 * on caller input. Both legs must verify under the PINNED keys over bytes this
 * function rebuilds itself, or the result is a named refusal.
 *
 * The closed algorithm registry, the Ed25519 curve pin, the exact signature and
 * public-key length pins, and the "no ML-DSA backend is a refusal, never a pass"
 * rule all live in EP-SIG-AGILITY-v1 and are reached through
 * verifyAgileSignatureSet. None of them is reimplemented here.
 */
export async function verifyIdentifiedSubmissionV2(
  receiptHash: string,
  submission: any,
  keys: IdentifiedSubmissionV2Keys | null | undefined,
  options: Record<string, unknown> = {},
): Promise<IdentifiedSubmissionV2Result> {
  const checks: IdentifiedSubmissionV2Result['checks'] = {
    algorithm_set: null,
    legs_present: null,
    signatures_valid: null,
  };
  const refuse = (reason: string, failedAlgorithm: string | null = null): IdentifiedSubmissionV2Result =>
    ({ valid: false, reason, failed_algorithm: failedAlgorithm, checks });

  if (!submission || typeof submission !== 'object' || Array.isArray(submission)) {
    return refuse('malformed_submission');
  }
  if (submission['@version'] !== IDENTIFIED_SUBMISSION_V2_PROFILE) {
    return refuse('unknown_profile');
  }

  // The declared set must be EXACTLY the registered one. A narrowed set is the
  // stripping attack's cover story, refused structurally here and, independently,
  // by the signature check below, which rebuilds the bytes from the REGISTERED
  // set regardless of what the submission declares.
  if (!v2SetMatchesRegistered(submission.required_algorithms)) {
    checks.algorithm_set = false;
    return refuse('algorithm_set_mismatch');
  }
  checks.algorithm_set = true;

  const signatures = Array.isArray(submission.signatures) ? submission.signatures : null;
  if (!signatures || signatures.length === 0) {
    checks.legs_present = false;
    return refuse('hybrid_leg_missing');
  }
  const presented = new Set<string>();
  for (const s of signatures) {
    if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
      checks.legs_present = false;
      return refuse('malformed_submission');
    }
    if (presented.has(s.alg)) {
      checks.legs_present = false;
      return refuse('duplicate_algorithm', s.alg);
    }
    presented.add(s.alg);
  }
  for (const alg of IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS) {
    if (!presented.has(alg)) {
      checks.legs_present = false;
      return refuse('hybrid_leg_missing', alg);
    }
  }
  for (const alg of presented) {
    if (!(IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
      checks.legs_present = false;
      return refuse('unexpected_algorithm', alg);
    }
  }
  checks.legs_present = true;

  if (!keys || typeof keys !== 'object' || !keys.ed25519PublicKey || !keys.mldsaPublicKey) {
    return refuse('missing_key');
  }

  let messageBytes: Buffer;
  try {
    messageBytes = identifiedSubmissionV2SignedBytes(receiptHash, IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS);
  } catch {
    return refuse('malformed_receipt_hash');
  }

  // The agility module verifies Ed25519 under a base64url SPKI DER key. This
  // module has historically also accepted a raw 32-byte key, so normalize
  // through the SAME ed25519PublicKey() helper the v1 path uses rather than
  // teaching the agility module a second encoding.
  let edSpkiB64u: string;
  try {
    edSpkiB64u = ed25519PublicKey(keys.ed25519PublicKey).canonicalDer.toString('base64url');
  } catch {
    return refuse('missing_key', 'Ed25519');
  }

  const { verifyAgileSignatureSet } = await import('@emilia-protocol/verify/pq-signature-agility');
  const verificationKeys = [
    { alg: 'Ed25519', public_key: edSpkiB64u, ...(keys.ed25519KeyId ? { key_id: keys.ed25519KeyId } : {}) },
    { alg: 'ML-DSA-65', public_key: keys.mldsaPublicKey, ...(keys.mldsaKeyId ? { key_id: keys.mldsaKeyId } : {}) },
  ];

  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(messageBytes),
      signatures,
      verificationKeys,
      {
        ...(options?.mldsaBackend !== undefined ? { mldsaBackend: options.mldsaBackend } : {}),
        ...(options?.mldsaBackendLoader !== undefined ? { mldsaBackendLoader: options.mldsaBackendLoader } : {}),
        policy: 'hybrid_all',
        requiredAlgorithms: [...IDENTIFIED_SUBMISSION_V2_REQUIRED_ALGORITHMS],
      } as any,
    );
  } catch {
    checks.signatures_valid = false;
    return refuse('signature_invalid');
  }

  if (setResult?.verified === true) {
    checks.signatures_valid = true;
    return { valid: true, reason: null, failed_algorithm: null, checks };
  }

  checks.signatures_valid = false;
  const failed = Array.isArray(setResult?.results)
    ? setResult.results.find((r: any) => r?.verified !== true) ?? null
    : null;
  const failedAlgorithm = failed?.alg ?? null;
  const rawReason = String(setResult?.reason ?? '');
  if (rawReason === 'missing_required_algorithm') return refuse('hybrid_leg_missing', failedAlgorithm);
  if (rawReason.endsWith('pq_backend_unavailable') || failed?.reason === 'pq_backend_unavailable') {
    return refuse('pq_backend_unavailable', failedAlgorithm);
  }
  if (failed?.reason === 'malformed_key' || failed?.reason === 'algorithm_key_mismatch') {
    return refuse('missing_key', failedAlgorithm);
  }
  return refuse('signature_invalid', failedAlgorithm);
}

/**
 * The v2 sibling of resolveProvenanceTier(). Same downgrade discipline: a
 * claimed identified_signed tier that does not verify under the PINNED keys
 * becomes self_attested with a warning naming why. A missing ML-DSA backend
 * downgrades — it never passes on the Ed25519 leg alone.
 *
 * resolveProvenanceTier() above is untouched and stays synchronous; a caller
 * that has not adopted v2 submissions keeps its exact current behaviour.
 */
export async function resolveProvenanceTierV2(
  claimedTier: string,
  receiptHash: string,
  evidence: any,
  trustedKeys: IdentifiedSubmissionV2Keys | null | undefined,
  options: Record<string, unknown> = {},
): Promise<{ tier: string; warning?: string }> {
  if (claimedTier !== 'identified_signed') return { tier: claimedTier };

  const submission = evidence?.signature_v2;
  if (!submission) {
    return {
      tier: 'self_attested',
      warning: 'identified_signed tier claimed but no EP-IDENTIFIED-RECEIPT-SUBMISSION-v2 proof is present in evidence; downgraded to self_attested',
    };
  }
  if (!trustedKeys?.ed25519PublicKey || !trustedKeys?.mldsaPublicKey) {
    return {
      tier: 'self_attested',
      warning: 'identified_signed tier has no enrolled Ed25519 + ML-DSA-65 submitter key pair; downgraded to self_attested',
    };
  }

  const result = await verifyIdentifiedSubmissionV2(receiptHash, submission, trustedKeys, options);
  if (result.valid) return { tier: 'identified_signed' };
  return {
    tier: 'self_attested',
    warning: `identified_signed v2 signature verification failed: ${result.reason}${
      result.failed_algorithm ? ` (${result.failed_algorithm})` : ''
    }; downgraded to self_attested`,
  };
}
