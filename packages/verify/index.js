/**
 * @emilia-protocol/verify — Zero-Dependency Trust Verification
 *
 * Verify EP trust receipts, Merkle anchors, and commitment proofs
 * using ONLY Node.js built-in crypto. No EP infrastructure required.
 *
 * This is the core primitive that makes EP a protocol, not an API.
 * Anyone can verify. No account. No API key. Just math.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

// =============================================================================
// CONSTANTS
// =============================================================================

const SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'];
const SUPPORTED_PROOF_VERSIONS = ['EP-PROOF-v1'];

// =============================================================================
// PRIMITIVES
// =============================================================================

function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// Recursive canonical JSON — depth-first key sort at every level.
//
// The previous implementation
//
//   JSON.stringify(obj, Object.keys(obj).sort())
//
// was a SHALLOW canonicalization. The second argument to JSON.stringify
// in array form is a property allowlist filter, NOT a sort order, and it
// does NOT recurse into nested objects to enforce key order at depth.
// Worse, it filters nested keys to only those names present in the
// top-level allowlist.
//
// Net effect of the shallow pattern: a verifier and a signer that both
// "sort keys before signing" could compute different canonical bytes for
// the same logical document, producing a false-negative signature
// failure. And nested fields (e.g. claim.context.risk_signals or
// claim.context.change.after_bank_hash) were not deterministically
// included in the signed material under the shallow algorithm.
//
// The fix below is the same recursive canonicalize() used by
// lib/guard-policies.js (hashCanonicalAction) on the server side, so
// signer and verifier produce byte-identical canonical material for any
// arbitrarily-nested object.
//
// Bug history: shipped in 1.0.0, fixed in 1.0.1. See package.json.
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashPair(a, b) {
  const sorted = [a, b].sort();
  return sha256(sorted[0] + sorted[1]);
}

// =============================================================================
// RECEIPT VERIFICATION
// =============================================================================

/**
 * Verify an EP receipt document.
 *
 * Performs up to three independent checks:
 *   1. Version — document format is EP-RECEIPT-v1
 *   2. Signature — Ed25519 over the canonical payload
 *   3. Anchor (if present) — Merkle proof reconstructs the claimed root
 *
 * @param {object} doc - EP receipt document (EP-RECEIPT-v1)
 * @param {string} publicKeyBase64url - Signer's Ed25519 public key (base64url SPKI DER)
 * @returns {{ valid: boolean, checks: { version: boolean, signature: boolean, anchor: boolean|null }, error?: string }}
 */
export function verifyReceipt(doc, publicKeyBase64url) {
  const checks = { version: false, signature: false, anchor: null };

  if (!doc?.['@version'] || !SUPPORTED_VERSIONS.includes(doc['@version'])) {
    return { valid: false, checks, error: `Unsupported version: ${doc?.['@version']}` };
  }
  checks.version = true;

  if (!doc.payload || !doc.signature?.value || !doc.signature?.algorithm) {
    return { valid: false, checks, error: 'Missing payload or signature' };
  }

  try {
    const payloadBytes = Buffer.from(canonicalize(doc.payload), 'utf8');
    const publicKeyDer = Buffer.from(publicKeyBase64url, 'base64url');
    const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    const sigBytes = Buffer.from(doc.signature.value, 'base64url');
    checks.signature = crypto.verify(null, payloadBytes, keyObject, sigBytes);
  } catch (e) {
    return { valid: false, checks, error: `Signature verification failed: ${e.message}` };
  }

  if (doc.anchor?.merkle_proof && doc.anchor?.leaf_hash && doc.anchor?.merkle_root) {
    checks.anchor = verifyMerkleAnchor(doc.anchor.leaf_hash, doc.anchor.merkle_proof, doc.anchor.merkle_root);
  }

  const valid = checks.version && checks.signature && (checks.anchor === null || checks.anchor === true);
  return { valid, checks };
}

// =============================================================================
// MERKLE ANCHOR VERIFICATION
// =============================================================================

/**
 * Verify a Merkle inclusion proof.
 *
 * @param {string} leafHash - hex SHA-256 of the receipt
 * @param {Array<{hash: string, position: 'left'|'right'}>} proof - proof steps
 * @param {string} expectedRoot - hex expected Merkle root
 * @returns {boolean}
 */
export function verifyMerkleAnchor(leafHash, proof, expectedRoot) {
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  if (proof.length > 20) return false;

  let current = leafHash;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string') return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
    current = step.position === 'left' ? hashPair(step.hash, current) : hashPair(current, step.hash);
  }

  return current === expectedRoot;
}

// =============================================================================
// COMMITMENT PROOF VERIFICATION
// =============================================================================

/**
 * Verify an EP commitment proof.
 *
 * @param {object} proof - EP commitment proof document (EP-PROOF-v1)
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @returns {{ valid: boolean, claim: object, error?: string }}
 */
export function verifyCommitmentProof(proof, publicKeyBase64url) {
  if (!proof?.['@version'] || !SUPPORTED_PROOF_VERSIONS.includes(proof['@version'])) {
    return { valid: false, claim: null, error: `Unsupported version: ${proof?.['@version']}` };
  }

  if (proof.expires_at && new Date(proof.expires_at) < new Date()) {
    return { valid: false, claim: proof.claim, error: 'Proof has expired' };
  }

  if (publicKeyBase64url && proof.signature) {
    try {
      const commitmentBytes = Buffer.from(canonicalize(proof.commitment), 'utf8');
      const publicKeyDer = Buffer.from(publicKeyBase64url, 'base64url');
      const keyObject = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
      const sigBytes = Buffer.from(proof.signature.value, 'base64url');
      if (!crypto.verify(null, commitmentBytes, keyObject, sigBytes)) {
        return { valid: false, claim: proof.claim, error: 'Invalid signature' };
      }
    } catch (e) {
      return { valid: false, claim: proof.claim, error: `Signature check failed: ${e.message}` };
    }
  }

  return { valid: true, claim: proof.claim };
}

// =============================================================================
// BUNDLE VERIFICATION
// =============================================================================

/**
 * Verify an EP receipt bundle.
 *
 * @param {object} bundle - EP-BUNDLE-v1 format
 * @param {string} publicKeyBase64url - Entity's Ed25519 public key
 * @returns {{ valid: boolean, total: number, verified: number, failed: string[] }}
 */
export function verifyReceiptBundle(bundle, publicKeyBase64url) {
  if (bundle?.['@version'] !== 'EP-BUNDLE-v1') {
    return { valid: false, total: 0, verified: 0, failed: ['Invalid bundle version'] };
  }

  const failed = [];
  let verified = 0;

  for (let i = 0; i < bundle.documents.length; i++) {
    const result = verifyReceipt(bundle.documents[i], publicKeyBase64url);
    if (result.valid) verified++;
    else failed.push(`doc[${i}]: ${result.error || 'verification failed'}`);
  }

  return { valid: failed.length === 0, total: bundle.documents.length, verified, failed };
}
