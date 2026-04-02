/**
 * EP Handshake — Claim normalization.
 *
 * Pure functions that normalize raw presentations into internal format.
 * Provides canonical claim vocabulary and deterministic normalization
 * to address audit issue #8 (claim normalization under-done).
 *
 * @license Apache-2.0
 */

import { sha256 } from './invariants.js';

// ── Canonical Claim Vocabulary (v1) ─────────────────────────────────────────

/**
 * Fixed set of claim keys that policy rules reference.
 * Only these keys survive normalization — everything else is dropped.
 */
export const CANONICAL_CLAIMS = {
  // Identity claims
  legal_entity: 'legal_entity',
  legal_name: 'legal_name',
  authorized_signer: 'authorized_signer',

  // Compliance claims
  sanctions_screened: 'sanctions_screened',
  aml_verified: 'aml_verified',
  kyc_verified: 'kyc_verified',

  // Authority claims
  role_authority: 'role_authority',
  delegation_proof: 'delegation_proof',
};

const CANONICAL_SET = new Set(Object.keys(CANONICAL_CLAIMS));

// ── Synonym / Alias Map ─────────────────────────────────────────────────────

/**
 * Maps common alternative key names to their canonical form.
 * Keys here are lowercase, trimmed versions of potential raw inputs.
 */
const SYNONYM_MAP = {
  legalentity: 'legal_entity',
  legal_entity: 'legal_entity',
  legalname: 'legal_name',
  legal_name: 'legal_name',
  authorizedsigner: 'authorized_signer',
  authorized_signer: 'authorized_signer',
  sanctionsscreened: 'sanctions_screened',
  sanctions_screened: 'sanctions_screened',
  amlverified: 'aml_verified',
  aml_verified: 'aml_verified',
  kycverified: 'kyc_verified',
  kyc_verified: 'kyc_verified',
  roleauthority: 'role_authority',
  role_authority: 'role_authority',
  delegationproof: 'delegation_proof',
  delegation_proof: 'delegation_proof',
};

// ── Boolean Coercion ────────────────────────────────────────────────────────

const TRUTHY_STRINGS = new Set(['yes', 'true', '1']);
const FALSY_STRINGS = new Set(['no', 'false', '0']);

/**
 * Coerce boolean-like values to actual booleans.
 * Non-boolean-like values pass through unchanged.
 */
function coerceBooleanLike(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    const lower = value.trim().toLowerCase();
    if (TRUTHY_STRINGS.has(lower)) return true;
    if (FALSY_STRINGS.has(lower)) return false;
  }
  return value;
}

// ── Normalization ───────────────────────────────────────────────────────────

/**
 * Resolve a raw key to its canonical form, or null if unknown.
 *  - Lowercases and trims whitespace
 *  - Strips dots (flattening nested paths like `identity.legal_name`)
 *  - Checks synonym map
 */
function resolveKey(rawKey) {
  /* c8 ignore next -- callers always pass String(role); non-string guard is defensive */
  if (typeof rawKey !== 'string') return null;

  // Lowercase, trim, take the last segment if dotted (e.g. identity.legal_name → legal_name)
  let key = rawKey.trim().toLowerCase();
  const dotIdx = key.lastIndexOf('.');
  if (dotIdx >= 0) {
    key = key.slice(dotIdx + 1).trim();
  }
  // Remove remaining underscores for synonym lookup if direct lookup fails
  const canonical = SYNONYM_MAP[key];
  if (canonical) return canonical;
  // Try without underscores
  const stripped = key.replace(/_/g, '');
  return SYNONYM_MAP[stripped] || null;
}

/**
 * Normalize raw presentation claims to canonical form.
 *
 * - Handles common synonyms and variant key formats
 * - Handles boolean-like string values ('yes', 'true', '1')
 * - Handles nested structures via dot-path flattening
 * - Expands `roles` array entries into individual boolean claims
 * - Lowercases all keys, strips whitespace
 * - Returns ONLY canonical claim keys — drops unknown keys
 * - Output is deterministic (sorted keys)
 *
 * @param {Record<string, unknown>} rawClaims
 * @returns {Record<string, unknown>} normalized claims with only canonical keys
 */
export function normalizeClaims(rawClaims) {
  if (!rawClaims || typeof rawClaims !== 'object' || Array.isArray(rawClaims)) {
    return {};
  }

  const result = {};

  for (const [rawKey, rawValue] of Object.entries(rawClaims)) {
    // Special handling for `roles` array: expand each entry into a boolean claim
    const keyLower = rawKey.trim().toLowerCase();
    if (keyLower === 'roles' && Array.isArray(rawValue)) {
      for (const role of rawValue) {
        const canonical = resolveKey(String(role));
        if (canonical) {
          result[canonical] = true;
        }
      }
      continue;
    }

    const canonical = resolveKey(rawKey);
    if (!canonical) continue; // drop unknown keys

    result[canonical] = coerceBooleanLike(rawValue);
  }

  // Deterministic output: sorted keys
  const sorted = {};
  for (const key of Object.keys(result).sort()) {
    sorted[key] = result[key];
  }
  return sorted;
}

// ── Canonical Hashing ───────────────────────────────────────────────────────

/**
 * Produce a deterministic SHA-256 hash of normalized claims.
 * Claims are JSON-serialized with sorted keys to ensure determinism.
 *
 * @param {Record<string, unknown>} normalizedClaims — already-normalized claims
 * @returns {string} hex-encoded SHA-256 hash
 */
export function claimsToCanonicalHash(normalizedClaims) {
  const stable = JSON.stringify(normalizedClaims || {}, Object.keys(normalizedClaims || {}).sort());
  return sha256(stable);
}

// ── Legacy / Backward Compat ────────────────────────────────────────────────

/**
 * Compute a presentation hash from presentation data.
 */
export function computePresentationHash(data) {
  return sha256(
    typeof data === 'string' ? data : JSON.stringify(data),
  );
}
