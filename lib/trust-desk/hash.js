/**
 * AI Trust Desk — claim hashing and signing.
 *
 * @license Apache-2.0
 *
 * Canonicalization reuses EP's binding-layer rules so a claim hashed here
 * will match the hash computed by the EP commit pipeline when we swap the
 * HMAC signature for a real EP Commit receipt in month 1.
 *
 *   - strings NFC-normalized
 *   - object keys deep-sorted at every nesting level
 *   - non-finite numbers rejected
 *   - undefined / functions rejected
 *
 * Today's signing path is HMAC-SHA256 keyed by ATD_SIGNING_KEY (env).
 * Month 1 target: replace the `signature` field with an EP binding_hash
 * and a pointer into the EP event log — envelope shape stays stable.
 */

import crypto from 'node:crypto';
import { sha256 } from '@/lib/crypto';

// ── Canonicalization ───────────────────────────────────────────────────────

/**
 * Canonicalize a value for deterministic hashing.
 * Mirrors lib/handshake/binding.js:deepSortKeys exactly.
 */
function canonicalize(value) {
  if (value === null) return null;
  if (value === undefined) {
    throw new Error('CANONICALIZATION_ERROR: undefined cannot be canonicalized');
  }
  if (typeof value === 'function') {
    throw new Error('CANONICALIZATION_ERROR: functions cannot be canonicalized');
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`CANONICALIZATION_ERROR: non-finite number ${value}`);
    }
    return value;
  }
  if (typeof value === 'string') {
    return value.normalize('NFC');
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value === 'object') {
    const sortedKeys = Object.keys(value).sort();
    const out = {};
    for (const k of sortedKeys) out[k.normalize('NFC')] = canonicalize(value[k]);
    return out;
  }
  return value;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Hash a JSON-serializable claim object. Returns hex.
 */
export function hashClaim(claim) {
  return sha256(JSON.stringify(canonicalize(claim)));
}

/**
 * Hash a plain-text policy document. Normalizes line endings and trailing
 * whitespace before hashing so CRLF vs LF doesn't produce different hashes.
 */
export function hashText(text) {
  const normalized = String(text)
    .replace(/\r\n/g, '\n')
    .replace(/\s+$/gm, '')
    .normalize('NFC');
  return sha256(normalized);
}

/**
 * Generate a short, human-readable claim ID from a claim hash.
 * Format: `clm_<first-12-chars-hex>`. Deterministic, safe for URLs.
 */
export function claimId(hashHex) {
  if (!/^[0-9a-f]{64}$/.test(hashHex)) {
    throw new Error('claimId expects a 64-char hex sha256');
  }
  return `clm_${hashHex.slice(0, 12)}`;
}

/**
 * Build a signed claim envelope. Today the signature is an HMAC-SHA256
 * keyed by ATD_SIGNING_KEY. In month 1 this is replaced by an EP
 * Commit receipt — envelope shape is stable across the migration.
 *
 * @param {object} claim - The claim payload to sign.
 * @param {string} [signingKey] - Override key (defaults to env).
 * @returns {{
 *   claim_id: string,
 *   payload_hash: string,
 *   signed_at: string,
 *   signer: string,
 *   signature: string,
 * }}
 */
export function signClaim(claim, signingKey = process.env.ATD_SIGNING_KEY) {
  if (!signingKey) {
    throw new Error('ATD_SIGNING_KEY not set — cannot sign claims');
  }
  const canonical = JSON.stringify(canonicalize(claim));
  const payload_hash = sha256(canonical);
  const signed_at = new Date().toISOString();
  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(`${payload_hash}.${signed_at}`, 'utf8')
    .digest('hex');
  return {
    claim_id: claimId(payload_hash),
    payload_hash,
    signed_at,
    signer: 'ai-trust-desk',
    signature,
  };
}
