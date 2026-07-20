/**
 * AI Trust Desk — identifier + slug generation.
 *
 * @license Apache-2.0
 *
 * engagement_id  → `eng_<24-hex>`  pipeline-internal handle
 * customer slug  → url-safe, derived from company name + a short hash of the
 *                  engagement id for uniqueness. MUST satisfy the customer
 *                  loader's strict regex `^[a-z0-9][a-z0-9-]{0,63}$`
 *                  (see lib/trust-desk/customers.js).
 */

import crypto from 'node:crypto';
import { sha256 } from '../crypto.js';

/** @returns {string} `eng_` + 24 hex chars (96 bits). */
export function newEngagementId() {
  return `eng_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Derive a stable, url-safe customer slug.
 *
 * Deterministic given (company, engagementId): same inputs → same slug, so a
 * retried pipeline run targets the same trust page instead of orphaning a new
 * one. The 6-char hash suffix prevents collisions between two customers with
 * the same company name.
 *
 * @param {string} company
 * @param {string} engagementId
 * @returns {string} slug matching ^[a-z0-9][a-z0-9-]{0,63}$
 */
export function deriveSlug(company, engagementId) {
  const base = String(company || 'customer')
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-') // non-alnum → hyphen
    .replace(/^-+|-+$/g, '') // trim hyphens
    .slice(0, 40)
    .replace(/-+$/g, ''); // re-trim after slice

  const safeBase = base && /^[a-z0-9]/.test(base) ? base : `c-${base}`;
  const suffix = sha256(engagementId).slice(0, 6);
  const slug = `${safeBase}-${suffix}`.slice(0, 64).replace(/-+$/g, '');

  // Final guard: if anything produced an invalid leading char, prefix.
  return /^[a-z0-9]/.test(slug) ? slug : `t-${suffix}`;
}

/**
 * Build a deterministic claim id from a payload hash.
 * Mirrors lib/trust-desk/hash.js:claimId so verify endpoints agree.
 * @param {string} hashHex 64-char sha256 hex
 */
export function shortClaimId(hashHex) {
  return `clm_${String(hashHex).slice(0, 12)}`;
}
