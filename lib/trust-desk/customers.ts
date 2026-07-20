/**
 * AI Trust Desk — customer fixture loader + status helpers.
 *
 * @license Apache-2.0
 *
 * Week 1: customer trust pages are backed by on-disk JSON fixtures under
 * data/trust-desk/customers/. Month 2: swap to the EP event log.
 *
 * Each claim is re-signed at load time — this is cheap (HMAC) and means
 * a post-hoc edit to the underlying JSON produces different hashes.
 * That is a deliberate drift signal, not a bug.
 */

import fs from 'node:fs';
import path from 'node:path';
import { signClaim } from './hash.js';

const CUSTOMER_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'customers');

/**
 * Raw claim as stored in a customer fixture / Supabase doc. Pipeline-minted
 * claims (see minter.js) carry the stored envelope fields (claim_id,
 * payload_hash, signed_at, signer, signature); legacy fixtures leave them
 * null and get a load-time envelope instead (see hydrateCustomerDoc).
 *
 * @typedef {object} TrustDeskRawClaim
 * @property {string} id
 * @property {string} [title]
 * @property {string} [category]
 * @property {string} [source_file]
 * @property {string} [summary]
 * @property {string[]} [bullets]
 * @property {string} [policy_version]
 * @property {string|null} [content_hash]
 * @property {string|null} [claim_id]
 * @property {string|null} [payload_hash]
 * @property {string|null} [signed_at]
 * @property {string|null} [signer]
 * @property {string|null} [signature]
 */

/**
 * Raw trust-page document, as stored on disk (data/trust-desk/customers/*.json)
 * or in the Supabase trust_desk_pages row. Only the fields this module reads
 * are declared; the doc also carries buyer-facing fields (company, website,
 * contact, status, notes_for_buyer, ...) that pass through untouched via the
 * `...raw` spread in hydrateCustomerDoc.
 *
 * @typedef {object} TrustDeskRawCustomerDoc
 * @property {string} [slug]
 * @property {TrustDeskRawClaim[]} [claims]
 * @property {{expires_at?: string}} [engagement]
 * @property {string} [expires_at]
 */

/**
 * Load a single customer fixture by slug. Returns null when missing.
 *
 * Slug validation: strict `[a-z0-9][a-z0-9-]{0,63}` to prevent path traversal.
 * Signing: each claim gets a fresh signed envelope (claim_id, payload_hash,
 * signed_at, signature) on every load.
 *
 * @param {string} slug
 * @returns {object|null} hydrated customer (see hydrateCustomerDoc), or null
 */
export function loadCustomer(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) {
    return null;
  }
  const file = path.join(CUSTOMER_DIR, `${slug}.json`);
  if (!file.startsWith(CUSTOMER_DIR + path.sep)) return null;
  if (!fs.existsSync(file)) return null;

  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  return hydrateCustomerDoc(raw);
}

/**
 * Map a raw trust-page document (from disk OR Supabase) into the render shape:
 * each claim gets its signed envelope (stored if minted, else signed at load).
 * Shared by loadCustomer (file) and the Supabase page loader so both backends
 * produce identical output.
 *
 * @param {TrustDeskRawCustomerDoc} raw the stored trust-page document
 * @returns {object|null} customer with hydrated claims, or null when raw is falsy
 */
export function hydrateCustomerDoc(raw) {
  if (!raw) return null;
  const claims = (raw.claims || []).map((claim) => {
    const { id, title, category, source_file, summary, bullets, policy_version } = claim;

    // Pipeline-minted claims carry a STORED signed envelope (stable signature
    // + non-null content_hash). Prefer it so the signature a buyer verifies is
    // reproducible and time-stable. Legacy fixtures (no stored signature) are
    // signed at load time — a fresh envelope every render, which still surfaces
    // content drift via the recomputed payload hash.
    const hasStoredEnvelope = Boolean(claim.signature && claim.payload_hash && claim.signed_at);
    const envelope = hasStoredEnvelope
      ? {
          claim_id: claim.claim_id,
          payload_hash: claim.payload_hash,
          signed_at: claim.signed_at,
          signer: claim.signer || 'ai-trust-desk',
          signature: claim.signature,
        }
      : signClaim({
          claim_id_source: id,
          customer: raw.slug,
          source_file,
          content_hash: claim.content_hash,
          title,
        });

    return {
      kind: category || 'policy',
      id,
      title,
      summary,
      bullets,
      policy_version,
      content_hash: claim.content_hash ?? null,
      signature_origin: hasStoredEnvelope ? 'minted' : 'load-time',
      ...envelope,
    };
  });

  return { ...raw, claims };
}

/**
 * List available customer slugs (useful for admin pages; not exposed publicly).
 */
export function listCustomers() {
  if (!fs.existsSync(CUSTOMER_DIR)) return [];
  return fs
    .readdirSync(CUSTOMER_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
}

/**
 * Status of a trust page based on engagement.expires_at:
 *   - current:  now < expires_at - 30d
 *   - expiring: expires_at - 30d < now < expires_at
 *   - stale:    now > expires_at
 *
 * @param {TrustDeskRawCustomerDoc} [customer]
 * @returns {'unknown'|'stale'|'expiring'|'current'}
 */
export function trustPageStatus(customer) {
  const now = Date.now();
  const expiresAtStr = customer?.engagement?.expires_at || customer?.expires_at;
  const expiresAt = expiresAtStr ? new Date(expiresAtStr).getTime() : NaN;
  const msDay = 86_400_000;
  if (!expiresAt || Number.isNaN(expiresAt)) return 'unknown';
  if (now > expiresAt) return 'stale';
  if (expiresAt - now < 30 * msDay) return 'expiring';
  return 'current';
}
