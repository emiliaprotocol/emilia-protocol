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
 * Load a single customer fixture by slug. Returns null when missing.
 *
 * Slug validation: strict `[a-z0-9][a-z0-9-]{0,63}` to prevent path traversal.
 * Signing: each claim gets a fresh signed envelope (claim_id, payload_hash,
 * signed_at, signature) on every load.
 */
export function loadCustomer(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) {
    return null;
  }
  const file = path.join(CUSTOMER_DIR, `${slug}.json`);
  if (!file.startsWith(CUSTOMER_DIR + path.sep)) return null;
  if (!fs.existsSync(file)) return null;

  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));

  const claims = (raw.claims || []).map((claim) => {
    // Sign each claim at load time. Trust page always shows fresh signatures.
    // If the fixture has been edited since last_rehashed, the new hash will
    // differ from the stored content_hash — rendering surfaces that mismatch
    // so reviewers can catch drift.
    const { id, title, category, source_file, summary, bullets, policy_version } = claim;
    const envelope = signClaim({
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
