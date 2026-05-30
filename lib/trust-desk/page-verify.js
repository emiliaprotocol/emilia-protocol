/**
 * AI Trust Desk — published trust-page verifier (shared).
 *
 * @license Apache-2.0
 *
 * Single source of truth for "is this published claim intact?", used by both
 * the CLI (scripts/td-verify.mjs) and the buyer-facing verify endpoint
 * (/api/trust-desk/verify/[slug]). Re-derives every binding from the published
 * artifacts on disk:
 *
 *   content_integrity : content_hash === hash(published artifact)
 *   payload_binding    : payload_hash === hash(canonical claim envelope)
 *   signature          : HMAC(key, payload_hash.signed_at) === signature
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { hashText, hashClaim } from './hash.js';
import { getSigningKey } from './signing.js';

const CUSTOMER_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'customers');

/**
 * Verify every claim on a published trust page.
 * @param {string} slug
 * @returns {{found:boolean, slug:string, company?:string, ok?:boolean, claims?:Array}}
 */
export function verifyPublishedPage(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) {
    return { found: false, slug };
  }
  const file = path.join(CUSTOMER_DIR, `${slug}.json`);
  if (!file.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(file)) {
    return { found: false, slug };
  }

  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  let key = null;
  try {
    key = getSigningKey();
  } catch {
    /* signature check reported as unavailable */
  }

  const claims = (doc.claims || []).map((claim) => {
    const checks = {};

    // 1. content integrity
    const artifact = readArtifact(claim);
    if (artifact == null) {
      checks.content_integrity = { ok: false, detail: 'artifact missing' };
    } else {
      const recomputed =
        claim.category === 'questionnaire' ? hashClaim(artifact) : hashText(artifact);
      checks.content_integrity = {
        ok: recomputed === claim.content_hash,
        detail: recomputed === claim.content_hash ? 'verified' : 'hash mismatch',
      };
    }

    // 2. payload binding
    const payloadHash = hashClaim({
      claim_id_source: claim.id,
      customer: doc.slug,
      source_file: claim.source_file,
      content_hash: claim.content_hash,
      title: claim.title,
    });
    checks.payload_binding = {
      ok: payloadHash === claim.payload_hash,
      detail: payloadHash === claim.payload_hash ? 'verified' : 'payload mismatch',
    };

    // 3. signature
    if (key) {
      const expected = crypto
        .createHmac('sha256', key)
        .update(`${claim.payload_hash}.${claim.signed_at}`, 'utf8')
        .digest('hex');
      checks.signature = {
        ok: expected === claim.signature,
        detail: expected === claim.signature ? 'verified' : 'HMAC mismatch',
      };
    } else {
      checks.signature = { ok: null, detail: 'signing key unavailable' };
    }

    const passed = Object.values(checks).every((c) => c.ok !== false);
    return {
      id: claim.id,
      claim_id: claim.claim_id,
      title: claim.title,
      category: claim.category,
      content_hash: claim.content_hash,
      payload_hash: claim.payload_hash,
      signed_at: claim.signed_at,
      signer: claim.signer,
      checks,
      passed,
    };
  });

  return {
    found: true,
    slug,
    company: doc.company,
    ok: claims.every((c) => c.passed),
    claim_count: claims.length,
    claims,
  };
}

function readArtifact(claim) {
  const p = path.join(CUSTOMER_DIR, claim.source_file || '');
  // Confine to the customer dir (defense against crafted source_file).
  if (!p.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, 'utf8');
  if (claim.category === 'questionnaire') {
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  return raw;
}
