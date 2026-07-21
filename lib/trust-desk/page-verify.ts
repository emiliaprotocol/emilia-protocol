/**
 * AI Trust Desk — published trust-page verifier (shared).
 *
 * @license Apache-2.0
 *
 * Single source of truth for "is this published claim intact?", used by the CLI
 * (sync, file backend) and the buyer-facing verify endpoint (async, any
 * backend). Re-derives every binding from the published artifacts:
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
import { getPublishedPage } from './page-store.js';

const CUSTOMER_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'customers');

// ── Result shape ────────────────────────────────────────────────────────────

type PageVerifyChecks = {
  content_integrity: { ok: boolean; detail: string };
  payload_binding: { ok: boolean; detail: string };
  signature: { ok: boolean | null; detail: string };
};

type PageVerifyClaim = {
  id: any;
  claim_id: any;
  title: any;
  category: any;
  content_hash: any;
  payload_hash: any;
  signed_at: any;
  signer: any;
  checks: PageVerifyChecks;
  passed: boolean;
};

type PageVerifyFound = {
  found: true;
  slug: any;
  company: any;
  ok: boolean;
  claim_count: number;
  claims: PageVerifyClaim[];
};

type PageVerifyResult = { found: false; slug: string } | PageVerifyFound;

/**
 * Sync, file-backend verification (used by the CLI). For the server/API or the
 * Supabase backend, use verifyPublishedPageAsync.
 */
export function verifyPublishedPage(slug): PageVerifyResult {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) {
    return { found: false, slug };
  }
  const file = path.join(CUSTOMER_DIR, `${slug}.json`);
  if (!file.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(file)) {
    return { found: false, slug };
  }
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const getArtifact = (sourceFile) => {
    const p = path.join(CUSTOMER_DIR, sourceFile || '');
    if (!p.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(p)) return null;
    return fs.readFileSync(p, 'utf8');
  };
  return verifyDoc(doc, getArtifact);
}

/**
 * Backend-agnostic verification (file or Supabase). Used by the verify endpoint.
 */
export async function verifyPublishedPageAsync(slug): Promise<PageVerifyResult> {
  const page = await getPublishedPage(slug);
  if (!page) return { found: false, slug };
  return verifyDoc(page.raw, page.getArtifact);
}

// ── Core ────────────────────────────────────────────────────────────────────

function verifyDoc(doc, getArtifact): PageVerifyFound {
  let key: string | null = null;
  try {
    key = getSigningKey();
  } catch {
    /* signature check reported as unavailable */
  }

  const claims = (doc.claims || []).map((claim) => {
    const checks = {} as PageVerifyChecks;

    // 1. content integrity
    const raw = getArtifact(claim.source_file);
    if (raw == null) {
      checks.content_integrity = { ok: false, detail: 'artifact missing' };
    } else {
      const recomputed =
        claim.category === 'questionnaire' ? hashClaim(safeJson(raw)) : hashText(raw);
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
    slug: doc.slug,
    company: doc.company,
    ok: claims.every((c) => c.passed),
    claim_count: claims.length,
    claims,
  };
}

function safeJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}
