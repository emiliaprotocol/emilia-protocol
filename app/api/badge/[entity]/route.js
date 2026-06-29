// SPDX-License-Identifier: Apache-2.0
/**
 * GET /api/badge/[entity]
 * @license Apache-2.0
 *
 * The EMILIA CAPABILITY badge — a verifiable shield, NOT a score.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  WHAT THIS IS                                                  capability badge
 * ──────────────────────────────────────────────────────────────────────────
 *
 * EMILIA's thesis is "portable evidence, not another score" (see
 * docs/positioning/EYE_VS_EP.md — "Eye does not maintain reputation scores,
 * trust indices, or cumulative risk assessments"). This badge therefore
 * asserts exactly ONE thing, and it is a *capability*, not an opinion:
 *
 *     "EMILIA · authorization receipts: ON — verify →"
 *
 * "ON" means: a real, cryptographically verifiable EP-RECEIPT-v1 authorization
 * receipt exists for this entity, signed by its issuer key. That is a fact the
 * viewer can independently re-derive — it is not an EMILIA-vouched judgement.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  HOUSE RULES THIS ENDPOINT OBEYS
 * ──────────────────────────────────────────────────────────────────────────
 *
 *  These rules scope to THIS badge surface (and the ?view=capability projection
 *  it reads). Full /api/trust/profile access is authenticated and self-scoped;
 *  public callers get only this deliberately minimal capability view.
 *
 *  • NO score on this surface. No 0–100, no reputation index, no ranking number.
 *    (And no 0–100 score is emitted on ANY path — the legacy compat_score was
 *    retired from the wire.)
 *  • NO volume leak via the badge. We never render receipt counts, submitter
 *    counts, dollar amounts, or any per-entity transaction volume here. The
 *    capability is rendered as a boolean ("ON" / "—"), derived from
 *    `receiptCount > 0`, and the count itself never crosses the wire via the badge.
 *  • EVERY factual element is independently re-derivable by the viewer:
 *      1. Capability presence  → GET /api/trust/profile/:entity?view=capability
 *      2. A real receipt       → GET /api/verify/:receiptId        (public)
 *      3. Offline crypto check → /verify  (Ed25519, client-side, no server trust)
 *    The verification path is encoded in the SVG (<metadata> + aria-label) and
 *    documented in docs/TRUST-BADGE.md.
 *  • Eye's law preserved: this badge is an advisory marker. It NEVER authorizes
 *    an action and is NEVER a gate. It only points at evidence.
 *
 * Optional query params:
 *   ?format=svg|json   (default: svg)
 *
 * No auth. Public read. Cache-friendly (immutable-ish, short s-maxage).
 */

import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';

// Brand tokens duplicated as literals (SVG must be self-contained — no JS theme
// vars survive into a cached <img>). Matches lib/tokens.js: ink, gold, green.
const INK = '#0C0A09';
const GOLD = '#B08D35';
const GREEN = '#16A34A';
const MUTED = '#78716C';

const PUBLIC_BASE =
  process.env.NEXT_PUBLIC_BASE_URL ||
  process.env.NEXT_PUBLIC_SITE_URL ||
  'https://www.emiliaprotocol.ai';

// Cache headers: a capability flips rarely. Let CDNs and <img> caches hold it
// for a few minutes, serve stale while revalidating. Never private data, so a
// shared cache is safe.
const CACHE_HEADERS = {
  'Cache-Control': 'public, max-age=120, s-maxage=300, stale-while-revalidate=600',
};

/**
 * Escape the five XML-significant characters so an entity slug can never break
 * out of an attribute or inject markup into the SVG. (Entity ids are already
 * constrained upstream, but the badge is a public, embeddable surface — defence
 * in depth against a malformed/hostile id.)
 */
function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Approximate text width for a Verdana-ish 11px label so the two-tone shield
 * auto-sizes to its content. Shields.io uses the same trick; exactness is not
 * required, only "no clipping".
 */
function approxWidth(text, perChar = 6.2, pad = 10) {
  return Math.ceil(text.length * perChar) + pad * 2;
}

/**
 * Resolve the ONE fact this badge is allowed to assert:
 *   capabilityOn = "a verifiable authorization receipt exists for this entity"
 *
 * Derived from the canonical evaluator — the same trust brain used by
 * /api/trust/profile, pre-action enforcement, and MCP. We read ONLY the
 * boolean presence of receipts / historical establishment. We deliberately
 * discard receiptCount, uniqueSubmitters, score, and confidence here so they
 * cannot leak into the rendered badge.
 */
async function resolveCapability(entityId) {
  const result = await canonicalEvaluate(entityId, {
    includeDisputes: false,
    includeEstablishment: true,
  });

  if (!result || result.error) {
    return { found: false, capabilityOn: false };
  }

  // Boolean only. A receipt exists (current OR historically established) ⇒ a
  // viewer can pull one and verify it. We collapse to a bit on purpose.
  const hasReceipt =
    (result.receiptCount || 0) > 0 ||
    result.establishment?.established === true ||
    (result.establishment?.total_receipts || 0) > 0;

  return {
    found: true,
    capabilityOn: Boolean(hasReceipt),
    displayName: result.display_name || result.entity_id || entityId,
  };
}

function renderSvg({ entityId, capabilityOn }) {
  const left = 'EMILIA';
  // The capability claim. ON ⇒ a verifiable receipt exists. Otherwise we show a
  // neutral "—" rather than any negative/score-like signal.
  const value = capabilityOn ? 'authorization receipts: ON' : 'authorization receipts: —';
  const valueColor = capabilityOn ? GREEN : MUTED;

  const lw = approxWidth(left, 6.4, 9);
  const rw = approxWidth(value, 6.2, 12);
  const total = lw + rw;
  const h = 22;
  const lcx = lw / 2;
  const rcx = lw + rw / 2;

  // The independently-re-derivable verification path, carried with the artifact.
  const profileUrl = `${PUBLIC_BASE}/api/trust/profile/${encodeURIComponent(entityId)}?view=capability`;
  const verifyUrl = `${PUBLIC_BASE}/verify`;
  const claim = capabilityOn
    ? `EMILIA capability: a verifiable authorization receipt (EP-RECEIPT-v1) exists for this entity. Re-derive: ${profileUrl} then verify a real receipt at ${verifyUrl}. This is a capability, not a score — no ranking, no counts, no volume.`
    : `EMILIA capability: no verifiable authorization receipt found for this entity. Re-derive: ${profileUrl}. This is a capability check, not a score.`;

  const ariaLabel = capabilityOn
    ? `EMILIA authorization receipts: ON — verify`
    : `EMILIA authorization receipts: not found`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${h}" role="img" aria-label="${xmlEscape(ariaLabel)}">
  <title>${xmlEscape(ariaLabel)}</title>
  <metadata>${xmlEscape(claim)}</metadata>
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="${h}" fill="${INK}"/>
    <rect x="${lw}" width="${rw}" height="${h}" fill="#FAFAF9"/>
    <rect width="${total}" height="${h}" fill="url(#g)"/>
  </g>
  <g font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lcx}" y="16" text-anchor="middle" fill="#010101" fill-opacity=".3">${xmlEscape(left)}</text>
    <text x="${lcx}" y="15" text-anchor="middle" fill="${GOLD}">${xmlEscape(left)}</text>
    <text x="${rcx}" y="16" text-anchor="middle" fill="#010101" fill-opacity=".15">${xmlEscape(value)}</text>
    <text x="${rcx}" y="15" text-anchor="middle" fill="${valueColor}">${xmlEscape(value)}</text>
  </g>
</svg>`;
}

// Constant-time floor for the capability resolution. Entity existence is already
// public (profile/search), so this is belt-and-suspenders, but pinning every
// response to the same minimum latency removes the exists-vs-not timing signal.
const BADGE_MIN_MS = 60;

export async function GET(request, { params }) {
  const { entity } = await params;
  const format = (request.nextUrl.searchParams.get('format') || 'svg').toLowerCase();

  const startedAt = Date.now();
  let cap;
  try {
    cap = await resolveCapability(entity);
  } catch {
    // Fail closed to a neutral badge — never error a public <img> with private
    // detail, never assert a capability we could not confirm.
    cap = { found: false, capabilityOn: false };
  }
  const elapsed = Date.now() - startedAt;
  if (elapsed < BADGE_MIN_MS) {
    await new Promise((r) => setTimeout(r, BADGE_MIN_MS - elapsed));
  }

  if (format === 'json') {
    // Machine-readable, still leak-free: a boolean capability + the public,
    // independently-checkable verification path. No counts, no score.
    return NextResponse.json(
      {
        entity_id: entity,
        capability: 'authorization_receipts',
        // The single asserted fact, as a boolean. Never a number.
        capability_on: cap.capabilityOn,
        claim: cap.capabilityOn
          ? 'A verifiable EP-RECEIPT-v1 authorization receipt exists for this entity.'
          : 'No verifiable authorization receipt found for this entity.',
        // How the viewer re-derives the claim — no internal URL templates in
        // this public JSON surface.
        verify: {
          verifier: `${PUBLIC_BASE}/verify`,
          receipt_id_required: true,
        },
        _note:
          'Capability, not score. No 0-100, no ranking, no counts, no transaction volume. ' +
          'Every element is independently re-derivable by the viewer.',
        _protocol_version: 'EP/1.1-v2',
      },
      { headers: CACHE_HEADERS }
    );
  }

  const svg = renderSvg({ entityId: entity, capabilityOn: cap.capabilityOn });

  return new NextResponse(svg, {
    status: 200,
    headers: {
      ...CACHE_HEADERS,
      'Content-Type': 'image/svg+xml; charset=utf-8',
      // The SVG is static markup with no scripts; lock it down anyway since it
      // renders cross-origin inside arbitrary pages.
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
    },
  });
}
