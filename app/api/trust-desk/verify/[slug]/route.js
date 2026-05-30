/**
 * GET /api/trust-desk/verify/[slug]
 *
 * @license Apache-2.0
 *
 * Buyer-facing verification endpoint. Re-derives every cryptographic binding
 * on a published trust page server-side and returns pass/fail per claim. This
 * is what makes "buyer-verifiable" real: a buyer (or their security tooling)
 * can hit this endpoint and confirm the page they're reading is intact and
 * signed by the Trust Desk key.
 *
 * Optional ?claim_id= filters to a single claim.
 */

import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors';
import { signingKeyFingerprint } from '@/lib/trust-desk/signing';
import { verifyPublishedPage } from '@/lib/trust-desk/page-verify';

export const dynamic = 'force-dynamic';

export async function GET(request, { params }) {
  const { slug } = await params;
  const result = verifyPublishedPage(slug);
  if (!result.found) return epProblem(404, 'not_found', 'trust page not found');

  const url = new URL(request.url);
  const claimId = url.searchParams.get('claim_id');

  let claims = result.claims;
  if (claimId) {
    claims = claims.filter((c) => c.claim_id === claimId || c.id === claimId);
    if (claims.length === 0) return epProblem(404, 'claim_not_found', 'claim not found on this page');
  }

  let fingerprint = null;
  try {
    fingerprint = signingKeyFingerprint();
  } catch {
    /* production without key — fingerprint omitted */
  }

  return NextResponse.json(
    {
      slug: result.slug,
      company: result.company,
      verified: claimId ? claims.every((c) => c.passed) : result.ok,
      signing_key_fingerprint: fingerprint,
      verify_method: 'HMAC-SHA256 over canonical claim envelope; content bound by SHA-256',
      claim_count: result.claim_count,
      claims,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
