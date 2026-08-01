/**
 * GET  /api/trust-desk/review/[engagementId] - the prepared packet, for review
 * POST /api/trust-desk/review/[engagementId] - approve or reject it
 *
 * @license Apache-2.0
 *
 * The human sign-off boundary. Answers prepared by the pipeline sit at
 * `awaiting_review` and reach a buyer only when a named reviewer approves them
 * here. Both routes require an internal session: the GET returns full answer
 * text, which is customer material and never public.
 *
 * A rejection is recorded the same way an approval is, so a decision not to
 * publish leaves the same trail as a decision to publish.
 */

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getEngagement, STATUS } from '@/lib/trust-desk/store';
import { publishReviewed, rejectReviewed } from '@/lib/trust-desk/pipeline';
import { authenticateTrustDeskReviewer, TRUST_DESK_SESSION_COOKIE } from '@/lib/trust-desk/auth';

export const dynamic = 'force-dynamic';

function reviewerSession(request: NextRequest) {
  return authenticateTrustDeskReviewer(request.cookies.get(TRUST_DESK_SESSION_COOKIE)?.value);
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ engagementId: string }> }
): Promise<NextResponse> {
  if (!reviewerSession(request)) return epProblem(401, 'unauthorized', 'internal reviewer session required');

  const { engagementId } = await params;
  const eng = await getEngagement(engagementId);
  if (!eng) return epProblem(404, 'not_found', 'engagement not found');

  return NextResponse.json({
    engagement_id: eng.engagement_id,
    company: eng.intake?.company || null,
    status: eng.status,
    awaiting_review: eng.status === STATUS.AWAITING_REVIEW,
    slug: eng.slug || null,
    prepared_at: eng.prepared_at || null,
    verification: eng.verification || null,
    // Full answer text: this is what the reviewer must actually read before
    // it goes out under the customer's name.
    answers: Array.isArray(eng.answers) ? eng.answers : [],
    reviewer: eng.reviewer || null,
    approved_at: eng.approved_at || null,
  });
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ engagementId: string }> }
): Promise<NextResponse> {
  const session = reviewerSession(request);
  if (!session) return epProblem(401, 'unauthorized', 'internal reviewer session required');

  const { engagementId } = await params;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return epProblem(400, 'invalid_body', 'a JSON body is required');
  }

  const decision = String(body?.decision || '').toLowerCase();
  // Reviewer identity is signed into the server-issued session. Never accept
  // a caller-selected name from the decision body.
  const reviewer = session.reviewerId;

  if (decision === 'approve') {
    const result = await publishReviewed({
      engagementId,
      reviewer,
      note: typeof body?.note === 'string' ? body.note : undefined,
    });
    if (!result.ok) {
      const status = result.error === 'engagement_not_found' ? 404
        : result.error === 'not_awaiting_review' ? 409 : 400;
      return epProblem(status, result.error, result.detail || result.error);
    }
    return NextResponse.json(result);
  }

  if (decision === 'reject') {
    const reason = typeof body?.reason === 'string' ? body.reason.trim() : '';
    if (!reason) return epProblem(400, 'reason_required', 'a rejection reason is required');
    const result = await rejectReviewed({ engagementId, reviewer, reason });
    if (!result.ok) {
      const status = result.error === 'engagement_not_found' ? 404
        : result.error === 'not_awaiting_review' ? 409 : 400;
      return epProblem(status, result.error, result.detail || result.error);
    }
    return NextResponse.json(result);
  }

  return epProblem(400, 'invalid_decision', 'decision must be "approve" or "reject"');
}
