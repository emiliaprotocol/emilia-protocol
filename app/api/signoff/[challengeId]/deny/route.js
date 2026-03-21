import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { denyChallenge } from '@/lib/signoff/deny';
import { EP_ERRORS, epProblem } from '@/lib/errors';

/**
 * POST /api/signoff/[challengeId]/deny
 *
 * Deny a signoff challenge — the accountable human entity declines
 * the requested action. Updates challenge status to 'denied' and
 * emits a protocol event.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId } = await params;
    const body = await request.json().catch(() => ({}));

    const result = await denyChallenge({
      actor: auth.entity,
      challengeId,
      reason: body.reason || null,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_denial_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error('Signoff denial error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
