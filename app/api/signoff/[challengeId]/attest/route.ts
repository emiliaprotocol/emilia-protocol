import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * POST /api/signoff/[challengeId]/attest
 *
 * This legacy bearer/JSON path cannot prove a fresh human ceremony and is
 * intentionally disabled. Approval must use a server-verified WebAuthn or
 * secure-application ceremony that records one-time challenge-bound evidence.
 */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ challengeId: string }> },
): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();
    if (!authEntityId(auth).trim()) {
      return epProblem(403, 'not_authorized', 'A named authenticated entity is required');
    }

    await params;
    return epProblem(
      409,
      'verified_ceremony_required',
      'Bearer-authenticated JSON cannot approve a signoff. Complete a server-verified WebAuthn or secure-application ceremony.',
    );
  } catch (err: any) {
    logger.error('Signoff attestation error:', {
      message: err?.message,
      code: err?.code,
    });
    return NextResponse.json({
      error: {
        code: 'EP-9001',
        message: 'Attestation could not be processed.',
        detail: null,
      },
    }, { status: err?.status || 500 });
  }
}
