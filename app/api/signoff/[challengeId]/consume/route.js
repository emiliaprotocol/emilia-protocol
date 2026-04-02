import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { consumeSignoff } from '@/lib/signoff/consume';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * POST /api/signoff/[signoffId]/consume
 *
 * Consume a signoff attestation — marks the attestation as used by
 * binding it to a specific execution. A consumed signoff cannot be
 * reused, ensuring one-time authorization semantics.
 *
 * Required body fields:
 *   - executionRef: Reference to the execution consuming this signoff
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId: signoffId } = await params;
    const body = await request.json();

    if (!body.executionRef) {
      return EP_ERRORS.BAD_REQUEST('Missing required field: executionRef');
    }

    const result = await consumeSignoff({
      actor: auth.entity,
      signoffId,
      executionRef: body.executionRef,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_consumption_failed', result.error);
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Signoff consumption error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
