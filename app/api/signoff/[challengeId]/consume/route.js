import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityActor } from '@/lib/auth-projections.js';
import { consumeSignoff } from '@/lib/signoff/consume';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

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
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    if (!body.executionRef) {
      return EP_ERRORS.BAD_REQUEST('Missing required field: executionRef');
    }

    const result = await consumeSignoff({
      actor: authEntityActor(auth),
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
