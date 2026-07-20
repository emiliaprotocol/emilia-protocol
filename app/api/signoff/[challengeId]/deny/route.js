import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityActor } from '@/lib/auth-projections.js';
import { denyChallenge } from '@/lib/signoff/deny';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 32 * 1024;

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
    const parsed = await readEpJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;

    // authenticateRequest() only returns without `error` when the auth RPC
    // resolved a live, active entity (see resolve_authenticated_actor SQL),
    // so authEntityActor() is guaranteed non-null here even though its
    // general signature allows null for the no-entity case.
    const actor = /** @type {{ id: string, entity_id: string }} */ (authEntityActor(auth));

    const result = await denyChallenge({
      actor,
      challengeId,
      reason: body.reason || null,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'signoff_denial_failed', result.error);
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Signoff denial error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
