import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * GET /api/signoff/[challengeId]
 *
 * Retrieve details of a signoff challenge by ID.
 * The guarded client is used for reads to enforce write discipline.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { challengeId } = await params;

    const supabase = getGuardedClient();
    const { data: challenge, error } = await supabase
      .from('signoff_challenges')
      .select('*')
      .eq('id', challengeId)
      .maybeSingle();

    if (error) {
      return epProblem(500, 'signoff_challenge_fetch_failed', error.message);
    }

    if (!challenge) {
      return EP_ERRORS.NOT_FOUND('Signoff challenge');
    }

    // ── Authorization: caller must be the accountable actor or have operator permissions ──
    const callerEntityId = auth.entityId || auth.entity_id;
    const isAccountableActor = callerEntityId && callerEntityId === challenge.accountable_actor_ref;
    const hasOperatorPermission = auth.permissions?.includes('signoff.view') || auth.permissions?.includes('operator');

    if (!isAccountableActor && !hasOperatorPermission) {
      return epProblem(403, 'forbidden', 'You must be the accountable actor or have operator permissions to view this challenge');
    }

    return NextResponse.json(challenge);
  } catch (err) {
    logger.error('Signoff challenge fetch error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
