import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * POST /api/cloud/signoff/escalate
 *
 * Escalate a stalled or at-risk signoff challenge for manual review.
 * Requires: write permission.
 *
 * Body: { challenge_id: string, reason: string }
 */
export async function POST(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const body = await request.json();

    if (!body.challenge_id) {
      return epProblem(400, 'missing_challenge_id', '"challenge_id" is required');
    }
    if (!body.reason) {
      return epProblem(400, 'missing_reason', '"reason" is required');
    }

    const supabase = getGuardedClient();

    // Verify the challenge exists and is in an escalatable state
    const { data: challenge, error: lookupErr } = await supabase
      .from('signoff_challenges')
      .select('id, status')
      .eq('tenant_id', auth.tenantId)
      .eq('id', body.challenge_id)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/signoff/escalate] Lookup error:', lookupErr);
      return epProblem(500, 'escalation_lookup_failed', lookupErr.message);
    }

    if (!challenge) {
      return EP_ERRORS.NOT_FOUND('Signoff challenge');
    }

    if (challenge.status !== 'pending') {
      return epProblem(409, 'not_escalatable', `Challenge is in "${challenge.status}" state and cannot be escalated`);
    }

    return NextResponse.json({
      challenge_id: body.challenge_id,
      escalated: true,
      reason: body.reason,
      escalated_at: new Date().toISOString(),
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/escalate] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
