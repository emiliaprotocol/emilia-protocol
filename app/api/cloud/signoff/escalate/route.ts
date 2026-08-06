import { NextResponse, NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

/**
 * POST /api/cloud/signoff/escalate
 *
 * Escalate a stalled or at-risk signoff challenge for manual review.
 * Requires: write permission.
 *
 * Body: { challenge_id: string, reason: string }
 */
export async function POST(request: NextRequest) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as any;

    if (typeof body.challenge_id !== 'string' || !UUID.test(body.challenge_id)) {
      return epProblem(400, 'invalid_challenge_id', '"challenge_id" must be a UUID');
    }
    if (typeof body.reason !== 'string' || !body.reason.trim() || body.reason.length > 500) {
      return epProblem(400, 'invalid_reason', '"reason" must be a non-empty string of at most 500 characters');
    }

    const supabase = getGuardedClient();

    // Verify the challenge exists and is in an escalatable state
    const { data: challenge, error: lookupErr } = await supabase
      .from('signoff_challenges')
      .select('challenge_id, status, expires_at')
      .eq('tenant_id', auth.tenantId)
      .eq('challenge_id', body.challenge_id)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/signoff/escalate] Lookup error:', lookupErr);
      return epDbError(500, 'escalation_lookup_failed', lookupErr, 'cloud/signoff/escalate');
    }

    if (!challenge) {
      return EP_ERRORS.NOT_FOUND('Signoff challenge');
    }

    if (!['challenge_issued', 'challenge_viewed'].includes(challenge.status)) {
      return epProblem(409, 'not_escalatable', `Challenge is in "${challenge.status}" state and cannot be escalated`);
    }
    if (new Date(challenge.expires_at).getTime() <= Date.now()) {
      return epProblem(409, 'challenge_expired', 'Challenge has expired and cannot be escalated');
    }

    const escalatedAt = new Date().toISOString();
    const { data: event, error: insertErr } = await supabase
      .from('audit_events')
      .insert({
        event_type: 'cloud.signoff.escalated',
        actor_id: auth.keyId,
        actor_type: 'system',
        target_type: 'signoff_challenge',
        target_id: body.challenge_id,
        action: 'escalate',
        before_state: { status: challenge.status },
        after_state: {
          status: challenge.status,
          tenant_id: auth.tenantId,
          reason: body.reason.trim(),
          escalated_at: escalatedAt,
        },
      })
      .select('id, created_at')
      .single();
    if (insertErr) {
      if (insertErr.code === '23505') {
        return epProblem(409, 'already_escalated', 'Challenge has already been escalated');
      }
      return epDbError(500, 'escalation_record_failed', insertErr, 'cloud/signoff/escalate');
    }

    return NextResponse.json({
      challenge_id: body.challenge_id,
      escalated: true,
      reason: body.reason.trim(),
      escalation_event_id: event.id,
      escalated_at: event.created_at || escalatedAt,
      tenant_id: auth.tenantId,
    }, { status: 201 });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/escalate] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
