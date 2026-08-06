import { NextResponse, NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { deliverTenantEvent } from '@/lib/cloud/webhooks';
import { epProblem, EP_ERRORS, epDbError } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

/**
 * POST /api/cloud/signoff/notify
 *
 * Trigger a notification for a signoff challenge
 * (e.g. remind a party that attestation is needed).
 * Requires: write permission.
 *
 * Body: { challenge_id: string, channel?: 'email' | 'webhook', message?: string }
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

    const channel = body.channel || 'webhook';
    if (!['webhook', 'email'].includes(channel)) {
      return epProblem(400, 'invalid_notification_channel', 'channel must be "webhook" or "email"');
    }
    if (channel === 'email') {
      return epProblem(501, 'notification_channel_unavailable', 'Email delivery is not configured; no notification was queued.');
    }
    if (body.message !== undefined && (typeof body.message !== 'string' || body.message.length > 500)) {
      return epProblem(400, 'invalid_notification_message', 'message must be a string of at most 500 characters');
    }

    const supabase = getGuardedClient();
    const { data: challenge, error: lookupError } = await supabase
      .from('signoff_challenges')
      .select('challenge_id, status, expires_at, binding_hash, accountable_actor_ref')
      .eq('tenant_id', auth.tenantId)
      .eq('challenge_id', body.challenge_id)
      .maybeSingle();
    if (lookupError) {
      return epDbError(500, 'notification_lookup_failed', lookupError, 'cloud/signoff/notify');
    }
    if (!challenge) return EP_ERRORS.NOT_FOUND('Signoff challenge');
    if (!['challenge_issued', 'challenge_viewed'].includes(challenge.status)) {
      return epProblem(409, 'not_notifiable', `Challenge is in "${challenge.status}" state and cannot be notified`);
    }
    if (new Date(challenge.expires_at).getTime() <= Date.now()) {
      return epProblem(409, 'challenge_expired', 'Challenge has expired and cannot be notified');
    }

    const eventType = 'signoff.challenge.notification_requested';
    const delivery = await deliverTenantEvent(auth.tenantId, eventType, {
      event_type: eventType,
      challenge_id: challenge.challenge_id,
      binding_hash: challenge.binding_hash,
      accountable_actor_ref: challenge.accountable_actor_ref,
      message: body.message || null,
      requested_at: new Date().toISOString(),
    });
    if (delivery.error) {
      return epProblem(delivery.status || 500, 'notification_delivery_failed', delivery.error);
    }
    const status = delivery.delivery_state === 'delivered' ? 200
      : delivery.delivery_state === 'retrying' ? 202 : 502;

    return NextResponse.json({
      challenge_id: body.challenge_id,
      channel,
      notification_state: delivery.delivery_state,
      deliveries: delivery.deliveries,
      tenant_id: auth.tenantId,
    }, { status });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/notify] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
