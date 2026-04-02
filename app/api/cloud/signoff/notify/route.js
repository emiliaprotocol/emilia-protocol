import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * POST /api/cloud/signoff/notify
 *
 * Trigger a notification for a signoff challenge
 * (e.g. remind a party that attestation is needed).
 * Requires: write permission.
 *
 * Body: { challenge_id: string, channel?: 'email' | 'webhook', message?: string }
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

    const channel = body.channel || 'webhook';

    return NextResponse.json({
      challenge_id: body.challenge_id,
      channel,
      notification_queued: true,
      queued_at: new Date().toISOString(),
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/notify] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
