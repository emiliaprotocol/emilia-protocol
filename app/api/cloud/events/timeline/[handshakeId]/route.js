import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getTimeline } from '@/lib/cloud/event-explorer';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/cloud/events/timeline/[handshakeId]
 *
 * Chronological timeline of all events for a single handshake.
 * Requires: read permission.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { handshakeId } = await params;

    if (!handshakeId) {
      return epProblem(400, 'missing_handshake_id', 'handshakeId path parameter is required');
    }

    const events = await getTimeline(handshakeId, auth.tenantId);

    return NextResponse.json({
      handshake_id: handshakeId,
      events,
      count: events.length,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/events/timeline] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
