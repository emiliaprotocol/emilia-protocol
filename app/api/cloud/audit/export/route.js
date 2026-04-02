import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { queryEvents } from '@/lib/cloud/event-explorer';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/audit/export?date_from=...&date_to=...&format=json
 *
 * Export all events in the date range for compliance/archival.
 * Requires: admin permission (bulk data export).
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'admin');

    const url = new URL(request.url);
    const dateFrom = url.searchParams.get('date_from');
    const dateTo = url.searchParams.get('date_to');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '500', 10), 5000);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    const filters = { limit, offset };
    if (dateFrom) filters.date_from = dateFrom;
    if (dateTo) filters.date_to = dateTo;

    const { events, total } = await queryEvents(filters);

    return NextResponse.json({
      events,
      total,
      offset,
      limit,
      tenant_id: auth.tenantId,
      exported_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/audit/export] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
