import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { searchEvents } from '@/lib/cloud/event-explorer';
import { epProblem, EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/cloud/events/search?q=...&event_types=...&date_from=...&date_to=...
 *
 * Full-text search across all EP event tables.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const url = new URL(request.url);
    const query = url.searchParams.get('q');

    if (!query) {
      return epProblem(400, 'missing_query', 'Query parameter "q" is required');
    }

    const filters = {};
    const eventTypes = url.searchParams.get('event_types');
    if (eventTypes) {
      filters.event_types = eventTypes.split(',').map((t) => t.trim());
    }

    const dateFrom = url.searchParams.get('date_from');
    const dateTo = url.searchParams.get('date_to');
    if (dateFrom || dateTo) {
      filters.date_range = {};
      if (dateFrom) filters.date_range.from = dateFrom;
      if (dateTo) filters.date_range.to = dateTo;
    }

    const events = await searchEvents(query, filters);

    return NextResponse.json({
      events,
      count: events.length,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/events/search] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
