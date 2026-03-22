import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { queryEvents, verifyIntegrity } from '@/lib/cloud/event-explorer';
import { epProblem, EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/cloud/audit/report?date_from=...&date_to=...
 *
 * Generate an audit report: event summary + integrity score.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const url = new URL(request.url);
    const dateFrom = url.searchParams.get('date_from');
    const dateTo = url.searchParams.get('date_to');

    const filters = {};
    if (dateFrom) filters.date_from = dateFrom;
    if (dateTo) filters.date_to = dateTo;

    const [eventResult, integrityResult] = await Promise.all([
      queryEvents({ ...filters, limit: 0 }),
      verifyIntegrity({ from: dateFrom, to: dateTo }),
    ]);

    return NextResponse.json({
      total_events: eventResult.total,
      integrity: integrityResult,
      date_range: { from: dateFrom || null, to: dateTo || null },
      tenant_id: auth.tenantId,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/audit/report] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
