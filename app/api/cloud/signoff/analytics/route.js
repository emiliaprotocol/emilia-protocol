import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/signoff/analytics?date_from=...&date_to=...
 *
 * Analytics data for signoff operations: completion rates,
 * average processing times, and volume trends.
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

    const supabase = getGuardedClient();

    let query = supabase
      .from('signoff_challenges')
      .select('status, created_at, updated_at');

    if (dateFrom) query = query.gte('created_at', dateFrom);
    if (dateTo) query = query.lte('created_at', dateTo);

    const { data: challenges, error } = await query;

    if (error) {
      logger.error('[cloud/signoff/analytics] Query error:', error);
      return epProblem(500, 'signoff_analytics_query_failed', error.message);
    }

    const rows = challenges || [];
    const byStatus = {};
    for (const c of rows) {
      byStatus[c.status] = (byStatus[c.status] || 0) + 1;
    }

    return NextResponse.json({
      total: rows.length,
      by_status: byStatus,
      date_range: { from: dateFrom || null, to: dateTo || null },
      tenant_id: auth.tenantId,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/analytics] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
