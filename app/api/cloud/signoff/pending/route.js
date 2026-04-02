import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/signoff/pending?limit=50&offset=0
 *
 * List signoff challenges that are pending (awaiting attestation).
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);

    const supabase = getGuardedClient();

    const { data: challenges, error, count } = await supabase
      .from('signoff_challenges')
      .select('*', { count: 'exact' })
      .eq('status', 'pending')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      logger.error('[cloud/signoff/pending] Query error:', error);
      return epProblem(500, 'signoff_pending_query_failed', error.message);
    }

    return NextResponse.json({
      challenges: challenges || [],
      total: count || 0,
      offset,
      limit,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/pending] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
