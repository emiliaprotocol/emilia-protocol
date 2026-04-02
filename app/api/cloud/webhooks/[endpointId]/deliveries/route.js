import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/cloud/webhooks/[endpointId]/deliveries
 *
 * List recent deliveries for a webhook endpoint.
 * Requires: read permission.
 *
 * Query params:
 *   limit  — max results (default 50, max 200)
 *   status — filter by delivery status
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { endpointId } = await params;
    const supabase = getGuardedClient();

    // Verify ownership of the endpoint
    const { data: endpoint, error: lookupErr } = await supabase
      .from('webhook_endpoints')
      .select('endpoint_id')
      .eq('endpoint_id', endpointId)
      .eq('tenant_id', auth.tenantId)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/webhooks/deliveries] Lookup error:', lookupErr);
      return epProblem(500, 'webhook_query_failed', lookupErr.message);
    }

    if (!endpoint) {
      return EP_ERRORS.NOT_FOUND('Webhook endpoint');
    }

    // Parse query params
    const url = new URL(request.url);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 200);
    const statusFilter = url.searchParams.get('status');

    let query = supabase
      .from('webhook_deliveries')
      .select('*')
      .eq('endpoint_id', endpointId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (statusFilter) {
      query = query.eq('status', statusFilter);
    }

    const { data: deliveries, error } = await query;

    if (error) {
      logger.error('[cloud/webhooks/deliveries] Query error:', error);
      return epProblem(500, 'deliveries_query_failed', error.message);
    }

    return NextResponse.json({
      deliveries: deliveries || [],
      count: (deliveries || []).length,
      endpoint_id: endpointId,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/webhooks/deliveries] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
