import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { deliverWebhook } from '@/lib/cloud/webhooks';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../../lib/logger.js';

/**
 * POST /api/cloud/webhooks/[endpointId]/test
 *
 * Send a test webhook delivery to verify endpoint connectivity.
 * Requires: write permission.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const { endpointId } = await params;
    const supabase = getGuardedClient();

    // Verify ownership
    const { data: endpoint, error: lookupErr } = await supabase
      .from('webhook_endpoints')
      .select('endpoint_id, tenant_id, status')
      .eq('endpoint_id', endpointId)
      .eq('tenant_id', auth.tenantId)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/webhooks/test] Lookup error:', lookupErr);
      return epProblem(500, 'webhook_query_failed', lookupErr.message);
    }

    if (!endpoint) {
      return EP_ERRORS.NOT_FOUND('Webhook endpoint');
    }

    if (endpoint.status !== 'active') {
      return epProblem(422, 'endpoint_not_active', 'Endpoint must be active to send a test delivery');
    }

    // Send a test event
    const testPayload = {
      test: true,
      event_type: 'webhook.test',
      tenant_id: auth.tenantId,
      endpoint_id: endpointId,
      timestamp: new Date().toISOString(),
      message: 'This is a test webhook delivery from the Emilia Protocol.',
    };

    const result = await deliverWebhook(endpointId, 'webhook.test', testPayload);

    if (result.error) {
      return epProblem(result.status, 'test_delivery_failed', result.error);
    }

    return NextResponse.json({
      success: result.delivery?.status === 'delivered',
      delivery: result.delivery,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/webhooks/test] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
