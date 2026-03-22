import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { registerEndpoint } from '@/lib/cloud/webhooks';
import { epProblem, EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/cloud/webhooks
 *
 * List all webhook endpoints for the authenticated tenant.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const supabase = getGuardedClient();

    const { data: endpoints, error } = await supabase
      .from('webhook_endpoints')
      .select('endpoint_id, url, events, status, failure_count, last_success_at, last_failure_at, created_at, updated_at')
      .eq('tenant_id', auth.tenantId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('[cloud/webhooks] List error:', error);
      return epProblem(500, 'webhooks_query_failed', error.message);
    }

    return NextResponse.json({
      endpoints: endpoints || [],
      count: (endpoints || []).length,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/webhooks] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

/**
 * POST /api/cloud/webhooks
 *
 * Create a new webhook endpoint.
 * Requires: write permission.
 *
 * Body: { url: string, events: string[] }
 * Returns the endpoint with the HMAC signing secret (shown only once).
 */
export async function POST(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const body = await request.json();
    const { url, events } = body;

    if (!url || typeof url !== 'string') {
      return epProblem(400, 'invalid_url', 'A valid webhook URL is required');
    }

    // Basic URL validation
    try {
      const parsed = new URL(url);
      if (!['https:', 'http:'].includes(parsed.protocol)) {
        return epProblem(400, 'invalid_url', 'Webhook URL must use HTTPS or HTTP');
      }
    } catch {
      return epProblem(400, 'invalid_url', 'Webhook URL is not a valid URL');
    }

    if (!Array.isArray(events) || events.length === 0) {
      return epProblem(400, 'invalid_events', 'At least one event type is required');
    }

    const result = await registerEndpoint(auth.tenantId, url, events);

    if (result.error) {
      return epProblem(result.status, 'webhook_creation_failed', result.error);
    }

    return NextResponse.json({
      endpoint: result.endpoint,
      secret: result.secret,
      tenant_id: auth.tenantId,
    }, { status: 201 });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/webhooks] POST error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
