import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { getServiceClient } from '@/lib/supabase';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/webhooks/[endpointId]
 *
 * Get details of a specific webhook endpoint.
 * Requires: read permission.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const { endpointId } = await params;
    const supabase = getGuardedClient();

    const { data: endpoint, error } = await supabase
      .from('webhook_endpoints')
      .select('*')
      .eq('endpoint_id', endpointId)
      .eq('tenant_id', auth.tenantId)
      .maybeSingle();

    if (error) {
      logger.error('[cloud/webhooks] GET error:', error);
      return epProblem(500, 'webhook_query_failed', error.message);
    }

    if (!endpoint) {
      return EP_ERRORS.NOT_FOUND('Webhook endpoint');
    }

    return NextResponse.json({
      endpoint,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/webhooks/[endpointId]] GET error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

/**
 * PUT /api/cloud/webhooks/[endpointId]
 *
 * Update a webhook endpoint (URL, events, status).
 * Requires: write permission.
 *
 * Body: { url?: string, events?: string[], status?: 'active' | 'paused' | 'disabled' }
 */
export async function PUT(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const { endpointId } = await params;
    const body = await request.json();
    const supabase = getServiceClient();

    // Verify ownership
    const { data: existing, error: lookupErr } = await supabase
      .from('webhook_endpoints')
      .select('endpoint_id')
      .eq('endpoint_id', endpointId)
      .eq('tenant_id', auth.tenantId)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/webhooks] PUT lookup error:', lookupErr);
      return epProblem(500, 'webhook_query_failed', lookupErr.message);
    }

    if (!existing) {
      return EP_ERRORS.NOT_FOUND('Webhook endpoint');
    }

    // Build update object
    const update = { updated_at: new Date().toISOString() };

    if (body.url !== undefined) {
      try {
        const parsed = new URL(body.url);
        if (!['https:', 'http:'].includes(parsed.protocol)) {
          return epProblem(400, 'invalid_url', 'Webhook URL must use HTTPS or HTTP');
        }
      } catch {
        return epProblem(400, 'invalid_url', 'Webhook URL is not a valid URL');
      }
      update.url = body.url;
    }

    if (body.events !== undefined) {
      if (!Array.isArray(body.events) || body.events.length === 0) {
        return epProblem(400, 'invalid_events', 'At least one event type is required');
      }
      update.events = body.events;
    }

    if (body.status !== undefined) {
      if (!['active', 'paused', 'disabled'].includes(body.status)) {
        return epProblem(400, 'invalid_status', 'Status must be active, paused, or disabled');
      }
      update.status = body.status;
      // Reset failure count when re-enabling
      if (body.status === 'active') {
        update.failure_count = 0;
      }
    }

    const { data: updated, error: updateErr } = await supabase
      .from('webhook_endpoints')
      .update(update)
      .eq('endpoint_id', endpointId)
      .select()
      .single();

    if (updateErr) {
      logger.error('[cloud/webhooks] PUT update error:', updateErr);
      return epProblem(500, 'webhook_update_failed', updateErr.message);
    }

    return NextResponse.json({
      endpoint: updated,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/webhooks/[endpointId]] PUT error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

/**
 * DELETE /api/cloud/webhooks/[endpointId]
 *
 * Remove a webhook endpoint and its delivery history.
 * Requires: write permission.
 */
export async function DELETE(request, { params }) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'write');

    const { endpointId } = await params;
    const supabase = getServiceClient();

    // Verify ownership
    const { data: existing, error: lookupErr } = await supabase
      .from('webhook_endpoints')
      .select('endpoint_id')
      .eq('endpoint_id', endpointId)
      .eq('tenant_id', auth.tenantId)
      .maybeSingle();

    if (lookupErr) {
      logger.error('[cloud/webhooks] DELETE lookup error:', lookupErr);
      return epProblem(500, 'webhook_query_failed', lookupErr.message);
    }

    if (!existing) {
      return EP_ERRORS.NOT_FOUND('Webhook endpoint');
    }

    // Delete deliveries first (FK constraint)
    await supabase
      .from('webhook_deliveries')
      .delete()
      .eq('endpoint_id', endpointId);

    // Delete the endpoint
    const { error: deleteErr } = await supabase
      .from('webhook_endpoints')
      .delete()
      .eq('endpoint_id', endpointId);

    if (deleteErr) {
      logger.error('[cloud/webhooks] DELETE error:', deleteErr);
      return epProblem(500, 'webhook_delete_failed', deleteErr.message);
    }

    return NextResponse.json({
      deleted: true,
      endpoint_id: endpointId,
      tenant_id: auth.tenantId,
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/webhooks/[endpointId]] DELETE error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
