/**
 * EP Webhooks — Core Library
 *
 * Manages webhook endpoint registration, signed payload delivery,
 * retry logic with exponential backoff, and automatic endpoint
 * disabling after consecutive failures.
 *
 * Signature scheme:
 *   Header: X-EP-Signature = HMAC-SHA256(secret, timestamp + '.' + body)
 *   Header: X-EP-Timestamp = Unix seconds
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';

// ── Constants ────────────────────────────────────────────────────────────────

/** Retry intervals in milliseconds (exponential backoff). */
const RETRY_INTERVALS_MS = [
  1 * 60 * 1000,       // 1 minute
  5 * 60 * 1000,       // 5 minutes
  30 * 60 * 1000,      // 30 minutes
  2 * 60 * 60 * 1000,  // 2 hours
  12 * 60 * 60 * 1000, // 12 hours
];

/** Max consecutive failures before auto-disable. */
const MAX_CONSECUTIVE_FAILURES = 10;

/** Timeout for webhook delivery requests (ms). */
const DELIVERY_TIMEOUT_MS = 15_000;

// ── Endpoint Management ──────────────────────────────────────────────────────

/**
 * Register a new webhook endpoint for a tenant.
 *
 * @param {string} tenantId - The tenant UUID
 * @param {string} url - The webhook URL to receive payloads
 * @param {string[]} events - Event types to subscribe to
 * @returns {Promise<{ endpoint: object, secret: string } | { error: string, status: number }>}
 */
export async function registerEndpoint(tenantId, url, events) {
  const supabase = getServiceClient();
  const secret = `whsec_${crypto.randomBytes(32).toString('hex')}`;

  const { data: endpoint, error } = await supabase
    .from('webhook_endpoints')
    .insert({
      tenant_id: tenantId,
      url,
      secret,
      events,
    })
    .select()
    .single();

  if (error) {
    console.error('[webhooks] registerEndpoint error:', error);
    return { error: 'Failed to register webhook endpoint', status: 500 };
  }

  return { endpoint, secret };
}

/**
 * Disable a webhook endpoint (e.g. after too many failures).
 *
 * @param {string} endpointId - The endpoint UUID
 * @returns {Promise<{ success: boolean } | { error: string, status: number }>}
 */
export async function disableEndpoint(endpointId) {
  const supabase = getServiceClient();

  const { error } = await supabase
    .from('webhook_endpoints')
    .update({ status: 'disabled', updated_at: new Date().toISOString() })
    .eq('endpoint_id', endpointId);

  if (error) {
    console.error('[webhooks] disableEndpoint error:', error);
    return { error: 'Failed to disable endpoint', status: 500 };
  }

  return { success: true };
}

// ── Signing ──────────────────────────────────────────────────────────────────

/**
 * Compute the HMAC-SHA256 signature for a webhook payload.
 *
 * @param {string} secret - The endpoint's HMAC secret
 * @param {number} timestamp - Unix timestamp (seconds)
 * @param {object} payload - The event payload
 * @returns {string} Hex-encoded signature
 */
export function computeSignature(secret, timestamp, payload) {
  const message = `${timestamp}.${JSON.stringify(payload)}`;
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

// ── Delivery ─────────────────────────────────────────────────────────────────

/**
 * Deliver a webhook event to an endpoint.
 *
 * Signs the payload with HMAC-SHA256 and POSTs it to the endpoint URL.
 * Records the delivery attempt in webhook_deliveries.
 *
 * @param {string} endpointId - The endpoint UUID
 * @param {string} eventType - The event type (e.g. 'receipt.created')
 * @param {object} payload - The event payload
 * @returns {Promise<{ delivery: object } | { error: string, status: number }>}
 */
export async function deliverWebhook(endpointId, eventType, payload) {
  const supabase = getServiceClient();

  // Fetch the endpoint
  const { data: endpoint, error: epErr } = await supabase
    .from('webhook_endpoints')
    .select('*')
    .eq('endpoint_id', endpointId)
    .single();

  if (epErr || !endpoint) {
    return { error: 'Webhook endpoint not found', status: 404 };
  }

  if (endpoint.status !== 'active') {
    return { error: 'Webhook endpoint is not active', status: 422 };
  }

  // Create the delivery record
  const { data: delivery, error: delErr } = await supabase
    .from('webhook_deliveries')
    .insert({
      endpoint_id: endpointId,
      event_type: eventType,
      payload,
    })
    .select()
    .single();

  if (delErr) {
    console.error('[webhooks] deliverWebhook insert error:', delErr);
    return { error: 'Failed to create delivery record', status: 500 };
  }

  // Attempt the delivery
  const result = await attemptDelivery(supabase, endpoint, delivery);
  return result;
}

/**
 * Attempt to POST the signed payload to the endpoint URL.
 *
 * @param {object} supabase - Supabase client
 * @param {object} endpoint - The webhook endpoint record
 * @param {object} delivery - The webhook delivery record
 * @returns {Promise<{ delivery: object } | { error: string, status: number }>}
 */
async function attemptDelivery(supabase, endpoint, delivery) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = computeSignature(endpoint.secret, timestamp, delivery.payload);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

    const response = await fetch(endpoint.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-EP-Signature': signature,
        'X-EP-Timestamp': String(timestamp),
        'X-EP-Event': delivery.event_type,
        'X-EP-Delivery': delivery.delivery_id,
      },
      body: JSON.stringify(delivery.payload),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    const responseBody = await response.text().catch(() => '');

    if (response.ok) {
      // Success — update delivery and endpoint
      const { data: updated } = await supabase
        .from('webhook_deliveries')
        .update({
          status: 'delivered',
          attempts: delivery.attempts + 1,
          response_status: response.status,
          response_body: responseBody.slice(0, 4096),
          delivered_at: new Date().toISOString(),
        })
        .eq('delivery_id', delivery.delivery_id)
        .select()
        .single();

      await supabase
        .from('webhook_endpoints')
        .update({
          failure_count: 0,
          last_success_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq('endpoint_id', endpoint.endpoint_id);

      return { delivery: updated };
    }

    // Non-2xx — mark as failed / schedule retry
    return await handleFailure(
      supabase,
      endpoint,
      delivery,
      response.status,
      responseBody.slice(0, 4096),
    );
  } catch (err) {
    // Network error or timeout
    return await handleFailure(
      supabase,
      endpoint,
      delivery,
      null,
      err.message,
    );
  }
}

/**
 * Handle a failed delivery attempt — schedule retry or mark as failed.
 */
async function handleFailure(supabase, endpoint, delivery, responseStatus, responseBody) {
  const attempts = delivery.attempts + 1;
  const retryIndex = attempts - 1;
  const canRetry = retryIndex < RETRY_INTERVALS_MS.length;

  const deliveryUpdate = {
    attempts,
    response_status: responseStatus,
    response_body: responseBody,
    status: canRetry ? 'retrying' : 'failed',
  };

  if (canRetry) {
    deliveryUpdate.next_retry_at = new Date(
      Date.now() + RETRY_INTERVALS_MS[retryIndex],
    ).toISOString();
  }

  const { data: updated } = await supabase
    .from('webhook_deliveries')
    .update(deliveryUpdate)
    .eq('delivery_id', delivery.delivery_id)
    .select()
    .single();

  // Update endpoint failure tracking
  const newFailureCount = endpoint.failure_count + 1;
  const endpointUpdate = {
    failure_count: newFailureCount,
    last_failure_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  // Auto-disable after too many consecutive failures
  if (newFailureCount >= MAX_CONSECUTIVE_FAILURES) {
    endpointUpdate.status = 'disabled';
    console.warn(
      `[webhooks] Auto-disabling endpoint ${endpoint.endpoint_id} after ${newFailureCount} consecutive failures`,
    );
  }

  await supabase
    .from('webhook_endpoints')
    .update(endpointUpdate)
    .eq('endpoint_id', endpoint.endpoint_id);

  return { delivery: updated };
}

// ── Retry Worker ─────────────────────────────────────────────────────────────

/**
 * Retry all failed deliveries that are due for a retry.
 *
 * This should be called periodically (e.g. via cron) to process
 * deliveries in 'retrying' status whose next_retry_at has passed.
 *
 * @returns {Promise<{ processed: number, succeeded: number, failed: number }>}
 */
export async function retryFailedDeliveries() {
  const supabase = getServiceClient();

  const { data: deliveries, error } = await supabase
    .from('webhook_deliveries')
    .select('*, webhook_endpoints(*)')
    .eq('status', 'retrying')
    .lte('next_retry_at', new Date().toISOString())
    .order('next_retry_at', { ascending: true })
    .limit(50);

  if (error) {
    console.error('[webhooks] retryFailedDeliveries query error:', error);
    return { processed: 0, succeeded: 0, failed: 0 };
  }

  if (!deliveries || deliveries.length === 0) {
    return { processed: 0, succeeded: 0, failed: 0 };
  }

  let succeeded = 0;
  let failed = 0;

  for (const delivery of deliveries) {
    const endpoint = delivery.webhook_endpoints;
    if (!endpoint || endpoint.status !== 'active') {
      // Endpoint disabled or gone — mark delivery as failed
      await supabase
        .from('webhook_deliveries')
        .update({ status: 'failed' })
        .eq('delivery_id', delivery.delivery_id);
      failed++;
      continue;
    }

    const result = await attemptDelivery(supabase, endpoint, delivery);
    if (result.delivery?.status === 'delivered') {
      succeeded++;
    } else {
      failed++;
    }
  }

  return { processed: deliveries.length, succeeded, failed };
}
