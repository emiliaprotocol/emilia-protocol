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
import https from 'node:https';
import { lookup } from 'node:dns/promises';
import { getServiceClient } from '@/lib/supabase';
import { logger } from '../logger.js';

// ── SSRF Protection ─────────────────────────────────────────────────────────

/** Private/reserved IP ranges that must not be targeted by webhooks. */
const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc/i,
  /^fd/i,
  /^fe80/i,
];

/**
 * Check whether a hostname resolves to a private/reserved IP or is a
 * well-known internal hostname. Used to prevent SSRF via webhook URLs.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
function isPrivateHost(hostname) {
  if (['localhost', '0.0.0.0'].includes(hostname)) return true;
  if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return true;
  const host = hostname.replace(/^\[|\]$/g, '').replace(/%.*$/, '').toLowerCase();
  const mapped = host.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  const candidates = mapped ? [host, mapped[1]] : [host];
  return candidates.some((h) => PRIVATE_RANGES.some(r => r.test(h)));
}

/** Check a resolved IP literal against the private/reserved ranges. */
function isPrivateIp(ip) {
  // Normalize IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) to its v4 form.
  const v4 = ip.replace(/^::ffff:/i, '');
  return PRIVATE_RANGES.some(r => r.test(v4)) || PRIVATE_RANGES.some(r => r.test(ip));
}

/**
 * Validate that a webhook URL does not target private/internal addresses.
 * Throws if the URL is invalid or targets a private host. On success returns the
 * validated public addresses so the caller can PIN the connection to one of
 * them (closing the DNS-rebinding TOCTOU — see deliverToPinnedAddress).
 *
 * @param {string} urlString
 * @returns {Promise<{ parsed: URL, addresses: {address:string, family:number}[] }>}
 * @throws {Error} If the URL targets a private/internal address
 */
export async function validateWebhookUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new Error('Invalid webhook URL');
  }

  // Literal-host guard (catches localhost / *.internal / IP-literal hostnames).
  if (isPrivateHost(parsed.hostname)) {
    throw new Error('Webhook URL must not target private or internal addresses');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Webhook URL must use https protocol');
  }

  // DNS guard: resolve the hostname and reject if ANY A/AAAA record is private.
  // Closes the SSRF hole where a public name (or a DNS-rebinding name) resolves
  // to a private/link-local address such as the cloud metadata endpoint. Run at
  // registration AND delivery time so a record flipped after registration is
  // caught before the request leaves.
  let addrs;
  try {
    addrs = await lookup(parsed.hostname, { all: true });
  } catch {
    throw new Error('Webhook URL host could not be resolved');
  }
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('Webhook URL must not resolve to a private or internal address');
  }
  return { parsed, addresses: addrs };
}

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
  // SSRF protection: block private/internal URLs at registration time
  try {
    await validateWebhookUrl(url);
  } catch (err) {
    return { error: err.message, status: 422 };
  }

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
    logger.error('[webhooks] registerEndpoint error:', error);
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
    logger.error('[webhooks] disableEndpoint error:', error);
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

// ── Pinned delivery (DNS-rebinding TOCTOU defense) ────────────────────────────

/**
 * POST a webhook body to a hostname while PINNING the TCP connection to a
 * specific, pre-validated IP address.
 *
 * The SSRF check in validateWebhookUrl resolves the hostname and rejects private
 * addresses. If the actual HTTP client then re-resolves independently (as
 * global fetch/undici does), an attacker controlling DNS can return a public IP
 * for the validation lookup and a private one (e.g. 169.254.169.254) for the
 * connection — a classic time-of-check/time-of-use rebinding. We eliminate the
 * second, independent resolution by handing node:https a `lookup` that ALWAYS
 * returns the address we already validated. TLS SNI and certificate validation
 * still use the real hostname (kept in the URL / servername), so pinning does
 * not weaken transport security.
 *
 * @param {URL} url the validated https URL
 * @param {string} pinnedAddress the validated public IP to connect to
 * @param {number} pinnedFamily 4 or 6
 * @param {{ headers: object, body: string, timeoutMs: number }} opts
 * @returns {Promise<{ status:number, ok:boolean, body:string }>}
 */
function deliverToPinnedAddress(url, pinnedAddress, pinnedFamily, { headers, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname, // preserved for SNI + cert validation
        servername: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: 'POST',
        headers: { ...headers, Host: url.host },
        // Pin the connection: force resolution to the already-validated IP so no
        // second, independent DNS lookup can rebind to an internal address.
        lookup: (_hostname, _options, cb) => cb(null, pinnedAddress, pinnedFamily || 4),
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let total = 0;
        const MAX = 8 * 1024; // we only keep a 4KB slice; cap the read defensively
        res.on('data', (c) => {
          total += c.length;
          if (total <= MAX) chunks.push(c);
          else res.destroy();
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            ok: res.statusCode >= 200 && res.statusCode < 300,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    // Never follow redirects: node:https does not auto-follow, so a 3xx simply
    // surfaces as a non-2xx status which attemptDelivery treats as a failure.
    req.on('timeout', () => { req.destroy(new Error('Webhook delivery timed out')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
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
    logger.error('[webhooks] deliverWebhook insert error:', delErr);
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
  // DNS rebinding protection: re-validate AND resolve the URL at delivery time,
  // then PIN the connection to the address we just validated so the actual
  // request cannot re-resolve to a rebind (169.254.169.254 / internal). Closes
  // the TOCTOU between the SSRF check and the outbound connection.
  let validated;
  try {
    validated = await validateWebhookUrl(endpoint.url);
  } catch (err) {
    return await handleFailure(supabase, endpoint, delivery, null, `SSRF blocked: ${err.message}`);
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const signature = computeSignature(endpoint.secret, timestamp, delivery.payload);

  try {
    const pinned = validated.addresses[0];
    const response = await deliverToPinnedAddress(
      validated.parsed,
      pinned.address,
      pinned.family,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-EP-Signature': signature,
          'X-EP-Timestamp': String(timestamp),
          'X-EP-Event': delivery.event_type,
          'X-EP-Delivery': delivery.delivery_id,
        },
        body: JSON.stringify(delivery.payload),
        timeoutMs: DELIVERY_TIMEOUT_MS,
      },
    );

    if (response.status >= 300 && response.status < 400) {
      return await handleFailure(supabase, endpoint, delivery, response.status, 'Webhook endpoint returned a redirect; redirects are not followed');
    }

    const responseBody = response.body || '';

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
    logger.warn(
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
    logger.error('[webhooks] retryFailedDeliveries query error:', error);
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
