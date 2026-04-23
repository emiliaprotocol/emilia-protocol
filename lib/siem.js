/**
 * EP SIEM Integration — Security event forwarder
 *
 * @license Apache-2.0
 *
 * Forwards high-signal audit events to an external SIEM via HTTP webhook.
 * Supports any SIEM that accepts HTTP POST (Splunk HEC, Datadog Events,
 * Elastic, generic webhook). The format follows Splunk HEC by default;
 * set SIEM_FORMAT=datadog for Datadog's event format.
 *
 * Configuration (environment variables):
 *   SIEM_WEBHOOK_URL    — Required. Full SIEM ingest URL.
 *   SIEM_AUTH_HEADER    — Optional. Authorization header value (e.g. "Splunk <HEC_TOKEN>").
 *   SIEM_FORMAT         — Optional. 'splunk' (default) | 'datadog' | 'generic'
 *   SIEM_SOURCE         — Optional. Source label for Splunk. Default: 'emilia-protocol'
 *   SIEM_INDEX          — Optional. Splunk index. Default: 'security'
 *   SIEM_DISABLED       — Set to 'true' to disable forwarding (e.g. in test envs)
 *
 * Usage:
 *   import { siemEvent } from '@/lib/siem';
 *   await siemEvent('HANDSHAKE_CONSUMED', { handshake_id, entity_id, ... });
 *
 * Design principles:
 *   - Fire-and-forget with timeout. Never blocks the critical path.
 *   - Never throws. Logs failures but does not propagate them.
 *   - Structured events with consistent schema (source, time, event_type, severity).
 *
 * @license Apache-2.0
 */

import { logger } from './logger.js';

// =============================================================================
// Event severity classification
// =============================================================================

const SEVERITY_MAP = {
  // Critical — immediate alert
  UNAUTHORIZED_ACCESS_ATTEMPT:  'critical',
  RATE_LIMIT_EXCEEDED:          'critical',
  PROOF_FORGERY_DETECTED:       'critical',
  DOUBLE_CONSUMPTION_ATTEMPT:   'critical',
  ANCHOR_FAILURE:               'critical',

  // High — investigate within 1h
  HANDSHAKE_REJECTED:           'high',
  SIGNOFF_DENIED:               'high',
  DISPUTE_ESCALATED:            'high',
  API_KEY_ROTATED:              'high',
  TENANT_SUSPENDED:             'high',
  FRAUD_FLAG_RAISED:            'high',

  // Medium — investigate within 24h
  HANDSHAKE_CONSUMED:           'medium',
  SIGNOFF_ATTESTED:             'medium',
  COMMITMENT_PROOF_GENERATED:   'medium',
  ENTITY_CREATED:               'medium',
  DELEGATION_CREATED:           'medium',

  // Low — informational
  HANDSHAKE_CREATED:            'low',
  EYE_ADVISORY_ISSUED:          'low',
  EYE_OBSERVATION_RECORDED:     'low',
  ANCHOR_BATCH_COMPLETED:       'low',
};

function getSeverity(eventType) {
  return SEVERITY_MAP[eventType] ?? 'low';
}

// =============================================================================
// Payload formatters
// =============================================================================

function formatSplunk(eventType, data, severity, source) {
  return JSON.stringify({
    time: Math.floor(Date.now() / 1000),
    host:  process.env.VERCEL_URL ?? 'emilia-protocol',
    source,
    sourcetype: 'emilia:protocol:event',
    index: process.env.SIEM_INDEX ?? 'security',
    event: {
      event_type: eventType,
      severity,
      ...data,
    },
  });
}

function formatDatadog(eventType, data, severity, source) {
  const ddSeverity = severity === 'critical' ? 'error'
    : severity === 'high' ? 'warning'
    : 'info';

  return JSON.stringify({
    title:      `EP: ${eventType}`,
    text:       `%%% \nEvent: ${eventType}\nSource: ${source}\n%%%`,
    priority:   severity === 'critical' || severity === 'high' ? 'normal' : 'low',
    alert_type: ddSeverity,
    tags: [
      `source:${source}`,
      `event_type:${eventType}`,
      `severity:${severity}`,
    ],
    ...data,
  });
}

function formatGeneric(eventType, data, severity, source) {
  return JSON.stringify({
    timestamp:  new Date().toISOString(),
    source,
    event_type: eventType,
    severity,
    payload:    data,
  });
}

// =============================================================================
// Core forwarder
// =============================================================================

/**
 * Forward a security event to the configured SIEM.
 * Fire-and-forget — never throws, never blocks the critical path.
 *
 * @param {string} eventType - Event type key (e.g. 'HANDSHAKE_CONSUMED')
 * @param {object} data      - Structured event payload. Must not contain secrets.
 */
export async function siemEvent(eventType, data = {}) {
  const url = process.env.SIEM_WEBHOOK_URL;

  if (!url || process.env.SIEM_DISABLED === 'true') {
    // SIEM not configured — skip silently in non-production, warn in production
    if (process.env.NODE_ENV === 'production' && !process.env.SIEM_WEBHOOK_URL) {
      logger.warn(`[siem] SIEM_WEBHOOK_URL not set — event ${eventType} not forwarded`);
    }
    return;
  }

  const severity = getSeverity(eventType);
  const source   = process.env.SIEM_SOURCE ?? 'emilia-protocol';
  const format   = process.env.SIEM_FORMAT ?? 'splunk';

  let body;
  if (format === 'datadog') {
    body = formatDatadog(eventType, data, severity, source);
  } else if (format === 'generic') {
    body = formatGeneric(eventType, data, severity, source);
  } else {
    body = formatSplunk(eventType, data, severity, source);
  }

  const headers = { 'Content-Type': 'application/json' };
  const authHeader = process.env.SIEM_AUTH_HEADER;
  if (authHeader) headers['Authorization'] = authHeader;

  // Fire-and-forget with 5s timeout — never block the API response
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);

  fetch(url, {
    method: 'POST',
    headers,
    body,
    signal: controller.signal,
  })
    .then(res => {
      clearTimeout(timeout);
      if (!res.ok) {
        logger.warn(`[siem] Event ${eventType} forwarding failed: HTTP ${res.status}`);
      }
    })
    .catch(err => {
      clearTimeout(timeout);
      if (err.name !== 'AbortError') {
        logger.warn(`[siem] Event ${eventType} forwarding error: ${err.message}`);
      }
    });
}

/**
 * Synchronous wrapper for use in server actions or places where you want
 * to await the SIEM forward (e.g. in cron routes where latency is acceptable).
 * Still swallows errors — SIEM failure must never fail the primary operation.
 *
 * @param {string} eventType
 * @param {object} data
 */
export async function siemEventAwait(eventType, data = {}) {
  try {
    await siemEvent(eventType, data);
  } catch {
    // intentional no-op
  }
}
