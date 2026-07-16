/**
 * EMILIA Protocol — Sentry Edge Runtime Configuration
 * @license Apache-2.0
 *
 * Initializes Sentry for Next.js Edge Runtime routes (middleware and
 * any API routes that opt into `export const runtime = 'edge'`).
 *
 * The Edge Runtime is a constrained environment: no Node.js APIs,
 * no file system access. This config mirrors server-config semantics
 * but avoids Node-only imports (e.g., crypto, fs).
 *
 * SENTRY_DSN is provided via the build-time env injection from
 * withSentryConfig() in next.config.js. No NEXT_PUBLIC_ prefix needed
 * here because edge config is evaluated at build time, not in the browser.
 *
 * See: https://docs.sentry.io/platforms/javascript/guides/nextjs/
 */

import * as Sentry from '@sentry/nextjs';

const configuredEnvironment = process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? 'development';
const sentryEnvironment = /^[A-Za-z0-9._-]{1,64}$/.test(configuredEnvironment)
  ? configuredEnvironment
  : 'development';

const SAFE_LEVELS = new Set(['fatal', 'error', 'warning', 'log', 'info', 'debug']);
const SAFE_PLATFORMS = new Set(['javascript', 'node']);
const SAFE_ERROR_TYPES = new Set([
  'Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError',
  'URIError', 'EvalError', 'AggregateError',
]);
const SAFE_SPAN_OPS = new Set([
  'http.client', 'http.server', 'middleware.nextjs', 'function.nextjs',
  'browser', 'navigation', 'pageload', 'resource', 'ui.action', 'db',
  'cache', 'queue', 'task', 'rpc', 'graphql',
]);
const SAFE_SPAN_STATUSES = new Set([
  'ok', 'cancelled', 'unknown_error', 'invalid_argument', 'deadline_exceeded',
  'not_found', 'already_exists', 'permission_denied', 'resource_exhausted',
  'failed_precondition', 'aborted', 'out_of_range', 'unimplemented',
  'internal_error', 'unavailable', 'data_loss', 'unauthenticated', 'error',
]);
const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const TRACE_ID = /^[a-f0-9]{32}$/i;
const SPAN_ID = /^[a-f0-9]{16}$/i;

function finiteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function safeId(value, pattern) {
  return typeof value === 'string' && pattern.test(value) ? value : undefined;
}

function safeMethod(value) {
  if (typeof value !== 'string') return undefined;
  const method = value.toUpperCase();
  return SAFE_HTTP_METHODS.has(method) ? method : undefined;
}

function sanitizeTraceContext(trace) {
  if (!trace || typeof trace !== 'object') return undefined;
  const safe = {};
  const traceId = safeId(trace.trace_id, TRACE_ID);
  const spanId = safeId(trace.span_id, SPAN_ID);
  const parentSpanId = safeId(trace.parent_span_id, SPAN_ID);
  if (traceId) safe.trace_id = traceId;
  if (spanId) safe.span_id = spanId;
  if (parentSpanId) safe.parent_span_id = parentSpanId;
  if (SAFE_SPAN_OPS.has(trace.op)) safe.op = trace.op;
  if (SAFE_SPAN_STATUSES.has(trace.status)) safe.status = trace.status;
  return Object.keys(safe).length ? safe : undefined;
}

function sanitizeException(exception) {
  if (!Array.isArray(exception?.values) || exception.values.length === 0) return undefined;
  return {
    values: exception.values.slice(0, 8).map((value) => ({
      type: SAFE_ERROR_TYPES.has(value?.type) ? value.type : 'Error',
      value: '[details suppressed]',
    })),
  };
}

function sanitizeSentrySpan(span = {}) {
  const safe = {
    data: {},
    trace_id: safeId(span.trace_id, TRACE_ID) ?? '00000000000000000000000000000000',
    span_id: safeId(span.span_id, SPAN_ID) ?? '0000000000000000',
    start_timestamp: finiteNumber(span.start_timestamp) ?? 0,
  };
  const parentSpanId = safeId(span.parent_span_id, SPAN_ID);
  const segmentId = safeId(span.segment_id, SPAN_ID);
  const timestamp = finiteNumber(span.timestamp);
  const exclusiveTime = finiteNumber(span.exclusive_time);
  if (parentSpanId) safe.parent_span_id = parentSpanId;
  if (segmentId) safe.segment_id = segmentId;
  if (timestamp !== undefined) safe.timestamp = timestamp;
  if (exclusiveTime !== undefined && exclusiveTime >= 0) safe.exclusive_time = exclusiveTime;
  if (SAFE_SPAN_OPS.has(span.op)) safe.op = span.op;
  if (SAFE_SPAN_STATUSES.has(span.status)) safe.status = span.status;
  if (typeof span.is_segment === 'boolean') safe.is_segment = span.is_segment;
  return safe;
}

function sanitizeTags(tags) {
  if (!tags || typeof tags !== 'object') return undefined;
  const safe = {};
  if (tags.protocol_version === 'EP/1.1-v2') safe.protocol_version = tags.protocol_version;
  if (tags.service === 'emilia-protocol-api') safe.service = tags.service;
  if (tags.runtime === 'edge') safe.runtime = tags.runtime;
  return Object.keys(safe).length ? safe : undefined;
}

function sanitizeSentryEvent(event = {}, hint) {
  // Attachments bypass the event object and are added to the envelope later.
  if (hint && typeof hint === 'object') hint.attachments = [];

  const safe = { environment: sentryEnvironment };
  const eventId = safeId(event.event_id, TRACE_ID);
  const timestamp = finiteNumber(event.timestamp);
  const startTimestamp = finiteNumber(event.start_timestamp);
  const method = safeMethod(event.request?.method);
  const trace = sanitizeTraceContext(event.contexts?.trace);
  const tags = sanitizeTags(event.tags);

  if (eventId) safe.event_id = eventId;
  if (timestamp !== undefined) safe.timestamp = timestamp;
  if (startTimestamp !== undefined) safe.start_timestamp = startTimestamp;
  if (SAFE_LEVELS.has(event.level)) safe.level = event.level;
  if (SAFE_PLATFORMS.has(event.platform)) safe.platform = event.platform;
  if (method) safe.request = { method };
  if (trace) safe.contexts = { trace };
  if (tags) safe.tags = tags;

  if (event.type === 'transaction') {
    safe.type = 'transaction';
    safe.transaction = '[route suppressed]';
    safe.spans = Array.isArray(event.spans)
      ? event.spans.slice(0, 1000).map(sanitizeSentrySpan)
      : [];
  } else {
    const exception = sanitizeException(event.exception);
    if (exception) safe.exception = exception;
    else safe.message = '[details suppressed]';
  }
  return safe;
}

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: sentryEnvironment,

  // Keep traces low to avoid latency impact on Edge routes.
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.05 : 0,

  // Only activate when DSN is configured — safe no-op otherwise.
  enabled: !!process.env.SENTRY_DSN,

  // Sentry 10 enables several collection categories when `dataCollection` is
  // present unless every field is explicit. Keep this closed by construction.
  sendDefaultPii: false,
  includeLocalVariables: false,
  attachStacktrace: false,
  maxBreadcrumbs: 0,
  enableLogs: false,
  enableMetrics: false,
  dataCollection: {
    userInfo: false,
    cookies: false,
    httpHeaders: { request: false, response: false },
    httpBodies: [],
    queryParams: false,
    genAI: { inputs: false, outputs: false },
    stackFrameVariables: false,
    frameContextLines: 0,
  },

  // Tag all Edge events consistently with server events for cross-runtime correlation.
  initialScope: {
    tags: {
      protocol_version: 'EP/1.1-v2',
      service: 'emilia-protocol-api',
      runtime: 'edge',
    },
  },

  beforeSend: sanitizeSentryEvent,
  beforeSendTransaction: sanitizeSentryEvent,
  beforeSendSpan: sanitizeSentrySpan,
  beforeBreadcrumb: () => null,
  beforeSendLog: () => null,
  beforeSendMetric: () => null,
});
