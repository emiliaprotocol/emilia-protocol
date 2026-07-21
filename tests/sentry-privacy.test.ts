/**
 * Sentry privacy boundary tests.
 *
 * Loads the real browser, server, and edge configuration with a mocked SDK and
 * proves that every outbound callback is structural-metadata-only.
 */

import { describe, expect, it, vi } from 'vitest';

const sentry = vi.hoisted(() => ({ init: vi.fn() }));
vi.mock('@sentry/nextjs', () => ({ init: sentry.init }));

await import('../sentry.client.config.js');
await import('../sentry.server.config.js');
await import('../sentry.edge.config.js');

const optionsByRuntime = new Map(
  sentry.init.mock.calls.map(([options]) => [options.initialScope.tags.runtime, options]),
);
const SECRET = 'receipt-action-secret-7f3c9e';
const TRACE_ID = 'a'.repeat(32);
const SPAN_ID = 'b'.repeat(16);
const PARENT_SPAN_ID = 'c'.repeat(16);

function serviceFor(runtime) {
  return runtime === 'browser' ? 'emilia-protocol-web' : 'emilia-protocol-api';
}

function hostileSpan() {
  return {
    data: {
      action: SECRET,
      receipt: { signature: SECRET },
      'http.request.body': SECRET,
      'http.response.status_code': 200,
    },
    description: `POST /api/signoff/${SECRET}`,
    op: 'http.server',
    parent_span_id: PARENT_SPAN_ID,
    span_id: SPAN_ID,
    trace_id: TRACE_ID,
    start_timestamp: 1,
    timestamp: 2,
    status: 'ok',
    origin: SECRET,
    measurements: { [SECRET]: { value: 1 } },
    links: [{ trace_id: TRACE_ID, span_id: SPAN_ID, attributes: { secret: SECRET } }],
  };
}

function hostileEvent(runtime, type) {
  return {
    event_id: 'd'.repeat(32),
    timestamp: 3,
    start_timestamp: 1,
    type,
    level: 'error',
    platform: 'javascript',
    message: SECRET,
    logentry: { message: SECRET, params: [SECRET] },
    transaction: `POST /api/trust/gate/${SECRET}`,
    request: {
      method: 'post',
      url: `https://example.test/api/receipts?receipt=${SECRET}`,
      query_string: `receipt=${SECRET}`,
      cookies: SECRET,
      headers: { authorization: SECRET, cookie: SECRET, 'user-agent': SECRET },
      data: { harmlessKey: SECRET, action: { amount: SECRET } },
      env: { LOCAL_SECRET: SECRET },
    },
    exception: {
      values: [{
        type: 'TypeError',
        value: SECRET,
        stacktrace: {
          frames: [{
            filename: SECRET,
            function: SECRET,
            vars: { receipt: SECRET },
            pre_context: [SECRET],
            context_line: SECRET,
            post_context: [SECRET],
          }],
        },
        mechanism: { type: SECRET, data: { action: SECRET } },
      }],
    },
    breadcrumbs: [{ category: 'request', message: SECRET, data: { receipt: SECRET } }],
    contexts: {
      trace: {
        trace_id: TRACE_ID,
        span_id: SPAN_ID,
        parent_span_id: PARENT_SPAN_ID,
        op: 'http.server',
        status: 'ok',
        data: { action: SECRET },
      },
      receipt: { exactAction: SECRET },
    },
    tags: {
      protocol_version: 'EP/1.1-v2',
      service: serviceFor(runtime),
      runtime,
      action: SECRET,
    },
    extra: { benignName: SECRET, receipt: { payload: SECRET } },
    user: { id: SECRET, email: SECRET, ip_address: SECRET },
    spans: [hostileSpan()],
    measurements: { [SECRET]: { value: 1 } },
    fingerprint: [SECRET],
    threads: { values: [{ name: SECRET, stacktrace: { frames: [{ vars: { secret: SECRET } }] } }] },
  };
}

describe('Sentry receipt-safe configuration', () => {
  it('loads browser, server, and edge runtimes', () => {
    expect([...optionsByRuntime.keys()].sort()).toEqual(['browser', 'edge', 'server']);
  });

  for (const runtime of ['browser', 'server', 'edge']) {
    describe(runtime, () => {
      const options = optionsByRuntime.get(runtime);

      it('disables implicit PII, local variables, bodies, logs, metrics, and breadcrumbs', () => {
        expect(options.sendDefaultPii).toBe(false);
        expect(options.includeLocalVariables).toBe(false);
        expect(options.attachStacktrace).toBe(false);
        expect(options.maxBreadcrumbs).toBe(0);
        expect(options.enableLogs).toBe(false);
        expect(options.enableMetrics).toBe(false);
        expect(options.dataCollection).toEqual({
          userInfo: false,
          cookies: false,
          httpHeaders: { request: false, response: false },
          httpBodies: [],
          queryParams: false,
          genAI: { inputs: false, outputs: false },
          stackFrameVariables: false,
          frameContextLines: 0,
        });
        expect(options.beforeBreadcrumb({ message: SECRET })).toBeNull();
        expect(options.beforeSendLog({ body: SECRET })).toBeNull();
        expect(options.beforeSendMetric({ name: SECRET })).toBeNull();
      });

      it('allows only structural error metadata and clears envelope attachments', () => {
        const hint = { attachments: [{ filename: 'receipt.json', data: SECRET }] };
        const sanitized = options.beforeSend(hostileEvent(runtime), hint);
        const serialized = JSON.stringify(sanitized);

        expect(serialized).not.toContain(SECRET);
        expect(hint.attachments).toEqual([]);
        expect(sanitized.request).toEqual({ method: 'POST' });
        expect(sanitized.exception).toEqual({
          values: [{ type: 'TypeError', value: '[details suppressed]' }],
        });
        expect(sanitized.contexts.trace).toEqual({
          trace_id: TRACE_ID,
          span_id: SPAN_ID,
          parent_span_id: PARENT_SPAN_ID,
          op: 'http.server',
          status: 'ok',
        });
        expect(sanitized).not.toHaveProperty('breadcrumbs');
        expect(sanitized).not.toHaveProperty('extra');
        expect(sanitized).not.toHaveProperty('user');
        expect(sanitized).not.toHaveProperty('threads');
      });

      it('removes transaction names, span descriptions, attributes, links, and measurements', () => {
        const span = options.beforeSendSpan(hostileSpan());
        expect(JSON.stringify(span)).not.toContain(SECRET);
        expect(span.data).toEqual({});
        expect(span).not.toHaveProperty('description');
        expect(span).not.toHaveProperty('links');
        expect(span).not.toHaveProperty('measurements');

        const hint = { attachments: [{ filename: 'action.json', data: SECRET }] };
        const transaction = options.beforeSendTransaction(hostileEvent(runtime, 'transaction'), hint);
        expect(JSON.stringify(transaction)).not.toContain(SECRET);
        expect(transaction.transaction).toBe('[route suppressed]');
        expect(transaction.spans).toHaveLength(1);
        expect(transaction.spans[0].data).toEqual({});
        expect(hint.attachments).toEqual([]);
      });
    });
  }
});
