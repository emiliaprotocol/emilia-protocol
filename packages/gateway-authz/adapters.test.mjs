// SPDX-License-Identifier: Apache-2.0
//
// Proxy adapters. The Envoy handler is exercised over a real `node:http`
// server, because that is exactly what Envoy talks to; the Kong handler is
// exercised through a PDK stand-in, because a Kong runtime is not a Node
// dependency. Both share the one core whose hostile cases authz.test.mjs pins.

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';

import { createExternalAuthorizer } from './authz.mjs';
import {
  createEnvoyHttpHandler,
  envoyDescriptor,
  toEnvoyHttpResponse,
} from './envoy.mjs';
import {
  createKongAccessHandler,
  kongAuthzDecision,
  kongDescriptor,
  toKongExit,
} from './kong.mjs';
import { carrierFor, mintReceipt, spyStore } from './fixtures.mjs';

const TARGET = 'payments.internal.example';
const APPROVED_BODY = Buffer.from('{"beneficiary":"acct_A","amount":25000}', 'utf8');
const SUBSTITUTED_BODY = Buffer.from('{"beneficiary":"acct_B","amount":25000}', 'utf8');

function newAuthorizer(overrides = {}) {
  const store = spyStore();
  const authorizer = createExternalAuthorizer({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store,
    ...overrides,
  });
  return { authorizer, store };
}

function approvedFor(authorizer, { body = APPROVED_BODY, path = '/v1/payments', query = '' } = {}) {
  const binding = authorizer.bindingFor({
    method: 'POST',
    path,
    query,
    target: TARGET,
    headers: {},
    bodyBytes: new Uint8Array(body),
  });
  return mintReceipt(binding.boundAction, binding.canonicalAction);
}

// ── Envoy ext_authz, HTTP variant ──────────────────────────────────────────

/** Headers Envoy forwards, given the Lua projection in the envoy.yaml reference. */
function envoyHeaders({ receipt, uri = '/v1/payments', partial = 'false', method = 'POST' } = {}) {
  return {
    'x-ep-original-method': method,
    'x-ep-original-uri': uri,
    'x-ep-original-host': TARGET,
    'x-ep-original-scheme': 'https',
    'x-envoy-auth-partial-body': partial,
    ...(receipt ? { 'x-emilia-receipt': carrierFor(receipt) } : {}),
  };
}

async function callEnvoyHandler(authorizer, { headers, body }) {
  const server = createServer(createEnvoyHttpHandler(authorizer));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/envoy-auth/v1/payments`, {
      method: 'POST',
      headers,
      body,
    });
    const text = await response.text();
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: text.length > 0 ? JSON.parse(text) : null,
    };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('ENVOY: an allow is a 200 carrying only the verified action and receipt id', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const result = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders({ receipt }),
    body: APPROVED_BODY,
  });

  assert.equal(result.status, 200);
  assert.equal(result.headers['x-emilia-verified-receipt-id'], receipt.payload.receipt_id);
  assert.match(result.headers['x-emilia-verified-action'], /^payments\.release:sha256:/u);
  assert.equal(result.body, null);
  // The allow is returned only after the authority is spent: Envoy forwards the
  // moment it sees the 200, and there is no later point at which releasing
  // would be sound.
  assert.deepEqual(store.verbs(), ['reserve', 'commit']);
});

test('ENVOY HOSTILE: the receipt for one body does not authorize another', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer, { body: APPROVED_BODY });
  const result = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders({ receipt }),
    body: SUBSTITUTED_BODY,
  });

  assert.equal(result.status, 428);
  assert.equal(result.headers['x-ep-refusal-reason'], 'action_mismatch');
  assert.equal(result.body.rejected.reason, 'action_mismatch');
  assert.equal(result.headers['content-type'], 'application/problem+json');
  assert.deepEqual(store.verbs(), []);
});

test('ENVOY HOSTILE: a missing receipt gets the 428 Receipt Required challenge', async () => {
  const { authorizer } = newAuthorizer();
  const result = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders(),
    body: APPROVED_BODY,
  });
  assert.equal(result.status, 428);
  assert.equal(result.headers['x-ep-refusal-reason'], 'receipt_required');
  assert.match(result.body.required.action, /^payments\.release:sha256:/u);
  assert.equal(result.body.required.proof_header, 'X-EMILIA-Receipt');
});

test('ENVOY HOSTILE: replay is refused on the second authorization call', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const headers = envoyHeaders({ receipt });

  const first = await callEnvoyHandler(authorizer, { headers, body: APPROVED_BODY });
  const second = await callEnvoyHandler(authorizer, { headers, body: APPROVED_BODY });

  assert.equal(first.status, 200);
  assert.equal(second.status, 428);
  assert.equal(second.headers['x-ep-refusal-reason'], 'replay_refused');
});

test('ENVOY: `with_request_body` missing means every request is refused', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  // Envoy only sets x-envoy-auth-partial-body when with_request_body is
  // configured. Without it the auth call carries no body, so nothing is
  // bindable and the deployment would otherwise be carrying an unbound receipt.
  const headers = envoyHeaders({ receipt });
  delete headers['x-envoy-auth-partial-body'];

  const result = await callEnvoyHandler(authorizer, { headers, body: '' });
  assert.equal(result.status, 500);
  assert.equal(result.headers['x-ep-refusal-reason'], 'request_body_not_buffered');
});

test('ENVOY: a partial body is refused rather than hashed as a prefix', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const result = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders({ receipt, partial: 'true' }),
    body: APPROVED_BODY.subarray(0, 10),
  });
  assert.equal(result.status, 500);
  assert.equal(result.headers['x-ep-refusal-reason'], 'request_body_truncated');
});

test('ENVOY: the query string is split off the forwarded URI and bound', async () => {
  const { authorizer } = newAuthorizer();
  const descriptor = envoyDescriptor({
    headers: envoyHeaders({ uri: '/v1/payments?dryRun=false&x=1' }),
    bodyBytes: new Uint8Array(APPROVED_BODY),
  });
  assert.equal(descriptor.path, '/v1/payments');
  assert.equal(descriptor.query, 'dryRun=false&x=1');

  const receipt = approvedFor(authorizer, { query: 'dryRun=false&x=1' });
  const allowed = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders({ receipt, uri: '/v1/payments?dryRun=false&x=1' }),
    body: APPROVED_BODY,
  });
  assert.equal(allowed.status, 200);

  const tampered = await callEnvoyHandler(authorizer, {
    headers: envoyHeaders({ receipt, uri: '/v1/payments?dryRun=true&x=1' }),
    body: APPROVED_BODY,
  });
  assert.equal(tampered.status, 428);
  assert.equal(tampered.headers['x-ep-refusal-reason'], 'action_mismatch');
});

test('ENVOY: missing proxy metadata is refused, not guessed', async () => {
  const { authorizer } = newAuthorizer();
  const headers = envoyHeaders();
  delete headers['x-ep-original-host'];
  const result = await callEnvoyHandler(authorizer, { headers, body: APPROVED_BODY });
  assert.equal(result.headers['x-ep-refusal-reason'], 'proxy_metadata_invalid');
  // A missing Lua projection is a gateway misconfiguration, in the same class
  // as an unbuffered body. A 4xx would teach operators to blame callers.
  assert.equal(result.status, 500);
});

test('ENVOY: the response shape is exactly what ext_authz consumes', () => {
  const allow = toEnvoyHttpResponse({
    ok: true,
    setHeaders: { 'x-emilia-verified-action': 'a', 'x-emilia-verified-receipt-id': 'r' },
  });
  assert.deepEqual(allow, {
    status: 200,
    headers: { 'x-emilia-verified-action': 'a', 'x-emilia-verified-receipt-id': 'r' },
    body: '',
  });

  const deny = toEnvoyHttpResponse({
    ok: false,
    status: 428,
    reason: 'receipt_required',
    headers: { 'x-ep-refusal-reason': 'receipt_required' },
    body: { rejected: { reason: 'receipt_required' } },
  });
  assert.equal(deny.status, 428);
  assert.equal(JSON.parse(deny.body).rejected.reason, 'receipt_required');
});

// ── Kong ───────────────────────────────────────────────────────────────────

/** Stand-in for the Kong JS PDK: records what the plugin did to the request. */
function fakeKong({ method = 'POST', path = '/v1/payments', rawQuery = '', headers = {}, rawBody }) {
  const applied = { setHeaders: {}, clearedHeaders: [], exit: null };
  return {
    applied,
    request: {
      async getMethod() { return method; },
      async getPath() { return path; },
      async getRawQuery() { return rawQuery; },
      async getHeaders() { return headers; },
      async getRawBody() { return rawBody; },
      async getHost() { return TARGET; },
    },
    response: {
      async exit(status, body, exitHeaders) { applied.exit = { status, body, headers: exitHeaders }; },
    },
    service: {
      request: {
        async setHeader(name, value) { applied.setHeaders[name] = value; },
        async clearHeader(name) { applied.clearedHeaders.push(name); },
      },
    },
  };
}

test('KONG: an allow sets the verified headers and strips the proof carrier', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const kong = fakeKong({
    headers: { 'x-emilia-receipt': carrierFor(receipt) },
    rawBody: APPROVED_BODY,
  });

  const decision = await createKongAccessHandler(authorizer, { target: TARGET })(kong);

  assert.equal(decision.exit, false);
  assert.equal(kong.applied.exit, null, 'an allowed request must not be terminated');
  assert.equal(kong.applied.setHeaders['x-emilia-verified-receipt-id'], receipt.payload.receipt_id);
  assert.deepEqual(kong.applied.clearedHeaders, ['x-emilia-receipt']);
  assert.deepEqual(store.verbs(), ['reserve', 'commit']);
});

test('KONG HOSTILE: the receipt for one body does not authorize another', async () => {
  const { authorizer, store } = newAuthorizer();
  const receipt = approvedFor(authorizer, { body: APPROVED_BODY });
  const kong = fakeKong({
    headers: { 'x-emilia-receipt': carrierFor(receipt) },
    rawBody: SUBSTITUTED_BODY,
  });

  await createKongAccessHandler(authorizer, { target: TARGET })(kong);

  assert.equal(kong.applied.exit.status, 428);
  assert.equal(kong.applied.exit.body.rejected.reason, 'action_mismatch');
  assert.equal(kong.applied.exit.headers['x-ep-refusal-reason'], 'action_mismatch');
  assert.deepEqual(kong.applied.setHeaders, {});
  assert.deepEqual(store.verbs(), []);
});

test('KONG HOSTILE: a missing receipt terminates with the 428 challenge', async () => {
  const { authorizer } = newAuthorizer();
  const kong = fakeKong({ rawBody: APPROVED_BODY });
  await createKongAccessHandler(authorizer, { target: TARGET })(kong);
  assert.equal(kong.applied.exit.status, 428);
  assert.equal(kong.applied.exit.headers['x-ep-refusal-reason'], 'receipt_required');
});

test('KONG HOSTILE: replay is refused on the second request', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const handler = createKongAccessHandler(authorizer, { target: TARGET });
  const headers = { 'x-emilia-receipt': carrierFor(receipt) };

  const first = fakeKong({ headers, rawBody: APPROVED_BODY });
  await handler(first);
  const second = fakeKong({ headers, rawBody: APPROVED_BODY });
  await handler(second);

  assert.equal(first.applied.exit, null);
  assert.equal(second.applied.exit.headers['x-ep-refusal-reason'], 'replay_refused');
});

test('KONG: a body nginx did not buffer refuses instead of proxying unbound', async () => {
  const { authorizer } = newAuthorizer();
  const receipt = approvedFor(authorizer);
  const handler = createKongAccessHandler(authorizer, { target: TARGET });

  // get_raw_body() returns nothing once the body exceeds client_body_buffer_size
  // and nginx spills it to a temp file. Proxying it would forward a body no
  // receipt ever covered.
  const spilled = fakeKong({ headers: { 'x-emilia-receipt': carrierFor(receipt) }, rawBody: undefined });
  await handler(spilled);
  assert.equal(spilled.applied.exit.status, 500);
  assert.equal(spilled.applied.exit.headers['x-ep-refusal-reason'], 'request_body_not_buffered');
  assert.deepEqual(spilled.applied.setHeaders, {});

  const declared = await kongAuthzDecision(authorizer, {
    method: 'POST',
    path: '/v1/payments',
    target: TARGET,
    headers: {},
    rawBody: APPROVED_BODY,
    bodyBuffered: false,
  });
  assert.equal(declared.exit, true);
  assert.equal(declared.body.rejected.reason, 'request_body_not_buffered');
});

test('KONG: a string body is bound as its UTF-8 bytes', () => {
  const fromString = kongDescriptor({
    method: 'POST',
    path: '/v1/payments',
    target: TARGET,
    headers: {},
    rawBody: APPROVED_BODY.toString('utf8'),
  });
  assert.ok(fromString.bodyBytes instanceof Uint8Array);
  assert.deepEqual(Buffer.from(fromString.bodyBytes), APPROVED_BODY);
});

test('KONG: the exit shape is exactly what kong.response.exit consumes', () => {
  const allow = toKongExit({
    ok: true,
    setHeaders: { 'x-emilia-verified-action': 'a' },
    removeHeaders: ['x-emilia-receipt'],
  });
  assert.deepEqual(allow, {
    exit: false,
    setHeaders: { 'x-emilia-verified-action': 'a' },
    clearHeaders: ['x-emilia-receipt'],
  });

  const deny = toKongExit({
    ok: false,
    status: 428,
    headers: { 'x-ep-refusal-reason': 'receipt_required' },
    body: { rejected: { reason: 'receipt_required' } },
  });
  assert.equal(deny.exit, true);
  assert.equal(deny.status, 428);
  assert.equal(deny.body.rejected.reason, 'receipt_required');
});

test('both adapters refuse rather than throw, for every malformed input', async () => {
  const { authorizer } = newAuthorizer();
  const malformed = [
    { headers: {}, body: APPROVED_BODY },
    { headers: envoyHeaders({ partial: 'maybe' }), body: APPROVED_BODY },
    { headers: { ...envoyHeaders(), 'x-ep-original-uri': 'v1/payments' }, body: APPROVED_BODY },
  ];
  for (const input of malformed) {
    const result = await callEnvoyHandler(authorizer, input);
    assert.ok(result.status >= 400, 'a malformed auth call must deny');
    assert.equal(typeof result.headers['x-ep-refusal-reason'], 'string');
    assert.ok(result.headers['x-ep-refusal-reason'].length > 0);
  }

  for (const snapshot of [
    { method: 'PO ST', path: '/v1/payments', target: TARGET, headers: {}, rawBody: APPROVED_BODY },
    { method: 'POST', path: 'v1/payments', target: TARGET, headers: {}, rawBody: APPROVED_BODY },
    { method: 'POST', path: '/v1/payments', target: TARGET, headers: {}, rawBody: null },
  ]) {
    const decision = await kongAuthzDecision(authorizer, snapshot);
    assert.equal(decision.exit, true);
    assert.equal(typeof decision.body.rejected.reason, 'string');
    assert.ok(decision.status >= 400);
  }
});
