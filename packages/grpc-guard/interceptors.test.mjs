// SPDX-License-Identifier: Apache-2.0
//
// Transport wiring. The server interceptor is exercised end to end against a
// plain service definition and plain handlers — that is the real integration
// shape, not a mock. The client interceptor is exercised against a fake that
// implements the @grpc/grpc-js interceptor contract this package codes to; it
// is NOT proof against a live grpc-js client. See README, "What is proven".

import assert from 'node:assert/strict';
import test from 'node:test';

import { createGrpcReceiptGuard } from './guard.mjs';
import {
  createClientInterceptor,
  createClientReceiptAttacher,
  createServerInterceptor,
  passthroughRequestDefinition,
} from './interceptors.mjs';
import { GRPC_STATUS } from './status.mjs';
import { carrierFor, mintReceipt, spyStore } from './fixtures.mjs';

const METHOD_PATH = '/emilia.payments.v1.Payments/ReleasePayment';
const TARGET = 'payments.internal.example:443';

/** A protobuf-shaped service definition; JSON stands in for the codec. */
const SERVICE = {
  releasePayment: {
    path: METHOD_PATH,
    requestStream: false,
    responseStream: false,
    requestSerialize: (message) => Buffer.from(JSON.stringify(message), 'utf8'),
    requestDeserialize: (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8')),
    responseSerialize: (message) => Buffer.from(JSON.stringify(message), 'utf8'),
    responseDeserialize: (bytes) => JSON.parse(Buffer.from(bytes).toString('utf8')),
  },
};

const encode = (message) => SERVICE.releasePayment.requestSerialize(message);

function newGuard(overrides = {}) {
  const store = spyStore();
  const guard = createGrpcReceiptGuard({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store,
    ...overrides,
  });
  return { guard, store };
}

function approvedFor(guard, bytes) {
  const binding = guard.bindingFor({ methodPath: METHOD_PATH, requestBytes: bytes });
  return mintReceipt(binding.boundAction, binding.canonicalAction);
}

/** Invoke a guarded handler the way a gRPC server would, and collect the result. */
function invoke(handler, { request, metadata = {} }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const callback = (error, value) => {
      if (settled) return;
      settled = true;
      resolve({ error, value });
    };
    Promise.resolve(handler({ request, metadata }, callback)).catch(reject);
  });
}

test('the guarded definition delivers wire bytes and the handler still gets the message', async () => {
  const { guard } = newGuard();
  const { definition, wrap } = createServerInterceptor({ guard, service: SERVICE });

  assert.notEqual(definition.releasePayment.requestDeserialize, SERVICE.releasePayment.requestDeserialize);
  assert.equal(SERVICE.releasePayment.requestDeserialize(encode({ a: 1 })).a, 1, 'input definition mutated');
  const raw = encode({ beneficiary: 'acct_A', amount: 25000 });
  assert.equal(definition.releasePayment.requestDeserialize(raw), raw);

  const seen = [];
  const implementation = wrap({
    releasePayment(call, callback) {
      seen.push(call.request);
      callback(null, { status: 'RELEASED', receipt: call.emiliaReceipt });
    },
  });

  const receipt = approvedFor(guard, raw);
  const result = await invoke(implementation.releasePayment, {
    request: raw,
    metadata: { 'x-emilia-receipt': carrierFor(receipt) },
  });

  assert.equal(result.error, null);
  assert.equal(result.value.status, 'RELEASED');
  assert.deepEqual(seen, [{ beneficiary: 'acct_A', amount: 25000 }]);
  assert.equal(result.value.receipt.receipt_id, receipt.payload.receipt_id);
});

test('HOSTILE: the receipt for one body does not run the handler on another', async () => {
  const { guard } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const approved = encode({ beneficiary: 'acct_A', amount: 25000 });
  const substituted = encode({ beneficiary: 'acct_B', amount: 25000 });

  let ran = 0;
  const implementation = wrap({
    releasePayment(call, callback) { ran += 1; callback(null, { status: 'RELEASED' }); },
  });

  const receipt = approvedFor(guard, approved);
  const result = await invoke(implementation.releasePayment, {
    request: substituted,
    metadata: { 'x-emilia-receipt': carrierFor(receipt) },
  });

  assert.equal(ran, 0, 'the handler must not run on an unapproved body');
  assert.equal(result.error.code, GRPC_STATUS.PERMISSION_DENIED);
  assert.equal(result.error.details, 'action_mismatch');
});

test('HOSTILE: a missing receipt refuses with FAILED_PRECONDITION and no crash', async () => {
  const { guard } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  let ran = 0;
  const implementation = wrap({
    releasePayment(call, callback) { ran += 1; callback(null, {}); },
  });
  const result = await invoke(implementation.releasePayment, { request: encode({ a: 1 }) });
  assert.equal(ran, 0);
  assert.equal(result.error.code, GRPC_STATUS.FAILED_PRECONDITION);
  assert.equal(result.error.details, 'receipt_required');
});

test('HOSTILE: replay through the interceptor refuses and runs the handler once', async () => {
  const { guard } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const raw = encode({ beneficiary: 'acct_A', amount: 25000 });
  let ran = 0;
  const implementation = wrap({
    releasePayment(call, callback) { ran += 1; callback(null, { status: 'RELEASED' }); },
  });
  const receipt = approvedFor(guard, raw);
  const metadata = { 'x-emilia-receipt': carrierFor(receipt) };

  const first = await invoke(implementation.releasePayment, { request: raw, metadata });
  const second = await invoke(implementation.releasePayment, { request: raw, metadata });

  assert.equal(first.error, null);
  assert.equal(second.error.code, GRPC_STATUS.ALREADY_EXISTS);
  assert.equal(second.error.details, 'replay_refused');
  assert.equal(ran, 1);
});

test('INDETERMINATE: a handler that never answers consumes the authority', async () => {
  const { guard, store } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE, handlerTimeoutMs: 10 });
  const raw = encode({ beneficiary: 'acct_A', amount: 25000 });
  const implementation = wrap({
    releasePayment() { /* the effect may have left; no answer ever arrives */ },
  });
  const receipt = approvedFor(guard, raw);
  const metadata = { 'x-emilia-receipt': carrierFor(receipt) };

  const result = await invoke(implementation.releasePayment, { request: raw, metadata });
  assert.equal(result.error.code, GRPC_STATUS.UNKNOWN);
  assert.equal(result.error.details, 'handler_outcome_indeterminate');
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'commit']);

  const retry = await invoke(implementation.releasePayment, { request: raw, metadata });
  assert.equal(retry.error.details, 'replay_refused');
});

test('an undecodable request releases the authority without entering the handler', async () => {
  const { guard, store } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const garbage = Buffer.from('not json at all', 'utf8');
  let ran = 0;
  const implementation = wrap({
    releasePayment(call, callback) { ran += 1; callback(null, {}); },
  });
  const receipt = approvedFor(guard, garbage);
  const result = await invoke(implementation.releasePayment, {
    request: garbage,
    metadata: { 'x-emilia-receipt': carrierFor(receipt) },
  });
  assert.equal(ran, 0);
  assert.equal(result.error.code, GRPC_STATUS.INVALID_ARGUMENT);
  assert.equal(result.error.details, 'request_deserialization_failed');
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'release']);
});

test('a handler error is delivered to the client and still spends the authority', async () => {
  const { guard, store } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const raw = encode({ beneficiary: 'acct_A', amount: 1 });
  const implementation = wrap({
    releasePayment(call, callback) {
      callback(Object.assign(new Error('upstream refused'), { code: GRPC_STATUS.ABORTED }));
    },
  });
  const receipt = approvedFor(guard, raw);
  const result = await invoke(implementation.releasePayment, {
    request: raw,
    metadata: { 'x-emilia-receipt': carrierFor(receipt) },
  });
  assert.equal(result.error.code, GRPC_STATUS.ABORTED);
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'commit']);
});

test('wrapping refuses an implementation that is missing a guarded method', () => {
  const { guard } = newGuard();
  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  assert.throws(() => wrap({}), /missing "releasePayment"/u);
  assert.throws(
    () => passthroughRequestDefinition(SERVICE, ['noSuchMethod']),
    /unknown method "noSuchMethod"/u,
  );
});

// ── client side ────────────────────────────────────────────────────────────

test('the attacher binds the bytes it is about to send', async () => {
  const { guard } = newGuard();
  const raw = encode({ beneficiary: 'acct_A', amount: 25000 });
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: (binding) => mintReceipt(binding.boundAction, binding.canonicalAction),
  });

  const metadata = {};
  const attached = await attacher.attach(metadata, { methodPath: METHOD_PATH, requestBytes: raw });
  assert.equal(attached.ok, true);

  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const implementation = wrap({
    releasePayment(call, callback) { callback(null, { status: 'RELEASED' }); },
  });
  const result = await invoke(implementation.releasePayment, { request: raw, metadata });
  assert.equal(result.error, null);
  assert.equal(result.value.status, 'RELEASED');
});

test('the client attach is a convenience: binding the wrong bytes still refuses at the server', async () => {
  const { guard } = newGuard();
  const approved = encode({ beneficiary: 'acct_A', amount: 25000 });
  const sent = encode({ beneficiary: 'acct_B', amount: 25000 });
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: (binding) => mintReceipt(binding.boundAction, binding.canonicalAction),
  });

  const metadata = {};
  await attacher.attach(metadata, { methodPath: METHOD_PATH, requestBytes: approved });

  const { wrap } = createServerInterceptor({ guard, service: SERVICE });
  const implementation = wrap({
    releasePayment(call, callback) { callback(null, { status: 'RELEASED' }); },
  });
  const result = await invoke(implementation.releasePayment, { request: sent, metadata });
  assert.equal(result.error.details, 'action_mismatch');
});

test('the attacher refuses rather than sending an unauthorized call', async () => {
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: () => null,
  });
  const denied = await attacher.attach({}, { methodPath: METHOD_PATH, requestBytes: encode({ a: 1 }) });
  assert.equal(denied.ok, false);
  assert.equal(denied.reason, 'receipt_unavailable');
  assert.equal(denied.code, GRPC_STATUS.FAILED_PRECONDITION);

  const throwing = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: () => { throw new Error('approval service down'); },
  });
  const failed = await throwing.attach({}, { methodPath: METHOD_PATH, requestBytes: encode({ a: 1 }) });
  assert.equal(failed.ok, false);
  assert.equal(failed.reason, 'receipt_acquisition_failed');
});

/** Minimal stand-in for the @grpc/grpc-js client interceptor contract. */
function fakeGrpc() {
  class Metadata {
    #values = new Map();
    set(key, value) { this.#values.set(key, value); }
    get(key) { return this.#values.has(key) ? [this.#values.get(key)] : []; }
  }
  class InterceptingCall {
    constructor(nextCall, requester) {
      this.nextCall = nextCall;
      this.requester = requester;
    }
  }
  return { Metadata, InterceptingCall };
}

test('the client interceptor holds start until the message is bound, then sends', async () => {
  const grpc = fakeGrpc();
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: (binding) => mintReceipt(binding.boundAction, binding.canonicalAction),
  });
  const interceptor = createClientInterceptor({ grpc, attacher });

  const options = { method_definition: SERVICE.releasePayment };
  const call = interceptor(options, () => ({ nextCall: true }));

  const metadata = new grpc.Metadata();
  const listener = { statuses: [], onReceiveStatus(status) { this.statuses.push(status); } };
  const started = [];
  call.requester.start(metadata, listener, (md) => started.push(md));
  assert.deepEqual(started, [], 'start must wait for the message it has to bind');

  const raw = encode({ beneficiary: 'acct_A', amount: 25000 });
  const sent = [];
  call.requester.sendMessage(raw, (message) => sent.push(message));
  await new Promise((resolve) => { setImmediate(resolve); });

  assert.equal(started.length, 1, 'start must fire once the receipt is attached');
  assert.deepEqual(sent, [raw]);
  assert.deepEqual(listener.statuses, []);
  assert.equal(metadata.get('x-emilia-receipt').length, 1);
});

test('the client interceptor fails the call locally instead of sending it unauthorized', async () => {
  const grpc = fakeGrpc();
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: () => null,
  });
  const interceptor = createClientInterceptor({ grpc, attacher });
  const call = interceptor({ method_definition: SERVICE.releasePayment }, () => ({}));

  const listener = { statuses: [], onReceiveStatus(status) { this.statuses.push(status); } };
  const started = [];
  call.requester.start(new grpc.Metadata(), listener, (md) => started.push(md));

  const sent = [];
  call.requester.sendMessage(encode({ a: 1 }), (message) => sent.push(message));
  await new Promise((resolve) => { setImmediate(resolve); });

  assert.deepEqual(sent, [], 'an unauthorized message must never be sent');
  assert.deepEqual(started, [], 'metadata must never be sent for a refused call');
  assert.equal(listener.statuses.length, 1);
  assert.equal(listener.statuses[0].code, GRPC_STATUS.FAILED_PRECONDITION);
  assert.equal(listener.statuses[0].details, 'receipt_unavailable');
});

test('the client interceptor refuses a message it cannot bind to bytes', async () => {
  const grpc = fakeGrpc();
  const attacher = createClientReceiptAttacher({
    baseAction: 'payments.release',
    target: TARGET,
    acquireReceipt: (binding) => mintReceipt(binding.boundAction, binding.canonicalAction),
  });
  const interceptor = createClientInterceptor({ grpc, attacher });
  // No pass-through codec and no opt-in: the message object cannot be bound to
  // the octets the wire will carry, so the call is refused rather than guessed.
  const call = interceptor({ method_definition: SERVICE.releasePayment }, () => ({}));
  const listener = { statuses: [], onReceiveStatus(status) { this.statuses.push(status); } };
  call.requester.start(new grpc.Metadata(), listener, () => {});
  const sent = [];
  call.requester.sendMessage({ beneficiary: 'acct_A' }, (message) => sent.push(message));
  await new Promise((resolve) => { setImmediate(resolve); });

  assert.deepEqual(sent, []);
  assert.equal(listener.statuses[0].details, 'request_bytes_reserialization_not_permitted');
  assert.equal(listener.statuses[0].code, GRPC_STATUS.INVALID_ARGUMENT);
});

test('the client interceptor requires a grpc module and an attacher', () => {
  assert.throws(() => createClientInterceptor({}), /@grpc\/grpc-js module is required/u);
  assert.throws(() => createClientInterceptor({ grpc: fakeGrpc() }), /attacher is required/u);
});
