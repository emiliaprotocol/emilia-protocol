// SPDX-License-Identifier: Apache-2.0
//
// Hostile cases for the gRPC guard. Every test here is a way an attacker gets
// a real, validly signed, unexpired receipt and tries to spend it on something
// other than what it authorized.

import assert from 'node:assert/strict';
import test from 'node:test';

import { GRPC_STATUS } from './status.mjs';
import { INDETERMINATE_REASON, createGrpcReceiptGuard } from './guard.mjs';
import { carrierFor, mintReceipt, spyStore } from './fixtures.mjs';

const METHOD = '/emilia.payments.v1.Payments/ReleasePayment';
const OTHER_METHOD = '/emilia.payments.v1.Payments/CancelPayment';
const TARGET = 'payments.internal.example:443';
const APPROVED_BODY = Buffer.from([0x0a, 0x06, 0x61, 0x63, 0x63, 0x74, 0x5f, 0x41]);
const SUBSTITUTED_BODY = Buffer.from([0x0a, 0x06, 0x61, 0x63, 0x63, 0x74, 0x5f, 0x42]);

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

/** A receipt approved for exactly `bytes` on exactly `methodPath`. */
function approvedFor(guard, { methodPath = METHOD, requestBytes = APPROVED_BODY } = {}) {
  const binding = guard.bindingFor({ methodPath, requestBytes });
  return mintReceipt(binding.boundAction, binding.canonicalAction);
}

const call = (receipt, { methodPath = METHOD, requestBytes = APPROVED_BODY } = {}) => ({
  methodPath,
  requestBytes,
  metadata: receipt === null ? {} : { 'x-emilia-receipt': carrierFor(receipt) },
});

test('a receipt bound to this exact request authorizes it', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, true);
  assert.equal(decision.code, GRPC_STATUS.OK);
  assert.equal(decision.receiptId, receipt.payload.receipt_id);
  assert.deepEqual(store.calls, [['reserve', receipt.payload.receipt_id]]);
});

test('HOSTILE: a valid receipt replayed against a DIFFERENT body is refused', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard, { requestBytes: APPROVED_BODY });

  // The receipt is genuine, freshly signed, unexpired, unused. The only thing
  // that changed is the message the agent actually wants executed.
  const decision = await guard.authorize(call(receipt, { requestBytes: SUBSTITUTED_BODY }));

  assert.equal(decision.ok, false);
  assert.equal(decision.code, GRPC_STATUS.PERMISSION_DENIED);
  assert.equal(decision.reason, 'action_mismatch');
  assert.deepEqual(store.calls, [], 'a substituted body must never reach the consumption store');

  // And the same receipt still works for the body it was actually approved for,
  // proving the refusal was about the binding and not about the receipt.
  const honest = await guard.authorize(call(receipt, { requestBytes: APPROVED_BODY }));
  assert.equal(honest.ok, true);
});

test('HOSTILE: a receipt for a different method is refused', async () => {
  const { guard } = newGuard();
  const receipt = approvedFor(guard, { methodPath: OTHER_METHOD });
  const decision = await guard.authorize(call(receipt, { methodPath: METHOD }));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
  assert.equal(decision.code, GRPC_STATUS.PERMISSION_DENIED);
});

test('HOSTILE: a receipt for a different target is refused', async () => {
  const { guard } = newGuard();
  const elsewhere = createGrpcReceiptGuard({
    baseAction: 'payments.release',
    target: 'payments.staging.example:443',
    allowInlineKey: true,
    store: spyStore(),
  });
  const receipt = approvedFor(elsewhere);
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'action_mismatch');
});

test('HOSTILE: a missing receipt is refused with a Receipt Required challenge', async () => {
  const { guard, store } = newGuard();
  const decision = await guard.authorize(call(null));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'receipt_required');
  assert.equal(decision.code, GRPC_STATUS.FAILED_PRECONDITION);
  assert.equal(decision.challenge.required.action, decision.boundAction);
  assert.deepEqual(store.calls, []);
});

test('HOSTILE: replaying the same receipt on the same request is refused', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);

  const first = await guard.authorize(call(receipt));
  assert.equal(first.ok, true);
  const settled = await first.invoke((settle) => { settle({ error: null, value: { ok: true } }); });
  assert.equal(settled.ok, true);

  const replay = await guard.authorize(call(receipt));
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replay_refused');
  assert.equal(replay.code, GRPC_STATUS.ALREADY_EXISTS);
  assert.equal(store.stateOf(receipt.payload.receipt_id), 'committed');
});

test('HOSTILE: an in-flight replay loses the reservation race', async () => {
  const { guard } = newGuard();
  const receipt = approvedFor(guard);
  const [first, second] = await Promise.all([
    guard.authorize(call(receipt)),
    guard.authorize(call(receipt)),
  ]);
  assert.equal([first.ok, second.ok].filter(Boolean).length, 1);
  const refused = first.ok ? second : first;
  assert.equal(refused.reason, 'replay_refused');
});

test('HOSTILE: a forged receipt is refused', async () => {
  const { guard } = newGuard();
  const receipt = approvedFor(guard);
  receipt.payload.claim.canonical_action.request_sha256 = `sha256:${'0'.repeat(64)}`;
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.code, GRPC_STATUS.PERMISSION_DENIED);
});

test('HOSTILE: a garbage carrier is refused, not parsed', async () => {
  const { guard } = newGuard();
  for (const carrier of ['not base64 !!', 'e30', Buffer.from('{}').toString('base64')]) {
    const decision = await guard.authorize({
      methodPath: METHOD,
      requestBytes: APPROVED_BODY,
      metadata: { 'x-emilia-receipt': carrier },
    });
    assert.equal(decision.ok, false, `accepted carrier ${carrier}`);
  }
});

test('every refusal is a returned reason, never a thrown crash', async () => {
  const { guard } = newGuard();
  const receipt = approvedFor(guard);
  const cases = [
    ['no receipt', call(null)],
    ['substituted body', call(receipt, { requestBytes: SUBSTITUTED_BODY })],
    ['unbindable method', { ...call(receipt), methodPath: 'ReleasePayment' }],
    ['request bytes missing', { methodPath: METHOD, requestBytes: undefined, metadata: {} }],
    ['request bytes summarized', { methodPath: METHOD, requestBytes: '{"amount":1}', metadata: {} }],
    ['ambiguous carrier', {
      methodPath: METHOD,
      requestBytes: APPROVED_BODY,
      metadata: { 'x-emilia-receipt': [carrierFor(receipt), carrierFor(receipt)] },
    }],
    ['oversized request', { methodPath: METHOD, requestBytes: new Uint8Array(8), metadata: {} }],
  ];
  for (const [label, input] of cases) {
    // Any throw here fails the test: an unhandled exception at a consequence
    // boundary is an outage, and an outage is how "fail closed" turns into
    // "the guard was removed to get the service back up".
    const decision = await guard.authorize(input);
    assert.equal(decision.ok, false, `${label} was allowed`);
    assert.equal(typeof decision.reason, 'string', `${label} produced no reason`);
    assert.ok(decision.reason.length > 0, `${label} produced an empty reason`);
    assert.equal(typeof decision.code, 'number');
    assert.notEqual(decision.code, GRPC_STATUS.OK);
  }
});

test('an unbindable call is refused before any verification is attempted', async () => {
  const { guard, store } = newGuard();
  const decision = await guard.authorize({
    methodPath: 'not-a-path',
    requestBytes: APPROVED_BODY,
    metadata: {},
  });
  assert.equal(decision.reason, 'method_path_invalid');
  assert.equal(decision.code, GRPC_STATUS.INVALID_ARGUMENT);
  assert.equal(decision.challenge, undefined);
  assert.deepEqual(store.calls, []);
});

test('INDETERMINATE: a handler that never settles consumes the authority', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, true);

  // The handler runs and returns, but never reports an outcome. The guard
  // cannot distinguish "nothing happened" from "the payment left and the
  // response was lost", so the approval must not survive.
  const outcome = await decision.invoke(() => {});

  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, INDETERMINATE_REASON);
  assert.equal(outcome.code, GRPC_STATUS.UNKNOWN);
  assert.equal(outcome.authority, 'consumed');
  assert.deepEqual(
    store.calls.map(([verb]) => verb),
    ['reserve', 'commit'],
    'an indeterminate outcome must never release the authority',
  );
  assert.equal(store.stateOf(receipt.payload.receipt_id), 'committed');

  const replay = await guard.authorize(call(receipt));
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replay_refused');
});

test('INDETERMINATE: a handler that throws consumes the authority', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);
  const decision = await guard.authorize(call(receipt));
  const outcome = await decision.invoke(() => { throw new Error('upstream reset'); });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, 'handler_failed');
  assert.equal(outcome.authority, 'consumed');
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'commit']);
});

test('a late callback cannot revive an already-settled authority', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);
  const decision = await guard.authorize(call(receipt));
  let late;
  const outcome = await decision.invoke((settle) => {
    setTimeout(() => { late = settle; settle({ error: null, value: 'too late' }); }, 0);
  });
  assert.equal(outcome.reason, INDETERMINATE_REASON);
  await new Promise((resolve) => { setTimeout(resolve, 5); });
  assert.equal(typeof late, 'function');
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'commit']);
  await assert.rejects(decision.invoke(() => {}), /already_settled/u);
});

test('the authority can only be released before the handler is entered', async () => {
  const { guard, store } = newGuard();
  const receipt = approvedFor(guard);

  const abandoned = await guard.authorize(call(receipt));
  const released = await abandoned.abandon();
  assert.equal(released.ok, true);
  assert.deepEqual(store.calls.map(([verb]) => verb), ['reserve', 'release']);

  // Released means never spent: the same receipt authorizes the same call again.
  const retried = await guard.authorize(call(receipt));
  assert.equal(retried.ok, true);
  await retried.invoke((settle) => settle({ error: null, value: 'done' }));

  // After invocation there is no release path at all.
  const late = await retried.abandon();
  assert.equal(late.ok, false);
  assert.equal(late.reason, 'authority_not_releasable');
  assert.equal(store.calls.filter(([verb]) => verb === 'release').length, 1);
});

test('a consumption store that cannot answer fails closed', async () => {
  const unavailable = {
    async reserve() { throw new Error('store down'); },
    async commit() { return true; },
    async release() { return true; },
  };
  const guard = createGrpcReceiptGuard({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store: unavailable,
  });
  const decision = await guard.authorize(call(approvedFor(guard)));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'consumption_store_unavailable');
  assert.equal(decision.code, GRPC_STATUS.UNAVAILABLE);
});

test('a commit that fails leaves the reservation standing, so replay still loses', async () => {
  const brokenCommit = {
    reserved: new Set(),
    async reserve(id) { if (this.reserved.has(id)) return false; this.reserved.add(id); return true; },
    async commit() { throw new Error('commit unavailable'); },
    async release() { return true; },
  };
  const guard = createGrpcReceiptGuard({
    baseAction: 'payments.release',
    target: TARGET,
    allowInlineKey: true,
    store: brokenCommit,
  });
  const receipt = approvedFor(guard);
  const decision = await guard.authorize(call(receipt));
  const outcome = await decision.invoke((settle) => settle({ error: null, value: 'done' }));
  assert.equal(outcome.ok, false);
  assert.equal(outcome.reason, 'consumption_commit_failed');
  assert.equal(outcome.code, GRPC_STATUS.INTERNAL);

  const replay = await guard.authorize(call(receipt));
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replay_refused');
});

test('pinned material metadata is part of the approval', async () => {
  const { guard } = newGuard({ materialMetadata: ['x-tenant-id'] });
  const binding = guard.bindingFor({
    methodPath: METHOD,
    requestBytes: APPROVED_BODY,
    metadata: { 'x-tenant-id': 'acme' },
  });
  const receipt = mintReceipt(binding.boundAction, binding.canonicalAction);

  const honest = await guard.authorize({
    methodPath: METHOD,
    requestBytes: APPROVED_BODY,
    metadata: { 'x-tenant-id': 'acme', 'x-emilia-receipt': carrierFor(receipt) },
  });
  assert.equal(honest.ok, true);

  const swapped = await guard.authorize({
    methodPath: METHOD,
    requestBytes: APPROVED_BODY,
    metadata: { 'x-tenant-id': 'rival', 'x-emilia-receipt': carrierFor(receipt) },
  });
  assert.equal(swapped.ok, false);
  assert.equal(swapped.reason, 'action_mismatch');
});

test('stripping the canonical action after signing breaks the signature', async () => {
  const { guard } = newGuard();
  const receipt = approvedFor(guard);
  delete receipt.payload.claim.canonical_action;
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'untrusted_or_invalid_signature');
});

test('pinning the carrier as material metadata is refused at construction', () => {
  // Unsatisfiable rather than merely wrong: the receipt would have to contain
  // its own digest. A deployment must not discover this as a permanent
  // action_mismatch in production.
  assert.throws(
    () => createGrpcReceiptGuard({
      baseAction: 'payments.release',
      target: TARGET,
      materialMetadata: ['X-EMILIA-Receipt'],
    }),
    /carrier cannot be pinned as material metadata/u,
  );
});

test('a validly signed receipt that binds no canonical action is refused', async () => {
  const { guard } = newGuard();
  const binding = guard.bindingFor({ methodPath: METHOD, requestBytes: APPROVED_BODY });
  // Correctly signed, correct action_type, unexpired. It just never committed
  // to WHICH request it approved, which is the property under test.
  const receipt = mintReceipt(binding.boundAction, binding.canonicalAction, {
    omitCanonicalAction: true,
  });
  const decision = await guard.authorize(call(receipt));
  assert.equal(decision.ok, false);
  assert.equal(decision.reason, 'signed_action_required');
  assert.equal(decision.code, GRPC_STATUS.PERMISSION_DENIED);
});
