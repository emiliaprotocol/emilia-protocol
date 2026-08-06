// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { bindExecutorAction, bindToolAction, snapshotToolArguments } from './index.js';

test('executor binding covers every material argument deterministically', () => {
  const first = bindToolAction('wire.transfer', {
    amount: 1250.5,
    destination: 'acct_A',
  }, 'payment.release');
  const reordered = bindToolAction('wire.transfer', {
    destination: 'acct_A',
    amount: 1250.5,
  }, 'payment.release');
  const substituted = bindToolAction('wire.transfer', {
    amount: 1250.5,
    destination: 'acct_B',
  }, 'payment.release');

  assert.equal(first, reordered);
  assert.match(first, /^payment\.release:sha256:[0-9a-f]{64}$/u);
  assert.notEqual(first, substituted);
});

test('receipt carriers cannot alter the action they authorize', () => {
  const material = bindToolAction('wire.transfer', { amount: 10 }, 'payment.release');
  const carried = bindToolAction('wire.transfer', {
    amount: 10,
    __ep: { receipt: 'attacker-controlled' },
    emilia_receipt: { payload: 'different' },
    emiliaReceipt: { payload: 'different-again' },
  }, 'payment.release');
  assert.equal(carried, material);
});

test('occurrence identity prevents sibling calls from sharing one approval', () => {
  const first = bindToolAction('order.cancel', { order_id: 42 }, 'openai.tool.order.cancel', 'call_A');
  const second = bindToolAction('order.cancel', { order_id: 42 }, 'openai.tool.order.cancel', 'call_B');
  assert.notEqual(first, second);
});

test('executor snapshots are detached from later caller mutation', () => {
  const input = { destination: 'acct_A', nested: { amount: 10.5 } };
  const snapshot = snapshotToolArguments(input);
  input.destination = 'acct_B';
  input.nested.amount = 999;
  assert.deepEqual(snapshot, { destination: 'acct_A', nested: { amount: 10.5 } });
});

test('ambiguous or executable payloads fail closed', () => {
  const accessor = {};
  Object.defineProperty(accessor, 'amount', { enumerable: true, get: () => 10 });
  assert.throws(() => bindExecutorAction('payment.release', accessor), /strict canonical JSON domain/u);
  let invoked = false;
  const carrierAccessor = { amount: 10 };
  Object.defineProperty(carrierAccessor, 'emiliaReceipt', {
    enumerable: true,
    get: () => { invoked = true; return {}; },
  });
  assert.throws(() => bindToolAction('wire.transfer', carrierAccessor, 'payment.release'), /action_binding_invalid/u);
  assert.equal(invoked, false, 'receipt carrier accessors must never execute');
  assert.throws(
    () => bindToolAction('wire.transfer', { amount: Number.MAX_SAFE_INTEGER + 1 }, 'payment.release'),
    /integer values must be safe/u,
  );
  assert.throws(() => bindExecutorAction('', {}), /action_binding_invalid/u);
});
