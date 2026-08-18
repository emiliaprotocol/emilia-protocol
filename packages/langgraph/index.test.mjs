// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  _resetLangGraphConsumption,
  bindLangGraphAction,
  createLangGraphApprovalAdapter,
} from './index.js';

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const issuer = crypto.generateKeyPairSync('ed25519');
const otherIssuer = crypto.generateKeyPairSync('ed25519');
const TRUSTED_KEY = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const OTHER_KEY = otherIssuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function mintReceipt(action, { keypair = issuer, publicKey = TRUSTED_KEY } = {}) {
  const payload = {
    receipt_id: `rcpt_${crypto.randomUUID()}`,
    subject: 'approver@example.com',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome: 'allow_with_signoff',
      approver: 'approver@example.com',
    },
  };
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalize(payload), 'utf8'),
    keypair.privateKey,
  );
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: signature.toString('base64url') },
    public_key: publicKey,
  };
}

function makeInterrupt(overrides = {}) {
  return {
    action_request: {
      action: 'wire_transfer',
      args: { payee: 'acct_alice', amount: 100 },
    },
    config: {
      allow_ignore: true,
      allow_respond: true,
      allow_edit: true,
      allow_accept: true,
    },
    description: 'Review this transfer',
    ...overrides,
  };
}

function occurrence(suffix = '1') {
  return { threadId: 'thread_finance', interruptId: `interrupt_${suffix}` };
}

function adapter(options = {}) {
  return createLangGraphApprovalAdapter({
    trustedKeys: [TRUSTED_KEY],
    maxAgeSec: 900,
    ...options,
  });
}

test('accept consumes exact authority and resumes only the frozen interrupt action', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence();
  const action = bindLangGraphAction(interrupt.action_request, where);
  const receipt = mintReceipt(action);
  const response = {
    type: 'accept',
    // Agent Inbox serializes values to strings. This field is intentionally not
    // trusted as the execution payload on accept.
    args: { action: 'wire_transfer', args: { payee: 'acct_mallory', amount: '100' } },
  };

  const decision = await adapter().resolve(interrupt, [response], receipt, where);
  assert.equal(decision.decision, 'resume');
  assert.equal(decision.action, action);
  assert.equal(decision.reason, 'valid_action_bound_receipt');
  assert.deepEqual(decision.response, {
    type: 'accept',
    args: interrupt.action_request,
  });
});

test('missing, forged, tampered, and replayed receipts never resume', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence('checks');
  const action = bindLangGraphAction(interrupt.action_request, where);
  const response = { type: 'accept', args: interrupt.action_request };
  const gate = adapter();

  const missing = await gate.resolve(interrupt, response, null, where);
  assert.deepEqual(
    { decision: missing.decision, reason: missing.reason },
    { decision: 'reject', reason: 'no_receipt_for_interrupt' },
  );

  const forged = await gate.resolve(
    interrupt,
    response,
    mintReceipt(action, { keypair: otherIssuer, publicKey: OTHER_KEY }),
    where,
  );
  assert.equal(forged.decision, 'reject');
  assert.equal(forged.reason, 'untrusted_or_invalid_signature');

  const tamperedReceipt = mintReceipt(action);
  tamperedReceipt.payload.claim.approver = 'mallory@example.com';
  const tampered = await gate.resolve(interrupt, response, tamperedReceipt, where);
  assert.equal(tampered.decision, 'reject');

  const receipt = mintReceipt(action);
  assert.equal((await gate.resolve(interrupt, response, receipt, where)).decision, 'resume');
  const replay = await gate.resolve(interrupt, response, receipt, where);
  assert.equal(replay.decision, 'reject');
  assert.equal(replay.reason, 'replay_refused');
});

test('trusted occurrence identity prevents authority transfer between sibling interrupts', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const first = occurrence('a');
  const second = occurrence('b');
  const receipt = mintReceipt(bindLangGraphAction(interrupt.action_request, first));
  const decision = await adapter().resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    receipt,
    second,
  );
  assert.equal(decision.decision, 'reject');
  assert.equal(decision.reason, 'action_mismatch');
});

test('occurrence tuple encoding has no delimiter collision', () => {
  const request = makeInterrupt().action_request;
  const first = bindLangGraphAction(request, { threadId: 'a:b', interruptId: 'c' });
  const second = bindLangGraphAction(request, { threadId: 'a', interruptId: 'b:c' });
  assert.notEqual(first, second);
});

test('edit creates a new exact action and requires fresh authority for it', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence('edit');
  const edited = {
    action: 'wire_transfer',
    args: { payee: 'acct_bob', amount: 25 },
  };
  const response = { type: 'edit', args: edited };
  const oldReceipt = mintReceipt(bindLangGraphAction(interrupt.action_request, where));
  const editedAction = bindLangGraphAction(edited, where);
  const gate = adapter();

  const absent = await gate.resolve(interrupt, response, null, where);
  assert.equal(absent.decision, 'reauthorize');
  assert.equal(absent.reason, 'fresh_receipt_required_for_edit');
  assert.equal(absent.action, editedAction);

  const old = await gate.resolve(interrupt, response, oldReceipt, where);
  assert.equal(old.decision, 'reauthorize');
  assert.equal(old.reason, 'fresh_receipt_required_for_edit');
  assert.equal(old.action, editedAction);

  const fresh = await gate.resolve(interrupt, response, mintReceipt(editedAction), where);
  assert.equal(fresh.decision, 'resume');
  assert.equal(fresh.reason, 'fresh_authority_for_edited_action');
  assert.deepEqual(fresh.response, response);
});

test('response and ignore are non-authorizing and do not consume a receipt', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence('pass');
  const receipt = mintReceipt(bindLangGraphAction(interrupt.action_request, where));
  const gate = adapter();

  const response = await gate.resolve(interrupt, { type: 'response', args: 'Not until tomorrow' }, receipt, where);
  assert.equal(response.decision, 'pass');
  assert.equal(response.action, null);
  const ignored = await gate.resolve(interrupt, { type: 'ignore', args: null }, receipt, where);
  assert.equal(ignored.decision, 'pass');

  const accepted = await gate.resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    receipt,
    where,
  );
  assert.equal(accepted.decision, 'resume', 'non-authorizing responses must not spend authority');
});

test('disabled response types and malformed structures fail closed', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt({
    config: {
      allow_ignore: false,
      allow_respond: false,
      allow_edit: false,
      allow_accept: true,
    },
  });
  const where = occurrence('invalid');
  assert.equal(
    (await adapter().resolve(interrupt, { type: 'edit', args: interrupt.action_request }, null, where)).reason,
    'response_type_not_allowed',
  );
  assert.equal(
    (await adapter().resolve(interrupt, [], null, where)).reason,
    'response_invalid',
  );
  assert.equal(
    (await adapter().resolve(interrupt, { type: 'ignore', args: 'smuggled' }, null, where)).reason,
    'response_type_not_allowed',
    'config denial wins before response-shape handling',
  );
  assert.equal(
    (await adapter().resolve({ ...interrupt, action_request: { action: '', args: {} } }, { type: 'accept' }, null, where)).reason,
    'interrupt_invalid',
  );
  assert.throws(
    () => bindLangGraphAction(interrupt.action_request, { threadId: '', interruptId: 'x' }),
    /runtime_occurrence_invalid/,
  );
});

test('non-authorizing response shapes are still strict', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence('strict-pass');
  const gate = adapter();
  assert.equal(
    (await gate.resolve(interrupt, { type: 'ignore', args: 'smuggled' }, null, where)).reason,
    'response_invalid',
  );
  assert.equal(
    (await gate.resolve(interrupt, { type: 'response', args: { command: 'execute' } }, null, where)).reason,
    'response_invalid',
  );
});

test('caller cannot override the derived exact action with a static gate option', async () => {
  _resetLangGraphConsumption();
  const interrupt = makeInterrupt();
  const where = occurrence('override');
  const exact = bindLangGraphAction(interrupt.action_request, where);
  const decision = await adapter({ action: 'unsafe.static.action' }).resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    mintReceipt(exact),
    where,
  );
  assert.equal(decision.decision, 'resume');
  assert.equal(decision.action, exact);
});

test('mutation while reserving releases authority and never resumes', async () => {
  const states = new Map();
  const interrupt = makeInterrupt();
  const where = occurrence('reserve-drift');
  const receipt = mintReceipt(bindLangGraphAction(interrupt.action_request, where));
  const store = {
    ownershipFenced: true,
    async reserve(id) {
      states.set(id, 'reserved');
      interrupt.action_request.args.payee = 'acct_mallory';
      return true;
    },
    async commit(id) { states.set(id, 'committed'); return true; },
    async release(id) { states.delete(id); return true; },
  };
  const decision = await adapter({ store }).resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    receipt,
    where,
  );
  assert.equal(decision.decision, 'reject');
  assert.equal(decision.reason, 'request_drifted_before_consumption');
  assert.equal(states.size, 0);
});

test('mutation during commit burns authority and never resumes', async () => {
  const states = new Map();
  const interrupt = makeInterrupt();
  const where = occurrence('commit-drift');
  const receipt = mintReceipt(bindLangGraphAction(interrupt.action_request, where));
  const store = {
    ownershipFenced: true,
    async reserve(id) { states.set(id, 'reserved'); return true; },
    async commit(id) {
      states.set(id, 'committed');
      interrupt.action_request.args.amount = 999;
      return true;
    },
    async release(id) { states.delete(id); return true; },
  };
  const gate = adapter({ store });
  const decision = await gate.resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    receipt,
    where,
  );
  assert.equal(decision.decision, 'reject');
  assert.equal(decision.reason, 'request_drifted_after_consumption');
  assert.equal(states.get(receipt.payload.receipt_id), 'committed');
});

test('durable consumption failure never resumes the graph', async () => {
  const states = new Map();
  const interrupt = makeInterrupt();
  const where = occurrence('commit-fail');
  const receipt = mintReceipt(bindLangGraphAction(interrupt.action_request, where));
  const store = {
    ownershipFenced: true,
    async reserve(id) { states.set(id, 'reserved'); return true; },
    async commit() { throw new Error('database unavailable'); },
    async release(id) { states.delete(id); return true; },
  };
  const decision = await adapter({ store }).resolve(
    interrupt,
    { type: 'accept', args: interrupt.action_request },
    receipt,
    where,
  );
  assert.equal(decision.decision, 'reject');
  assert.equal(decision.reason, 'consumption_commit_failed');
});
