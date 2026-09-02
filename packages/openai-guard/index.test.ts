// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  _resetConsumed,
  guardAction,
  requireReceiptForOpenAITool,
  runToolCalls,
  withGuard,
} from './index.js';
import { mintReceipt as hostedMintReceipt } from './receipt.js';
import { bindToolAction } from '../require-receipt/index.js';

test('package metadata pins the current optional verifier release line', () => {
  const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
  assert.equal(packageJson.version, '0.5.0');
  assert.equal(packageJson.peerDependencies['@emilia-protocol/verify'], '^3.21.0');
});

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const keyPair = crypto.generateKeyPairSync('ed25519');
const trustedKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function receipt(action) {
  const payload = {
    receipt_id: `rcpt_${crypto.randomUUID()}`,
    subject: 'ep:approver:alice',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:alice' },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: crypto.sign(null, Buffer.from(canonicalize(payload)), keyPair.privateKey).toString('base64url'),
    },
  };
}

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, async json() { return body; } };
}

test('hosted gate allows only an explicit allow backed by a durable commit', async () => {
  const base = { actor: 'ep:entity:agent', action: 'payment.release', apiKey: 'secret' };
  const accepted = await guardAction({
    ...base,
    fetchImpl: async () => response({ decision: 'allow', commit_ref: 'commit_123' }),
  });
  assert.equal(accepted.allow, true);

  for (const fetchImpl of [
    async () => response({ decision: 'allow' }),
    async () => response({}),
    async () => response({ decision: 'unknown' }),
    async () => response({ decision: 'allow', commit_ref: 'commit_123' }, 500),
    async () => { throw new Error('network down'); },
  ]) {
    const result = await guardAction({ ...base, fetchImpl });
    assert.equal(result.allow, false);
    assert.equal(result.deny, true);
  }
});

test('hosted gate never sends a credential without an authenticated endpoint boundary', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return response({ decision: 'allow', commit_ref: 'c' }); };
  assert.equal((await guardAction({ actor: 'agent', action: 'x', fetchImpl })).reason, 'api_key_required');
  assert.equal((await guardAction({ actor: 'agent', action: 'x', apiKey: 'k', gateUrl: 'http://remote.example/gate', fetchImpl })).reason, 'insecure_gate_url');
  assert.equal(calls, 0);
});

test('legacy signoff callback requires an explicit approved result', async () => {
  let runs = 0;
  const fn = async () => { runs += 1; return 'ran'; };
  const fetchImpl = async () => response({ decision: 'review' });
  const common = { action: 'payment.release', actor: 'agent', apiKey: 'k', fetchImpl };
  await assert.rejects(withGuard(fn, { ...common, onSignoff: async () => undefined })({}), /explicit signoff/);
  assert.equal(runs, 0);
  assert.equal(await withGuard(fn, { ...common, onSignoff: async () => ({ approved: true }) })({}), 'ran');
  assert.equal(runs, 1);
});

// The action the guard derives: the base action string PLUS a digest of the
// tool name and the exact executor arguments (the __ep receipt envelope is
// stripped before hashing, because it is not part of the effect).
function boundAction(toolName, args, base) {
  return bindToolAction(toolName, args, base);
}

test('offline tool gate binds material arguments and consumes a receipt once', async () => {
  _resetConsumed();
  let runs = 0;
  const guarded = requireReceiptForOpenAITool(async (args) => {
    runs += 1;
    assert.equal(args.__ep, undefined);
    return args.amount;
  }, {
    toolName: 'pay',
    actionFor: (args) => `payment.release:${args.destination}:${args.amount}`,
    trustedKeys: [trustedKey],
  });
  const args = { destination: 'acct_vendor', amount: 25 };
  const authorization = receipt(boundAction('pay', args, 'payment.release:acct_vendor:25'));
  assert.equal(await guarded({ ...args, __ep: { receipt: authorization } }), 25);
  await assert.rejects(
    guarded({ ...args, __ep: { receipt: authorization } }),
    /replay_refused/,
  );
  const wrongAmount = receipt(boundAction('pay', args, 'payment.release:acct_vendor:25'));
  await assert.rejects(
    guarded({ destination: 'acct_vendor', amount: 250000, __ep: { receipt: wrongAmount } }),
    /action_mismatch/,
  );
  assert.equal(runs, 1);
});

// Red-team E-2: the documented simple `action: 'payment.release'` form was NOT
// argument-bound, so one receipt for payment.release authorized ANY arguments.
// A PoC executed a $9,999,999 transfer to an attacker account on a receipt
// minted for $100 to an approved account.
test('E-2: the simple action form is argument-bound; one receipt cannot move the arguments', async () => {
  _resetConsumed();
  const payouts = [];
  const guarded = requireReceiptForOpenAITool(async (args) => {
    payouts.push(args);
    return { ok: true, ...args };
  }, {
    toolName: 'pay',
    action: 'payment.release',
    trustedKeys: [trustedKey],
  });

  const approved = { amount: 100, to: 'acct_OK' };
  const bound = boundAction('pay', approved, 'payment.release');
  assert.deepEqual(
    await guarded(approved, { receipt: receipt(bound) }),
    { ok: true, amount: 100, to: 'acct_OK' },
  );

  // A freshly minted receipt for the same bound action, spent on other arguments.
  await assert.rejects(
    guarded({ amount: 9999999, to: 'acct_ATTACKER' }, { receipt: receipt(bound) }),
    /action_mismatch/,
  );
  // The bare base action alone is no longer sufficient for anything.
  await assert.rejects(
    guarded(approved, { receipt: receipt('payment.release') }),
    /action_mismatch/,
  );
  // Replay of a correctly bound receipt is still refused.
  const once = receipt(boundAction('pay', approved, 'payment.release'));
  await guarded(approved, { receipt: once });
  await assert.rejects(guarded(approved, { receipt: once }), /replay_refused/);

  assert.equal(payouts.length, 2);
  assert.deepEqual(payouts, [approved, approved]);
});

// Red-team E-2 (second half): the guard hashed `snapshot` (which still carried
// the __ep receipt envelope) but executed `executionArgs` (with __ep stripped).
// The digest must cover exactly what runs.
test('E-2: the digest covers the arguments that execute, not the receipt envelope', async () => {
  _resetConsumed();
  let seen = null;
  const guarded = requireReceiptForOpenAITool(async (args) => { seen = args; return 'ran'; }, {
    toolName: 'pay',
    action: 'payment.release',
    trustedKeys: [trustedKey],
  });
  const args = { amount: 100, to: 'acct_OK' };
  // Minted against the digest of the EXECUTED arguments only.
  const authorization = receipt(boundAction('pay', args, 'payment.release'));
  assert.equal(await guarded({ ...args, __ep: { receipt: authorization } }), 'ran');
  assert.deepEqual(seen, args);
});

// runToolCalls binds to the tool name the model actually called, so the digest
// does not move with a local function identifier (or a minified one).
test('E-2: the tool-call loop binds the model-supplied tool name and exact arguments', async () => {
  _resetConsumed();
  const executed = [];
  const tools = {
    pay: { action: 'payment.release', fn: async (args) => { executed.push(args); return 'sent'; } },
  };
  const approvedArgs = { amount: 100, to: 'acct_OK' };
  const bound = boundAction('pay', approvedArgs, 'payment.release');

  const allowed = await runToolCalls(
    [{ id: 'call_1', function: { name: 'pay', arguments: JSON.stringify(approvedArgs) } }],
    tools,
    { trustedKeys: [trustedKey], receipts: { call_1: receipt(bound) } },
  );
  assert.equal(allowed[0].content, 'sent');

  // Same action string, different arguments, fresh receipt -> refused.
  const substituted = await runToolCalls(
    [{ id: 'call_2', function: { name: 'pay', arguments: JSON.stringify({ amount: 9999999, to: 'acct_ATTACKER' }) } }],
    tools,
    { trustedKeys: [trustedKey], receipts: { call_2: receipt(bound) } },
  );
  assert.match(substituted[0].content, /action_mismatch/);

  assert.deepEqual(executed, [approvedArgs]);
});

test('tool-loop defaults to gated, requires explicit read-only, and refuses duplicate JSON', async () => {
  let mutatingRuns = 0;
  let readRuns = 0;
  const tools = {
    mutate: { fn: async () => { mutatingRuns += 1; } },
    read: { readOnly: true, fn: async () => { readRuns += 1; return 'ok'; } },
  };
  const calls = [
    { id: 'a', function: { name: 'mutate', arguments: '{}' } },
    { id: 'b', function: { name: 'read', arguments: '{"q":1}' } },
    { id: 'c', function: { name: 'read', arguments: '{"q":1,"q":2}' } },
  ];
  const result = await runToolCalls(calls, tools);
  assert.match(result[0].content, /not explicitly read-only/);
  assert.equal(result[1].content, 'ok');
  assert.match(result[2].content, /duplicate-member/);
  assert.equal(mutatingRuns, 0);
  assert.equal(readRuns, 1);
});

test('hosted receipt client validates the origin before sending an API key', async () => {
  let called = false;
  await assert.rejects(
    hostedMintReceipt({
      apiKey: 'secret',
      base: 'https://user:password@example.com',
      organization_id: 'org',
      action_type: 'large_payment_release',
      target_resource_id: 'invoice',
      fetchImpl: async () => { called = true; },
    }),
    /absolute origin/,
  );
  assert.equal(called, false);
});
