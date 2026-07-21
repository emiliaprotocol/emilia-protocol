/**
 * @emilia-protocol/openai-agents — unit suite.
 * @license Apache-2.0
 *
 * Proves the four normative checks WITHOUT calling OpenAI. We construct synthetic
 * interruption objects in the exact shape the OpenAI Agents SDK surfaces
 * (`type: 'tool_approval_item'`, `name`, `arguments` as a JSON string, and a
 * `rawItem` function_call carrying name/arguments/callId), mint real EP-RECEIPT-v1
 * receipts with node:crypto (ed25519 over sorted-key canonical JSON), and drive a
 * fake RunState whose approve()/reject() match the documented signatures.
 *
 *   missing  -> rejected (tool stays blocked)
 *   valid    -> approved
 *   replay   -> rejected
 *   tampered -> rejected
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { requireReceiptForOpenAIAgent, _resetConsumed } from './index.js';

// ── canonical JSON (sorted keys), identical to require-receipt's verifier ──────
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

// One issuer keypair for the whole suite. SPKI-DER, base64url, as the verifier expects.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const TRUSTED_KEY = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function mintReceipt({ action, subject = 'alice@futureenterprises.example', approver = 'alice@futureenterprises.example', createdAt } = {}) {
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomUUID(),
    subject,
    created_at: createdAt || new Date().toISOString(),
    claim: {
      action_type: action,
      outcome: 'allow_with_signoff',
      approver,
    },
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey);
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
    public_key: TRUSTED_KEY,
  };
}

// A synthetic OpenAI Agents RunToolApprovalItem (function_call shape).
function makeInterruption({ name, args, callId }) {
  const argStr = JSON.stringify(args ?? {});
  return {
    type: 'tool_approval_item',
    name,
    arguments: argStr,
    agent: { name: 'TestAgent' },
    rawItem: {
      type: 'function_call',
      name,
      arguments: argStr,
      callId: callId ?? 'call_' + crypto.randomUUID(),
      status: 'in_progress',
    },
  };
}

// A fake RunState that records the SDK's approve()/reject() calls.
function makeFakeState() {
  const approvedCalls = [];
  const rejectedCalls = [];
  return {
    approve(item, options) { approvedCalls.push({ item, options }); },
    reject(item, options) { rejectedCalls.push({ item, options }); },
    approvedCalls,
    rejectedCalls,
  };
}

// Map a tool call to a canonical EP action_type.
const actionFor = (toolName) => `openai.tool.${toolName}`;

function newGate() {
  return requireReceiptForOpenAIAgent({
    trustedKeys: [TRUSTED_KEY],
    maxAgeSec: 900,
    actionFor,
  });
}

test('the four checks: missing -> blocked, valid -> approved, replay -> rejected, tampered -> rejected', async (t) => {
  _resetConsumed();
  const gate = newGate();

  await t.test('1. missing receipt -> REJECT (tool stays blocked)', async () => {
    const interruption = makeInterruption({ name: 'cancelOrder', args: { orderId: 42 } });
    const state = makeFakeState();
    const { approved, rejected, decisions } = await gate.resolve(
      { interruptions: [interruption], state },
      { receipts: {} },
    );
    assert.equal(approved.length, 0);
    assert.equal(rejected.length, 1);
    assert.equal(decisions[0].decision, 'reject');
    assert.equal(decisions[0].reason, 'no_receipt_for_interruption');
    assert.equal(state.rejectedCalls.length, 1, 'SDK state.reject() must be driven');
    assert.equal(state.approvedCalls.length, 0);
  });

  await t.test('2. valid action-bound receipt -> APPROVE', async () => {
    const interruption = makeInterruption({ name: 'cancelOrder', args: { orderId: 42 }, callId: 'call_valid' });
    const receipt = mintReceipt({ action: 'openai.tool.cancelOrder' });
    const state = makeFakeState();
    const { approved, rejected, decisions } = await gate.resolve(
      { interruptions: [interruption], state },
      { receipts: { call_valid: receipt } },
    );
    assert.equal(approved.length, 1);
    assert.equal(rejected.length, 0);
    assert.equal(decisions[0].decision, 'approve');
    assert.equal(decisions[0].reason, 'valid_action_bound_receipt');
    assert.equal(decisions[0].action, 'openai.tool.cancelOrder');
    assert.ok(decisions[0].subject, 'approve decision carries the accountable subject');
    assert.equal(state.approvedCalls.length, 1, 'SDK state.approve() must be driven');
  });

  await t.test('3. replayed receipt (same receipt_id again) -> REJECT', async () => {
    const receipt = mintReceipt({ action: 'openai.tool.wire' });
    const i1 = makeInterruption({ name: 'wire', callId: 'c1' });
    const i2 = makeInterruption({ name: 'wire', callId: 'c2' });
    // First use earns approval.
    const r1 = await gate.resolve({ interruptions: [i1], state: makeFakeState() }, { receipts: { c1: receipt } });
    assert.equal(r1.decisions[0].decision, 'approve');
    // Same receipt presented again -> replay refused.
    const state = makeFakeState();
    const r2 = await gate.resolve({ interruptions: [i2], state }, { receipts: { c2: receipt } });
    assert.equal(r2.decisions[0].decision, 'reject');
    assert.equal(r2.decisions[0].reason, 'receipt_replayed');
    assert.equal(state.rejectedCalls.length, 1);
  });

  await t.test('4. tampered receipt (signed field altered) -> REJECT', async () => {
    const receipt = mintReceipt({ action: 'openai.tool.deploy' });
    // Mutate a signed field after signing -> signature no longer verifies.
    receipt.payload.claim.action_type = 'openai.tool.deploy.tampered';
    const interruption = makeInterruption({ name: 'deploy', callId: 'c_tamper' });
    const state = makeFakeState();
    const { decisions } = await gate.resolve(
      { interruptions: [interruption], state },
      { receipts: { c_tamper: receipt } },
    );
    assert.equal(decisions[0].decision, 'reject');
    // Either the signature fails OR the action no longer matches — both block.
    assert.ok(
      ['untrusted_or_invalid_signature', 'action_mismatch'].includes(decisions[0].reason),
      `expected signature/action failure, got ${decisions[0].reason}`,
    );
    assert.equal(state.approvedCalls.length, 0, 'tampered receipt must never approve');
  });
});

test('decide(): per-interruption API mirrors resolve()', async () => {
  _resetConsumed();
  const gate = newGate();
  const interruption = makeInterruption({ name: 'refund', args: { amount: 10 }, callId: 'd1' });

  // missing
  assert.equal((await gate.decide(interruption, null)).decision, 'reject');
  // valid
  const ok = await gate.decide(interruption, mintReceipt({ action: 'openai.tool.refund' }));
  assert.equal(ok.decision, 'approve');
  assert.equal(ok.toolName, 'refund');
  assert.equal(ok.callId, 'd1');
});

test('action binding: a receipt for the WRONG tool is rejected', async () => {
  _resetConsumed();
  const gate = newGate();
  const interruption = makeInterruption({ name: 'cancelOrder', callId: 'x1' });
  const wrong = mintReceipt({ action: 'openai.tool.somethingElse' });
  const d = await gate.decide(interruption, wrong);
  assert.equal(d.decision, 'reject');
  assert.equal(d.reason, 'action_mismatch');
});

test('untrusted issuer: valid signature but unknown key is rejected', async () => {
  _resetConsumed();
  // Gate trusts only TRUSTED_KEY; mint with a different key.
  const gate = newGate();
  const other = crypto.generateKeyPairSync('ed25519');
  const payload = {
    receipt_id: 'rcpt_other',
    subject: 'mallory@example.com',
    created_at: new Date().toISOString(),
    claim: { action_type: 'openai.tool.cancelOrder', outcome: 'allow_with_signoff', approver: 'mallory@example.com' },
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), other.privateKey);
  const receipt = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sig.toString('base64url') },
    public_key: other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const d = await gate.decide(makeInterruption({ name: 'cancelOrder' }), receipt);
  assert.equal(d.decision, 'reject');
  assert.equal(d.reason, 'untrusted_or_invalid_signature');
});

test('array receipts are matched to interruptions by action_type', async () => {
  _resetConsumed();
  const gate = newGate();
  const i1 = makeInterruption({ name: 'cancelOrder', callId: 'a1' });
  const i2 = makeInterruption({ name: 'sendEmail', callId: 'a2' });
  const receipts = [
    mintReceipt({ action: 'openai.tool.sendEmail' }),
    mintReceipt({ action: 'openai.tool.cancelOrder' }),
  ];
  const { decisions } = await gate.resolve({ interruptions: [i1, i2], state: makeFakeState() }, { receipts });
  assert.equal(decisions[0].decision, 'approve');
  assert.equal(decisions[1].decision, 'approve');
});

test('durable consumption failure never reaches the OpenAI runtime approve boundary', async () => {
  _resetConsumed();
  const store = {
    ownershipFenced: true,
    async reserve() { return true; },
    async commit() { throw new Error('durable store unavailable'); },
    async release() { return true; },
  };
  const gate = requireReceiptForOpenAIAgent({
    trustedKeys: [TRUSTED_KEY],
    maxAgeSec: 900,
    actionFor,
    store,
  });
  const interruption = makeInterruption({ name: 'wire', callId: 'commit_failure' });
  const receipt = mintReceipt({ action: 'openai.tool.wire' });
  const state = makeFakeState();

  const result = await gate.resolve(
    { interruptions: [interruption], state },
    { receipts: { commit_failure: receipt } },
  );

  assert.equal(result.decisions[0].decision, 'reject');
  assert.equal(result.decisions[0].reason, 'approve_or_consumption_failed');
  assert.equal(state.approvedCalls.length, 0, 'runtime approve must happen only after durable commit');
  assert.equal(state.rejectedCalls.length, 1);
});

test('action derivation errors and empty bindings reject without reaching runtime approve', async () => {
  for (const badActionFor of [() => '', () => { throw new Error('bad arguments'); }]) {
    const gate = requireReceiptForOpenAIAgent({
      trustedKeys: [TRUSTED_KEY],
      actionFor: badActionFor,
    });
    const interruption = makeInterruption({ name: 'wire', callId: crypto.randomUUID() });
    const state = makeFakeState();
    const result = await gate.resolve(
      { interruptions: [interruption], state },
      { receipts: { [interruption.rawItem.callId]: mintReceipt({ action: 'openai.tool.wire' }) } },
    );
    assert.equal(result.decisions[0].decision, 'reject');
    assert.equal(result.decisions[0].reason, 'action_binding_invalid');
    assert.equal(state.approvedCalls.length, 0);
  }
});

test('duplicate or non-object tool arguments refuse before action binding', async () => {
  const gate = newGate();
  for (const raw of ['{"amount":1,"amount":999999}', '["not","an","argument object"]', 'not-json']) {
    const interruption = makeInterruption({ name: 'wire', callId: crypto.randomUUID() });
    interruption.arguments = raw;
    interruption.rawItem.arguments = raw;
    const state = makeFakeState();
    const result = await gate.resolve(
      { interruptions: [interruption], state },
      { receipts: { [interruption.rawItem.callId]: mintReceipt({ action: 'openai.tool.wire' }) } },
    );
    assert.equal(result.decisions[0].decision, 'reject');
    assert.equal(result.decisions[0].reason, 'tool_arguments_invalid');
    assert.equal(state.approvedCalls.length, 0);
  }
});

test('plain-object receipt lookup ignores inherited properties', async () => {
  const gate = newGate();
  const interruption = makeInterruption({ name: 'wire', callId: 'inherited_receipt' });
  const receipts = Object.create({
    inherited_receipt: mintReceipt({ action: 'openai.tool.wire' }),
  });
  const state = makeFakeState();
  const result = await gate.resolve({ interruptions: [interruption], state }, { receipts });
  assert.equal(result.decisions[0].reason, 'no_receipt_for_interruption');
  assert.equal(state.approvedCalls.length, 0);
});
