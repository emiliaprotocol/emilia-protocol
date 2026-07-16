// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedActionFirewall, createEg1Harness } from './index.js';
import { gateMcpTool, gateMcpTools } from './mcp.js';

function setup() {
  const harness = createEg1Harness();
  const gate = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
  });
  return { harness, gate, action: harness.action };
}

test('gateMcpTool refuses a guarded tool with no receipt (structured MCP error)', async () => {
  const { gate, action } = setup();
  let ran = false;
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => { ran = true; return { ok: true }; });
  const res = await tool({ amount_usd: 40000 });
  assert.equal(ran, false);
  assert.equal(res.isError, true);
  assert.equal(res._emilia.gate, 'refused');
  assert.equal(res._emilia.status, 428);
  assert.match(res._emilia.reason, /receipt_required/);
});

test('gateMcpTool refuses a software receipt on a Class-A tool', async () => {
  const { gate, harness, action } = setup();
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => ({ ok: true }));
  const res = await tool({ _emilia_receipt: harness.mint({ outcome: 'allow' }) });
  assert.equal(res.isError, true);
  assert.match(res._emilia.reason, /assurance/);
});

test('gateMcpTool runs the tool with a valid Class-A receipt and attaches proof', async () => {
  const { gate, harness, action } = setup();
  let ran = false;
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action },
    async () => { ran = true; return { wire_id: 'w_1' }; });
  const res = await tool({ _emilia_receipt: harness.mint({ outcome: 'allow_with_signoff' }) });
  assert.equal(ran, true);
  assert.equal(res.wire_id, 'w_1');
  assert.equal(res._emilia.gate, 'allowed');
  assert.ok(res._emilia.execution?.authorizes_decision);
  assert.equal(String(res._emilia.reliance.verdict).toLowerCase(), 'rely');
});

test('gateMcpTool refuses a replayed receipt', async () => {
  const { gate, harness, action } = setup();
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => ({ ok: true }));
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  const first = await tool({ _emilia_receipt: receipt });
  assert.equal(first._emilia.gate, 'allowed');
  const second = await tool({ _emilia_receipt: receipt });
  assert.equal(second.isError, true);
  assert.match(second._emilia.reason, /replay/);
});

test('gateMcpTool refuses on observed execution drift (args differ from authorized)', async () => {
  const { gate, harness } = setup();
  // observedAction defaults to the tool args; mint authorizes amount 40000, call with 999999.
  const tool = gateMcpTool(gate, { tool: 'release_payment' }, async () => ({ ok: true }));
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  const res = await tool({ ...harness.action, amount_usd: 999999, _emilia_receipt: receipt });
  assert.equal(res.isError, true);
  assert.match(res._emilia.reason, /binding/);
});

test('gateMcpTools wraps a map of handlers', async () => {
  const { gate, harness, action } = setup();
  const tools = gateMcpTools(gate, {
    release_payment: async () => ({ paid: true }),
  }, { observedAction: () => action });
  const refused = await tools.release_payment({});
  assert.equal(refused.isError, true);
  const allowed = await tools.release_payment({ _emilia_receipt: harness.mint({ outcome: 'allow_with_signoff' }) });
  assert.equal(allowed.paid, true);
});

test('gateMcpTool accepts the base64 receipt carrier', async () => {
  const { gate, harness, action } = setup();
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => ({ paid: true }));
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  const res = await tool({ _emilia_receipt_b64: Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64') });
  assert.equal(res.paid, true);
  assert.equal(res._emilia.gate, 'allowed');
});

test('gateMcpTool refuses a duplicate-member base64 receipt carrier', async () => {
  const { gate, action } = setup();
  let ran = false;
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => { ran = true; return { paid: true }; });
  const duplicate = Buffer.from('{"payload":{},"payload":{"forged":true}}', 'utf8').toString('base64');
  const res = await tool({ _emilia_receipt_b64: duplicate });
  assert.equal(res.isError, true);
  assert.equal(ran, false);
});

test('gateMcpTool does not let a lower-priority valid carrier override an invalid primary carrier', async () => {
  const { gate, harness, action } = setup();
  const tool = gateMcpTool(gate, { tool: 'release_payment', observedAction: () => action }, async () => ({ paid: true }));
  const invalidPrimary = harness.mint({ outcome: 'allow_with_signoff', tamper: { amount_usd: 999999 } });
  const validSecondary = harness.mint({ outcome: 'allow_with_signoff' });
  const res = await tool({
    _emilia_receipt: invalidPrimary,
    emilia_receipt: validSecondary,
  });
  assert.equal(res.isError, true);
  assert.match(res._emilia.reason, /receipt_rejected|binding|signature/);
});

test('gateMcpTool fail-closes when receipt resolution or observed-action mapping throws', async () => {
  const { gate, action } = setup();
  let ran = false;
  const receiptThrows = gateMcpTool(gate, {
    tool: 'release_payment',
    observedAction: () => action,
    receipt: () => { throw new Error('resolver down'); },
  }, async () => { ran = true; return { paid: true }; });
  const r1 = await receiptThrows({});
  assert.equal(r1.isError, true);
  assert.equal(r1._emilia.reason, 'receipt_boundary_failed');
  assert.equal(ran, false);

  const observedThrows = gateMcpTool(gate, {
    tool: 'release_payment',
    observedAction: () => { throw new Error('mapper down'); },
  }, async () => { ran = true; return { paid: true }; });
  const r2 = await observedThrows({});
  assert.equal(r2.isError, true);
  assert.equal(r2._emilia.reason, 'receipt_boundary_failed');
  assert.equal(ran, false);
});
