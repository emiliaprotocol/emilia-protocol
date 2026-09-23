// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import {
  canonicalizePaymentRelease,
  createDemoPaymentReleaseFixture,
  verifyOutcomeReceipt,
} from '../adapter.mjs';
import { processMuseHookEvent } from '../hook.mjs';
import { TOOLS, handleToolRequest } from '../server.mjs';
import { generateDemoConfig } from '../demo-config.mjs';

const HOOK_PATH = fileURLToPath(new URL('../hook.mjs', import.meta.url));
const SERVER_PATH = fileURLToPath(new URL('../server.mjs', import.meta.url));

const INPUT = Object.freeze({
  payee: 'vendor:acme',
  account: 'acct:us:0001842',
  amount: '1250.00',
  currency: 'USD',
  operation: 'invoice-1842',
});

test('canonicalizes all five material payment fields into registered payment.release.1 CAID content', () => {
  const first = canonicalizePaymentRelease(INPUT);
  const second = canonicalizePaymentRelease({ ...INPUT, account: 'acct:us:ATTACKER' });
  assert.equal(first.action.action_type, 'payment.release.1');
  assert.equal(first.action.payee_ref, INPUT.payee);
  assert.match(first.action.beneficiary_account, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.action.amount, INPUT.amount);
  assert.equal(first.action.currency, INPUT.currency);
  assert.equal(first.action.payment_instruction_id, INPUT.operation);
  assert.match(first.caid, /^caid:1:payment\.release\.1:jcs-sha256:/);
  assert.notEqual(first.caid, second.caid);
});

test('the Gate-wrapped provider emits an offline-verifiable EXECUTED receipt', async () => {
  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  assert.equal(fixture.providerCalls.length, 1);
  assert.equal(result._emilia.gate, 'allowed');
  assert.equal(result._emilia.outcome, 'EXECUTED');
  assert.equal(result._emilia.provider_entry, 'ENTERED');
  const verified = verifyOutcomeReceipt(result._emilia.outcome_receipt, fixture.outcomePublicKey);
  assert.equal(verified.valid, true, JSON.stringify(verified));
  assert.equal(result._emilia.outcome_receipt.payload.claim.caid, canonicalizePaymentRelease(INPUT).caid);
});

test('payee, account, amount, currency, and operation mutations all refuse before provider entry', async () => {
  const mutations = [
    { payee: 'vendor:attacker' },
    { account: 'acct:us:ATTACKER' },
    { amount: '1250.01' },
    { currency: 'EUR' },
    { operation: 'invoice-1842-copy' },
  ];
  for (const mutation of mutations) {
    const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
    const result = await fixture.tool({ ...INPUT, ...mutation, _emilia_receipt: fixture.mintReceipt() });
    assert.equal(result.isError, true, JSON.stringify({ mutation, result }));
    assert.equal(fixture.providerCalls.length, 0, JSON.stringify(mutation));
  }
});

test('replay is refused and never calls the provider twice', async () => {
  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const receipt = fixture.mintReceipt();
  const first = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(first._emilia.outcome, 'EXECUTED');
  assert.equal(replay.isError, true);
  assert.match(replay._emilia.reason, /replay/);
  assert.equal(fixture.providerCalls.length, 1);
});

test('a provider exception after entry burns authority and emits INDETERMINATE, never FAILED', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('response lost after provider accepted request'); },
  });
  const receipt = fixture.mintReceipt();
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(result.isError, true);
  assert.equal(result._emilia.provider_entry, 'ENTERED');
  assert.equal(result._emilia.outcome, 'INDETERMINATE');
  assert.equal(verifyOutcomeReceipt(result._emilia.outcome_receipt, fixture.outcomePublicKey).valid, true);
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(replay.isError, true);
  assert.match(replay._emilia.reason, /replay/);
});

test('hostile shapes, numeric money, and extra provider-affecting fields fail closed', async () => {
  const cases = [
    { ...INPUT, amount: 1250 },
    { ...INPUT, currency: 'usd' },
    { ...INPUT, account: ' acct:us:0001842' },
    { ...INPUT, destination_override: 'acct:attacker' },
  ];
  for (const input of cases) {
    const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
    const result = await fixture.tool({ ...input, _emilia_receipt: fixture.mintReceipt() });
    assert.equal(result.isError, true, JSON.stringify(input));
    assert.equal(fixture.providerCalls.length, 0);
  }
});

test('Muse PreToolUse hook is only an early refusal: deny JSON on invalid, silence on valid', async () => {
  const missing = await processMuseHookEvent({
    hook_event_name: 'PreToolUse', tool_name: 'mcp__emilia_payment_gate__release_payment',
    tool_input: INPUT,
  });
  assert.equal(missing.exitCode, 2);
  assert.equal(missing.output.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(missing.output.hookSpecificOutput.permissionDecision, 'deny');

  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const present = await processMuseHookEvent({
    hook_event_name: 'PreToolUse', tool_name: 'mcp__emilia_payment_gate__release_payment',
    tool_input: { ...INPUT, _emilia_receipt: fixture.mintReceipt() },
  });
  assert.deepEqual(present, { exitCode: 0, output: null });
});

test('stdio MCP surface inventories and dispatches only release_payment', async () => {
  assert.deepEqual(TOOLS.map((tool) => tool.name), ['release_payment']);
  const unknown = await handleToolRequest({ params: { name: 'not_a_tool', arguments: {} } }, { invoke: null });
  assert.equal(unknown.isError, true);
  const listedSchema = TOOLS[0].inputSchema;
  assert.equal(listedSchema.additionalProperties, false);
  assert.deepEqual(listedSchema.required, ['payee', 'account', 'amount', 'currency', 'operation', '_emilia_receipt']);
});

test('hook CLI uses Muse 1.3 denial JSON + exit 2 and emits nothing on allow', () => {
  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const base = {
    hook_event_name: 'PreToolUse',
    tool_name: 'mcp__emilia_payment_gate__release_payment',
  };
  const denied = spawnSync(process.execPath, [HOOK_PATH], {
    input: JSON.stringify({ ...base, tool_input: INPUT }), encoding: 'utf8',
  });
  assert.equal(denied.status, 2);
  const output = JSON.parse(denied.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');

  const allowed = spawnSync(process.execPath, [HOOK_PATH], {
    input: JSON.stringify({
      ...base,
      tool_input: { ...INPUT, _emilia_receipt: fixture.mintReceipt() },
    }),
    encoding: 'utf8',
  });
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.stdout, '');
});

test('real stdio MCP tools/list + tools/call execute once and refuse replay', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'emilia-muse-gate-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const generated = await generateDemoConfig(directory, { input: INPUT });
  const call = JSON.parse(await readFile(generated.callPath, 'utf8'));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_PATH],
    env: { EMILIA_MUSE_GATE_CONFIG: generated.configPath },
    stderr: 'pipe',
  });
  const client = new Client(
    { name: 'emilia-muse-gate-test', version: '1.0.0' },
    { capabilities: {} },
  );
  t.after(() => client.close());
  await client.connect(transport);
  const inventory = await client.listTools();
  assert.deepEqual(inventory.tools.map((tool) => tool.name), ['release_payment']);
  const first = await client.callTool({ name: call.tool, arguments: call.arguments });
  assert.equal(first.isError ?? false, false);
  assert.equal(first._emilia.outcome, 'EXECUTED');
  assert.equal(first._emilia.provider_entry, 'ENTERED');
  assert.equal(verifyOutcomeReceipt(first._emilia.outcome_receipt, call.outcome_verification_key).valid, true);
  const replay = await client.callTool({ name: call.tool, arguments: call.arguments });
  assert.equal(replay.isError, true);
  assert.equal(replay._emilia.reason, 'replay_refused');
  assert.equal(replay._emilia.provider_entry, 'NOT_ENTERED');
});
