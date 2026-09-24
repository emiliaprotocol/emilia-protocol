// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import {
  canonicalizePaymentRelease,
  createDemoPaymentReleaseFixture,
  createOutcomeSigner,
  createPaymentReconciliationTool,
  verifyReconciliationReceipt,
  verifyOutcomeReceipt,
} from '../adapter.mjs';
import { processMuseHookEvent } from '../hook.mjs';
import { TOOLS, createServerRuntime, handleToolRequest } from '../server.mjs';
import { generateDemoConfig } from '../demo-config.mjs';

const HOOK_PATH = fileURLToPath(new URL('../hook.mjs', import.meta.url));
const SERVER_PATH = fileURLToPath(new URL('../server.mjs', import.meta.url));
const SETTINGS_PATH = fileURLToPath(new URL('../examples/settings.json', import.meta.url));
const HOOKS_PATH = fileURLToPath(new URL('../examples/hooks.json', import.meta.url));
const PRIVACY_SCAN_PATH = fileURLToPath(new URL('../privacy-scan.mjs', import.meta.url));

const INPUT = Object.freeze({
  payee: 'vendor:acme',
  account: 'acct:us:0001842',
  amount: '1250.00',
  currency: 'USD',
  operation: 'invoice-1842',
});

test('outcome signer refuses a mismatched public key before provider entry', () => {
  const first = createOutcomeSigner();
  const second = createOutcomeSigner();
  assert.throws(
    () => createOutcomeSigner({ privateKey: first.privateKey, publicKey: second.publicKey }),
    /outcome_key_pair_mismatch/,
  );
});

test('outcome signer refuses a noncanonical or empty issuer before provider entry', () => {
  assert.throws(() => createOutcomeSigner({ keyId: '' }), /outcome_key_id_required/);
  assert.throws(() => createOutcomeSigner({ keyId: ' padded ' }), /outcome_key_id_not_canonical/);
});

test('reconciliation refuses a store without durable fenced permanent-consumption capabilities', () => {
  const methodsOnly = {
    get: async () => null,
    addIfAbsent: async () => true,
    compareAndSet: async () => true,
    deleteIfValue: async () => true,
  };
  assert.throws(
    () => createPaymentReconciliationTool({ reconcile: async () => ({}), reconciliationStore: methodsOnly }),
    /durable_reconciliation_store_required/,
  );
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
  assert.equal(Object.hasOwn(result._emilia, 'outcome_verification_key'), false);
  const verified = verifyOutcomeReceipt(result._emilia.outcome_receipt, fixture.outcomePublicKey);
  assert.equal(verified.valid, true, JSON.stringify(verified));
  const claim = result._emilia.outcome_receipt.payload.claim;
  assert.equal(claim.caid, canonicalizePaymentRelease(INPUT).caid);
  assert.equal(claim.gate_authorization_evidence_hash, result._emilia.execution.authorizes_decision);
  assert.equal(claim.gate_execution_evidence_hash, result._emilia.execution.hash);
});

test('missing authorization receipt refuses before provider entry', async () => {
  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const result = await fixture.tool(INPUT);
  assert.equal(result.isError, true);
  assert.match(result._emilia.reason, /receipt_required/);
  assert.equal(result._emilia.provider_entry, 'NOT_ENTERED');
  assert.equal(fixture.providerCalls.length, 0);
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

test('concurrent presentation of one receipt permits exactly one provider entry', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async (payment) => {
      await new Promise((resolve) => setImmediate(resolve));
      return {
        provider_status: 'ACCEPTED',
        provider_reference: `accepted:${payment.operation}`,
      };
    },
  });
  const receipt = fixture.mintReceipt();
  const [left, right] = await Promise.all([
    fixture.tool({ ...INPUT, _emilia_receipt: receipt }),
    fixture.tool({ ...INPUT, _emilia_receipt: receipt }),
  ]);
  const results = [left, right];
  assert.equal(results.filter((result) => result._emilia?.outcome === 'EXECUTED').length, 1);
  assert.equal(results.filter((result) => result._emilia?.reason === 'replay_refused').length, 1);
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

test('a generic MCP provider error is INDETERMINATE, never a safe pre-entry refusal', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => ({
      isError: true,
      content: [{ type: 'text', text: 'provider reported an error after accepting the call' }],
    }),
  });
  const receipt = fixture.mintReceipt();
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(fixture.providerCalls.length, 1);
  assert.equal(result.isError, true);
  assert.equal(result._emilia.gate, 'allowed');
  assert.equal(result._emilia.provider_entry, 'ENTERED');
  assert.equal(result._emilia.outcome, 'INDETERMINATE');
  assert.equal(result._emilia.retry, 'REFUSE');
  assert.equal(Object.hasOwn(result._emilia, 'outcome_verification_key'), false);
  assert.equal(verifyOutcomeReceipt(result._emilia.outcome_receipt, fixture.outcomePublicKey).valid, true);
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(replay.isError, true);
  assert.match(replay._emilia.reason, /replay/);
});

test('an explicit provider agent-access refusal is NOT_ACCEPTED, consumes authority, and requires new authorization', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => ({
      provider_status: 'DECLINED',
      reason_code: 'AGENT_ACCESS_DENIED',
      provider_reference: 'decline:1842',
      confidential_provider_payload: 'must-not-leak',
    }),
  });
  const receipt = fixture.mintReceipt();
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(result.isError, true);
  assert.equal(result._emilia.gate, 'allowed');
  assert.equal(result._emilia.provider_entry, 'ENTERED');
  assert.equal(result._emilia.provider_effect, 'NOT_ACCEPTED');
  assert.equal(result._emilia.outcome, 'REFUSED');
  assert.equal(result._emilia.reason, 'provider_agent_access_denied');
  assert.equal(result._emilia.retry, 'REQUIRES_NEW_AUTHORIZATION');
  assert.equal(JSON.stringify(result).includes('must-not-leak'), false);
  assert.equal(verifyOutcomeReceipt(result._emilia.outcome_receipt, fixture.outcomePublicKey).valid, true);
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: receipt });
  assert.equal(replay._emilia.reason, 'replay_refused');
  assert.equal(fixture.providerCalls.length, 1);
});

test('an unrecognized provider refusal shape remains INDETERMINATE', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => ({ provider_status: 'DECLINED', reason_code: 'FREE_TEXT_PROVIDER_ERROR' }),
  });
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  assert.equal(result._emilia.outcome, 'INDETERMINATE');
  assert.equal(result._emilia.retry, 'REFUSE');
});

test('authenticated reconciliation resolves an indeterminate accepted operation without replaying it', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('provider accepted but response was lost'); },
    reconcile: async () => ({
      authenticated: true,
      provider_status: 'ACCEPTED',
      provider_reference: 'accepted:1842',
      confidential_provider_payload: 'must-not-leak',
    }),
  });
  const authorization = fixture.mintReceipt();
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: authorization });
  assert.equal(uncertain._emilia.outcome, 'INDETERMINATE');
  const reconciled = await fixture.reconcileTool({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  assert.equal(reconciled.isError ?? false, false);
  assert.equal(reconciled._emilia.outcome, 'EXECUTED');
  assert.equal(reconciled._emilia.reconciliation, 'ACCEPTED');
  assert.equal(reconciled._emilia.original_authority, 'CONSUMED');
  assert.equal(reconciled._emilia.retry, 'REFUSE');
  assert.equal(JSON.stringify(reconciled).includes('must-not-leak'), false);
  const reconciliationClaim = reconciled._emilia.reconciliation_receipt.payload.claim;
  const projected = JSON.parse(reconciled.content[0].text);
  assert.equal(reconciliationClaim.provider_reference, 'accepted:1842');
  assert.match(reconciliationClaim.provider_assertion_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(reconciled.provider_reference, reconciliationClaim.provider_reference);
  assert.equal(reconciled._emilia.provider_reference, reconciliationClaim.provider_reference);
  assert.equal(projected.provider_reference, reconciliationClaim.provider_reference);
  assert.equal(
    reconciled._emilia.provider_assertion_digest,
    reconciliationClaim.provider_assertion_digest,
  );
  assert.equal(verifyReconciliationReceipt(
    reconciled._emilia.reconciliation_receipt,
    fixture.outcomePublicKey,
  ).valid, true);
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: authorization });
  assert.equal(replay._emilia.reason, 'replay_refused');
  assert.equal(fixture.providerCalls.length, 1);
  assert.equal(fixture.reconciliationCalls.length, 1);
});

test('terminal reconciliation is monotone when a provider answer later changes', async () => {
  let providerStatus = 'ACCEPTED';
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('response lost'); },
    reconcile: async () => (providerStatus === 'ACCEPTED'
      ? {
        authenticated: true,
        provider_status: 'ACCEPTED',
        provider_reference: 'accepted:stable',
      }
      : {
        authenticated: true,
        authoritative: true,
        provider_status: 'NOT_ACCEPTED',
        reason_code: 'NO_PROVIDER_RECORD',
      }),
  });
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  const args = { ...INPUT, _emilia_outcome_receipt: uncertain._emilia.outcome_receipt };
  const first = await fixture.reconcileTool(args);
  providerStatus = 'NOT_ACCEPTED';
  const repeated = await fixture.reconcileTool(args);
  assert.equal(first._emilia.outcome, 'EXECUTED');
  assert.equal(repeated._emilia.outcome, 'EXECUTED');
  assert.equal(
    repeated._emilia.reconciliation_receipt.payload.receipt_id,
    first._emilia.reconciliation_receipt.payload.receipt_id,
  );
  assert.equal(fixture.reconciliationCalls.length, 1);
});

test('concurrent reconciliation has one provider lookup and one terminal signer', async () => {
  let releaseLookup;
  const lookupMayFinish = new Promise((resolve) => { releaseLookup = resolve; });
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('response lost'); },
    reconcile: async () => {
      await lookupMayFinish;
      return {
        authenticated: true,
        provider_status: 'ACCEPTED',
        provider_reference: 'accepted:concurrent',
      };
    },
  });
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  const args = { ...INPUT, _emilia_outcome_receipt: uncertain._emilia.outcome_receipt };
  const firstPromise = fixture.reconcileTool(args);
  await new Promise((resolve) => setImmediate(resolve));
  const competing = await fixture.reconcileTool(args);
  assert.equal(competing.isError, true);
  assert.equal(competing._emilia.reason, 'reconciliation_in_progress_or_recovery_required');
  assert.equal(competing._emilia.outcome, 'INDETERMINATE');
  releaseLookup();
  const first = await firstPromise;
  assert.equal(first._emilia.outcome, 'EXECUTED');
  const repeated = await fixture.reconcileTool(args);
  assert.equal(
    repeated._emilia.reconciliation_receipt.payload.receipt_id,
    first._emilia.reconciliation_receipt.payload.receipt_id,
  );
  assert.equal(fixture.reconciliationCalls.length, 1);
});

test('ACCEPTED reconciliation without a provider reference stays unsigned and INDETERMINATE', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('response lost'); },
    reconcile: async () => ({ authenticated: true, provider_status: 'ACCEPTED' }),
  });
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  const result = await fixture.reconcileTool({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  assert.equal(result.isError, true);
  assert.equal(result._emilia.outcome, 'INDETERMINATE');
  assert.equal(Object.hasOwn(result._emilia, 'reconciliation_receipt'), false);
});

test('provider-reference mutation invalidates the signed reconciliation receipt', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('response lost'); },
    reconcile: async () => ({
      authenticated: true,
      provider_status: 'ACCEPTED',
      provider_reference: 'accepted:bound',
    }),
  });
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  const reconciled = await fixture.reconcileTool({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  const tampered = structuredClone(reconciled._emilia.reconciliation_receipt);
  tampered.payload.claim.provider_reference = 'accepted:attacker';
  assert.equal(verifyReconciliationReceipt(tampered, fixture.outcomePublicKey).valid, false);

  const digestTampered = structuredClone(reconciled._emilia.reconciliation_receipt);
  digestTampered.payload.claim.provider_assertion_digest = `sha256:${'0'.repeat(64)}`;
  assert.equal(verifyReconciliationReceipt(digestTampered, fixture.outcomePublicKey).valid, false);
});

test('authenticated NOT_ACCEPTED reconciliation permits only a fresh authorization, never the consumed one', async () => {
  const fixture = createDemoPaymentReleaseFixture({
    input: INPUT,
    provider: async () => { throw new Error('connection lost'); },
    reconcile: async () => ({
      authenticated: true,
      authoritative: true,
      provider_status: 'NOT_ACCEPTED',
      reason_code: 'NO_PROVIDER_RECORD',
    }),
  });
  const authorization = fixture.mintReceipt();
  const uncertain = await fixture.tool({ ...INPUT, _emilia_receipt: authorization });
  const reconciled = await fixture.reconcileTool({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  assert.equal(reconciled.isError, true);
  assert.equal(reconciled._emilia.outcome, 'REFUSED');
  assert.equal(reconciled._emilia.reconciliation, 'NOT_ACCEPTED');
  assert.equal(reconciled._emilia.original_authority, 'CONSUMED');
  assert.equal(reconciled._emilia.retry, 'REQUIRES_NEW_AUTHORIZATION');
  const replay = await fixture.tool({ ...INPUT, _emilia_receipt: authorization });
  assert.equal(replay._emilia.reason, 'replay_refused');
});

test('unauthenticated, non-authoritative, and failed reconciliation stay INDETERMINATE', async () => {
  const cases = [
    async () => ({ authenticated: false, provider_status: 'ACCEPTED' }),
    async () => ({ authenticated: true, authoritative: false, provider_status: 'NOT_ACCEPTED' }),
    async () => { throw new Error('lookup unavailable'); },
  ];
  for (const reconcile of cases) {
    const fixture = createDemoPaymentReleaseFixture({
      input: INPUT,
      provider: async () => { throw new Error('response lost'); },
      reconcile,
    });
    const uncertain = await fixture.tool({
      ...INPUT,
      _emilia_receipt: fixture.mintReceipt(),
    });
    const result = await fixture.reconcileTool({
      ...INPUT,
      _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
    });
    assert.equal(result.isError, true);
    assert.equal(result._emilia.outcome, 'INDETERMINATE');
    assert.equal(result._emilia.retry, 'REFUSE');
    assert.equal(Object.hasOwn(result._emilia, 'reconciliation_receipt'), false);
  }
});

test('reconciliation refuses a receipt that is not a signed matching INDETERMINATE outcome', async () => {
  const successful = createDemoPaymentReleaseFixture({ input: INPUT });
  const executed = await successful.tool({
    ...INPUT,
    _emilia_receipt: successful.mintReceipt(),
  });
  const result = await successful.reconcileTool({
    ...INPUT,
    _emilia_outcome_receipt: executed._emilia.outcome_receipt,
  });
  assert.equal(result.isError, true);
  assert.equal(result._emilia.reason, 'indeterminate_outcome_receipt_required');
  assert.equal(successful.reconciliationCalls.length, 0);
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

test('outcome receipt byte mutation invalidates offline verification', async () => {
  const fixture = createDemoPaymentReleaseFixture({ input: INPUT });
  const result = await fixture.tool({ ...INPUT, _emilia_receipt: fixture.mintReceipt() });
  const tampered = structuredClone(result._emilia.outcome_receipt);
  tampered.payload.claim.operation_id = 'invoice-attacker';
  const verified = verifyOutcomeReceipt(tampered, fixture.outcomePublicKey);
  assert.equal(verified.valid, false);
  assert.equal(verified.checks.signature, false);
});

test('a valid outcome signature under an unpinned key is refused', async () => {
  const pinned = createDemoPaymentReleaseFixture({ input: INPUT });
  const unpinned = createDemoPaymentReleaseFixture({ input: INPUT });
  const result = await unpinned.tool({ ...INPUT, _emilia_receipt: unpinned.mintReceipt() });
  assert.equal(verifyOutcomeReceipt(result._emilia.outcome_receipt, unpinned.outcomePublicKey).valid, true);
  assert.equal(verifyOutcomeReceipt(result._emilia.outcome_receipt, pinned.outcomePublicKey).valid, false);
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

test('Muse PostToolUseFailure is configured and records only a privacy-minimized observation', async () => {
  const hooks = JSON.parse(await readFile(HOOKS_PATH, 'utf8'));
  assert.equal(hooks.hooks.PostToolUseFailure[0].matcher, 'mcp__emilia_payment_gate__release_payment');
  const result = await processMuseHookEvent({
    hook_event_name: 'PostToolUseFailure',
    tool_name: 'mcp__emilia_payment_gate__release_payment',
    tool_input: { ...INPUT, account: 'acct:secret-canary' },
    tool_error: 'provider credential secret-canary',
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.output, null);
  assert.deepEqual(Object.keys(result.observation).sort(), [
    'hook_event_name', 'note', 'observed_at', 'state', 'tool_name',
  ]);
  assert.equal(result.observation.state, 'MUSE_TOOL_FAILURE_UNVERIFIED');
  assert.equal(JSON.stringify(result.observation).includes('secret-canary'), false);
});

test('stdio MCP surface inventories release and read-only reconciliation with strict schemas', async () => {
  assert.deepEqual(TOOLS.map((tool) => tool.name), ['release_payment', 'reconcile_payment']);
  const unknown = await handleToolRequest({ params: { name: 'not_a_tool', arguments: {} } }, { invoke: null });
  assert.equal(unknown.isError, true);
  const listedSchema = TOOLS[0].inputSchema;
  assert.equal(listedSchema.additionalProperties, false);
  assert.deepEqual(listedSchema.required, ['payee', 'account', 'amount', 'currency', 'operation', '_emilia_receipt']);
  assert.equal(TOOLS[1].inputSchema.additionalProperties, false);
  assert.deepEqual(TOOLS[1].inputSchema.required, [
    'payee', 'account', 'amount', 'currency', 'operation', '_emilia_outcome_receipt',
  ]);
});

test('Muse settings example follows the published required stdio server shape', async () => {
  const settings = JSON.parse(await readFile(SETTINGS_PATH, 'utf8'));
  assert.equal(settings.schema_version, 1);
  assert.equal(Object.hasOwn(settings, 'mcpServers'), false);
  const server = settings.mcp_servers?.emilia_payment_gate;
  assert.equal(server?.transport, 'stdio');
  assert.equal(Object.hasOwn(server, 'type'), false);
  assert.equal(server?.mode, 'required');
  assert.equal(server?.enabled, true);
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
  assert.deepEqual(inventory.tools.map((tool) => tool.name), ['release_payment', 'reconcile_payment']);
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

test('provider reconciliation survives server restart while the original authority stays consumed', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'emilia-muse-reconcile-restart-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const generated = await generateDemoConfig(directory, { input: INPUT });
  const firstRuntime = await createServerRuntime(generated.config, {
    providerMode: 'throw_after_entry',
  });
  const uncertain = await firstRuntime.invoke(generated.call.arguments);
  assert.equal(uncertain._emilia.outcome, 'INDETERMINATE');

  const restarted = await createServerRuntime(generated.config);
  const reconciled = await restarted.reconcile({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  assert.equal(reconciled._emilia.reconciliation, 'ACCEPTED');
  assert.equal(reconciled._emilia.original_authority, 'CONSUMED');
  assert.equal(verifyReconciliationReceipt(
    reconciled._emilia.reconciliation_receipt,
    generated.call.outcome_verification_key,
  ).valid, true);
  const terminalReceiptId = reconciled._emilia.reconciliation_receipt.payload.receipt_id;

  // Even if the demo provider ledger later changes, a new server instance
  // returns the first durably pinned terminal receipt and does not equivocate.
  await writeFile(generated.config.provider_ledger_file, '', 'utf8');
  const secondRestart = await createServerRuntime(generated.config);
  const repeated = await secondRestart.reconcile({
    ...INPUT,
    _emilia_outcome_receipt: uncertain._emilia.outcome_receipt,
  });
  assert.equal(repeated._emilia.reconciliation, 'ACCEPTED');
  assert.equal(repeated._emilia.reconciliation_receipt.payload.receipt_id, terminalReceiptId);
  const replay = await restarted.invoke(generated.call.arguments);
  assert.equal(replay._emilia.reason, 'replay_refused');
});

test('standalone privacy scan proves canary secrets absent from receipts and logs', () => {
  const scan = spawnSync(process.execPath, [PRIVACY_SCAN_PATH], { encoding: 'utf8' });
  assert.equal(scan.status, 0, scan.stderr);
  const artifact = JSON.parse(scan.stdout);
  assert.equal(artifact.profile, 'EP-MUSE-CODE-GATE-PRIVACY-SCAN-v1');
  assert.equal(artifact.result, 'PASS');
  assert.equal(artifact.checks.every((check) => check.passed === true), true);
});
