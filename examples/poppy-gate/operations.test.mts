// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalizeStrictJson } from '../../packages/verify/dist/strict-json.js';
import { createGate, createEg1Harness } from '../../packages/gate/dist/index.js';
import { createPoppyOperationsAdapter, createMemoryPoppyOperationStore, poppyActionDigest } from './operations.mjs';

const ISSUER = 'https://shop.example';
const ENDPOINT = `${ISSUER}/poppy/operations`;
const TIME = Date.parse('2026-10-12T12:00:00Z');
const owner = (overrides: any = {}) => ({
  clientId: 'https://agent.example/client.json', userId: 'user1', sessionId: 'session1',
  accountId: 'account1', scopes: ['payments:write'], dpop: { verified: true, jkt: 'pinned-key' },
  extensions: { operations: { version: '1' }, 'emiliaprotocol.ai/approval-evidence': { version: '1' } },
  ...overrides,
});
const request = (operation_id: string, suffix = '', body?: any, principal = owner()) => ({
  method: suffix ? 'POST' : 'GET', url: `${ENDPOINT}/${operation_id}${suffix}`,
  principal, ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}),
});
const proposal = (overrides: any = {}) => ({
  request: { principal: owner() }, actionKey: 'payment:one', operation_id: 'op_one',
  summary: 'Release USD 82.00 to supplier A.', terms: { amount: '82.00', currency: 'USD', destination: 'supplier-A' },
  expires_at: new Date(TIME + 60_000).toISOString(), ...overrides,
});
function setup(overrides: any = {}) {
  let count = 0;
  const store = createMemoryPoppyOperationStore();
  // Poppy's native trusted-agent profile: Gate is configured by the company,
  // and this selector explicitly does not demand a separate EP receipt.
  const gate = createGate({ manifest: { '@version': 'EP-ACTION-RISK-MANIFEST-v0.1', actions: [] }, allowEphemeralStore: true });
  const config = {
    companyIssuer: ISSUER, endpoint: ENDPOINT, store, gate, selector: { protocol: 'poppy', tool: 'release_payment' },
    requiredScopes: ['payments:write'], allowEphemeralStore: true, now: () => TIME,
    authenticateRequest: async (r: any) => r.principal,
    resolveAction: (operation: any) => ({ action_type: 'payment.release', ...operation.terms }),
    executeAction: async () => { count++; return { state: 'succeeded', summary: 'Payment accepted.', data: { provider_ref: 'p1' } }; },
    ...overrides,
  };
  const adapter = createPoppyOperationsAdapter(config);
  return { adapter, config, store, effects: () => count };
}

test('memory operation store is explicitly test-only and refused by default', () => {
  assert.throws(() => setup({ allowEphemeralStore: false }), /ephemeral/i);
});
test('removing a memory-store label cannot satisfy the production store contract', () => {
  const store = createMemoryPoppyOperationStore(); delete store.ephemeral;
  assert.throws(() => setup({ store, allowEphemeralStore: false }), /durable atomic ownership/i);
  for (const missing of ['durable', 'atomic', 'ownershipFenced']) {
    const advertised: any = { ...store, durable: true, atomic: true, ownershipFenced: true }; delete advertised[missing];
    assert.throws(() => setup({ store: advertised, allowEphemeralStore: false }), /durable atomic ownership/i);
  }
});
test('the configured issuer may include a path and operations may use another HTTPS host', async () => {
  const s = setup({ companyIssuer: 'https://identity.example/company', endpoint: 'https://api.example/poppy/operations' });
  const op = await s.adapter.propose(proposal());
  const out = await s.adapter.handle({ ...request(op.operation_id), url: 'https://api.example/poppy/operations/op_one' });
  assert.equal(out.status, 200);
});
test('impossible calendar dates and malformed URL proposals refuse without an effect', async () => {
  const s = setup();
  for (const expires_at of ['2027-02-30T10:00:00Z', '2027-02-29T10:00:00Z', '2027-01-01T24:00:00Z', '2027-01-01T00:60:00Z', '2027-01-01T00:00:00+25:00']) {
    await assert.rejects(() => s.adapter.propose(proposal({ expires_at })), /invalid_request/);
  }
  await assert.rejects(() => s.adapter.propose(proposal({ url: 'javascript:alert(1)' })), /invalid_request/);
  assert.equal(s.effects(), 0);
});
test('invalid company clocks fail closed at construction and during use', async () => {
  for (const value of [NaN, Infinity, -1, 'now', 8.64e15 + 1]) assert.throws(() => setup({ now: () => value }), /clock/i);
  let clock: any = TIME; const s = setup({ now: () => clock }); await s.adapter.propose(proposal()); clock = NaN;
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).status, 503);
  assert.equal(s.effects(), 0);
});
test('native proposal preserves operation ID, fixed revision, and does not perform work', async () => {
  const s = setup(); const op = await s.adapter.propose(proposal());
  assert.equal(op.operation_id, 'op_one'); assert.equal(op.revision, 1); assert.equal(op.state, 'proposed');
  assert.equal(op.confirmation, null); assert.equal(op.result, null); assert.equal(s.effects(), 0);
  assert.equal('owner' in op, false); assert.equal('observedAction' in op, false);
});
test('confirm uses the actual configured Gate and runs once on repeated and concurrent requests', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  const out = await Promise.all(Array.from({ length: 12 }, () => s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))));
  assert.equal(s.effects(), 1); assert.ok(out.every((r: any) => r.status === 200));
  const final = await s.adapter.handle(request('op_one'));
  assert.equal(final.body.state, 'succeeded'); assert.equal(final.body.confirmation.approved_by, 'user');
});
test('replicas and restarts share the same atomic record and do not repeat effects', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  const replica = createPoppyOperationsAdapter(s.config);
  await Promise.all([s.adapter, replica].map(a => a.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))));
  const restarted = createPoppyOperationsAdapter(s.config);
  assert.equal((await restarted.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'succeeded');
  assert.equal(s.effects(), 1);
});
test('same host action key across channels returns existing unresolved operation', async () => {
  const s = setup(); const first = await s.adapter.propose(proposal());
  assert.deepEqual(await s.adapter.propose(proposal({ operation_id: 'op_two' })), first);
});
test('authentication callback is pinned and required for every endpoint', async () => {
  let calls = 0; const s = setup({ authenticateRequest: async (r: any) => { calls++; return r.principal; } });
  await s.adapter.propose(proposal());
  s.config.authenticateRequest = async () => owner();
  for (const suffix of ['', '/confirm', '/cancel']) {
    const r = request('op_one', suffix, suffix === '/confirm' ? { revision: 1, approved_by: 'user' } : undefined, null as any);
    assert.equal((await s.adapter.handle(r)).status, 401);
  }
  assert.equal(calls, 4); assert.equal(s.effects(), 0);
});
test('caller-supplied identity cannot bypass OAuth/DPoP verification', async () => {
  const s = setup({ authenticateRequest: async () => null });
  assert.equal((await s.adapter.handle(request('op_one'))).status, 401);
});
test('DPoP assurance and normalized identities are required', async () => {
  for (const malformed of [owner({ dpop: { verified: false, jkt: 'x' } }), owner({ clientId: '' }), owner({ accountId: undefined }), owner({ scopes: 'payments:write' })]) {
    const s = setup(); assert.equal((await s.adapter.handle(request('op_one', '', undefined, malformed))).status, 401);
  }
});
test('same client/user/account can renew session; a different client, user or account gets 404', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  assert.equal((await s.adapter.handle(request('op_one', '', undefined, owner({ sessionId: 'renewed' })))).status, 200);
  for (const changed of [{ clientId: 'different' }, { userId: 'other' }, { accountId: 'other' }, { accountId: null }]) {
    assert.equal((await s.adapter.handle(request('op_one', '', undefined, owner(changed)))).status, 404);
  }
});
test('signed-out operation stays in its original session, including after signing in', async () => {
  const s = setup(); await s.adapter.propose(proposal({ request: { principal: owner({ accountId: null }) } }));
  assert.equal((await s.adapter.handle(request('op_one', '', undefined, owner({ accountId: null })))).status, 200);
  assert.equal((await s.adapter.handle(request('op_one', '', undefined, owner({ accountId: null, sessionId: 'new' })))).status, 404);
  assert.equal((await s.adapter.handle(request('op_one'))).status, 200);
});
test('missing action scope refuses confirmation before provider entry', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }, owner({ scopes: [] })));
  assert.equal(out.status, 403); assert.equal(out.body.error, 'insufficient_scope'); assert.equal(s.effects(), 0);
});
test('propose requires authenticated client metadata advertising Operations v1', async () => {
  const s = setup(); await assert.rejects(() => s.adapter.propose(proposal({ request: { principal: owner({ extensions: {} }) } })), /extension_required/);
});
test('JSON confirms refuse duplicates, unknown keys, invalid modes and nonintegral revisions', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  for (const body of ['{"revision":1,"revision":1,"approved_by":"user"}', { revision: 1, approved_by: 'user', execute: 'evil' }, { revision: 1, approved_by: 'agent' }, { revision: 1.5, approved_by: 'user' }, { revision: '1', approved_by: 'user' }]) {
    assert.equal((await s.adapter.handle(request('op_one', '/confirm', body))).status, 400);
  }
  assert.equal(s.effects(), 0);
});
test('new terms require a new immutable revision and stale confirm returns terms_changed', async () => {
  const s = setup(); const input = proposal(); await s.adapter.propose(input);
  input.terms.amount = '900.00';
  assert.equal((await s.adapter.handle(request('op_one'))).body.terms.amount, '82.00');
  const changed = await s.adapter.revise(proposal({ operation_id: 'op_one', revision: 1, summary: 'Release USD 90.00.', terms: { amount: '90.00' } }));
  assert.equal(changed.revision, 2);
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(out.status, 409); assert.equal(out.body.error, 'terms_changed'); assert.equal(out.body.operation.revision, 2); assert.equal(s.effects(), 0);
});
test('standing permission is accepted natively unless fresh user approval is required', async () => {
  const s = setup(); await s.adapter.propose(proposal({ user_approval_required: true }));
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'standing_permission' }));
  assert.equal(out.status, 403); assert.equal(out.body.error, 'user_approval_required'); assert.equal(s.effects(), 0);
  const t = setup(); await t.adapter.propose(proposal());
  assert.equal((await t.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'standing_permission' }))).body.state, 'succeeded');
});
test('proposal expiry is final, but expiry does not terminate confirmed work', async () => {
  let clock = TIME; let release: any; const started = new Promise(r => { release = r; });
  const s = setup({ now: () => clock, executeAction: async () => { await started; return { state: 'succeeded', summary: 'Done.' }; } });
  await s.adapter.propose(proposal()); clock += 60_000;
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'expired');
  clock = TIME; const t = setup({ now: () => clock, executeAction: s.config.executeAction }); await t.adapter.propose(proposal());
  const confirm = t.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  await new Promise(r => setImmediate(r)); clock += 120_000;
  assert.equal((await t.adapter.handle(request('op_one'))).body.state, 'in_progress'); release();
  assert.equal((await confirm).body.state, 'succeeded');
});
test('cancel races confirmation atomically and never overwrites a terminal state', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  await s.adapter.handle(request('op_one', '/cancel'));
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'cancelled'); assert.equal(s.effects(), 0);
  const t = setup(); await t.adapter.propose(proposal());
  await t.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal((await t.adapter.handle(request('op_one', '/cancel'))).body.state, 'succeeded');
});
test('simultaneous cancel and confirm resolve to one consistent atomic winner', async () => {
  for (let i = 0; i < 10; i++) {
    const s = setup(); await s.adapter.propose(proposal());
    await Promise.all([s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' })), s.adapter.handle(request('op_one', '/cancel'))]);
    const state = (await s.adapter.handle(request('op_one'))).body.state;
    assert.ok(['succeeded', 'cancelled'].includes(state)); assert.equal(s.effects(), state === 'succeeded' ? 1 : 0);
  }
});
test('provider response loss never becomes failed or permits a new proposal', async () => {
  let calls = 0; const s = setup({ executeAction: async () => { calls++; throw new Error('SECRET provider committed'); } });
  await s.adapter.propose(proposal());
  const first = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(first.status, 200); assert.equal(first.body.state, 'in_progress'); assert.equal(first.headers['Retry-After'], '2');
  assert.equal(JSON.stringify(first).includes('SECRET'), false);
  await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal((await s.adapter.propose(proposal({ operation_id: 'new' }))).operation_id, 'op_one'); assert.equal(calls, 1);
});
test('a slow provider returns in_progress promptly and later completion is recorded once', async () => {
  let finish: any; let executions = 0; const pending = new Promise(resolve => { finish = resolve; });
  const s = setup({ confirmResponseWaitMs: 10, executeAction: async () => { executions++; await pending; return { state: 'succeeded', summary: 'Finished later.' }; } });
  await s.adapter.propose(proposal());
  const first = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(first.body.state, 'in_progress'); assert.equal(first.headers['Retry-After'], '2');
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'in_progress');
  finish(); await new Promise(resolve => setImmediate(resolve));
  assert.equal((await s.adapter.handle(request('op_one'))).body.state, 'succeeded'); assert.equal(executions, 1);
});
test('stronger evidence profile requires negotiated extension before claiming operation', async () => {
  const s = setup({ requireApprovalEvidence: true, verifyApprovalEvidence: async () => ({ satisfied: true }) }); await s.adapter.propose(proposal());
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(out.status, 403); assert.equal(out.body.error, 'extension_required');
  assert.equal((await s.adapter.handle(request('op_one'))).body.state, 'proposed'); assert.equal(s.effects(), 0);
});
test('asynchronous evidence verification cannot confirm a revision replaced meanwhile', async () => {
  let release: any; const pause = new Promise(r => { release = r; });
  const s = setup({ requireApprovalEvidence: true, verifyApprovalEvidence: async ({ operation }: any) => { await pause; return { satisfied: true, action_digest: poppyActionDigest({ action_type: 'payment.release', ...operation.terms }) }; } });
  await s.adapter.propose(proposal());
  const confirm = s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user', extensions: { 'emiliaprotocol.ai/approval-evidence': { version: '1', evidence: {} } } }));
  await new Promise(r => setImmediate(r)); await s.adapter.revise(proposal({ revision: 1, summary: 'Different.' })); release();
  assert.equal((await confirm).status, 409); assert.equal(s.effects(), 0);
});
test('approval freshness is rechecked after slow authority resolution before confirmation', async () => {
  let clock = TIME; let enteredResolver: any; let release: any; let verifications = 0;
  const started = new Promise(resolve => { enteredResolver = resolve; }); const pause = new Promise(resolve => { release = resolve; });
  const s = setup({ now: () => clock, requireApprovalEvidence: true,
    verifyApprovalEvidence: async ({ operation }: any) => { verifications++; return { satisfied: clock < TIME + 1000,
      action_digest: poppyActionDigest({ action_type: 'payment.release', ...operation.terms }) }; },
    resolveGateReceipt: async () => { enteredResolver(); await pause; return null; } });
  await s.adapter.propose(proposal());
  const confirm = s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user', extensions: { 'emiliaprotocol.ai/approval-evidence': { version: '1', evidence: {} } } }));
  await started; clock += 2000; release(); const out = await confirm;
  assert.equal(out.status, 403); assert.equal(out.body.error, 'approval_evidence_rejected'); assert.equal(verifications, 2);
  assert.equal((await s.adapter.handle(request('op_one'))).body.state, 'proposed'); assert.equal(s.effects(), 0);
});
test('expiry CAS losing to a new revision cannot execute new terms with an old approval', async () => {
  for (const approved_by of ['user', 'standing_permission']) {
    let clock = TIME; let releaseRevision: any; let releaseExpiry: any; let beganRevision: any; let beganExpiry: any;
    const revisionGate = new Promise(resolve => { releaseRevision = resolve; });
    const expiryGate = new Promise(resolve => { releaseExpiry = resolve; });
    const revisionStarted = new Promise(resolve => { beganRevision = resolve; });
    const expiryStarted = new Promise(resolve => { beganExpiry = resolve; });
    const store = createMemoryPoppyOperationStore(); const originalCas = store.cas.bind(store);
    store.cas = async (...args: any[]) => {
      if (args[4].operation.state === 'expired') { beganExpiry(); await expiryGate; }
      return (originalCas as any)(...args);
    };
    const s = setup({ store, now: () => clock, resolveAction: async (op: any) => {
      if (op.revision === 2) { beganRevision(); await revisionGate; }
      return { action_type: 'payment.release', ...op.terms };
    } });
    await s.adapter.propose(proposal({ expires_at: new Date(TIME + 1000).toISOString() }));
    const revision = s.adapter.revise(proposal({ revision: 1, summary: 'Release USD 999.00.', terms: { amount: '999.00' }, user_approval_required: true }));
    await revisionStarted; clock += 1000;
    const confirm = s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by }));
    await expiryStarted; releaseRevision(); await revision; releaseExpiry();
    const out = await confirm;
    assert.equal(out.status, 409); assert.equal(out.body.error, 'terms_changed'); assert.equal(out.body.operation.revision, 2); assert.equal(s.effects(), 0);
    assert.equal((await s.adapter.handle(request('op_one'))).body.confirmation, null);
  }
});
test('actual Gate rejects forged or absent authority on a protected selector', async () => {
  const h = createEg1Harness({ now: () => TIME });
  const gate = createGate({ trustedKeys: [h.publicKey], approverKeys: h.approverKeys, rpId: h.rpId, allowedOrigins: h.allowedOrigins, now: () => TIME, allowEphemeralStore: true });
  const s = setup({ gate }); await s.adapter.propose(proposal());
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(out.status, 403); assert.equal(out.body.error, 'gate_refused'); assert.equal(out.body.operation.state, 'failed'); assert.equal(s.effects(), 0);
  const forged = h.mint(); forged.payload.claim.currency = 'EUR';
  const t = setup({ gate, resolveGateReceipt: async () => forged }); await t.adapter.propose(proposal());
  assert.equal((await t.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).status, 403); assert.equal(t.effects(), 0);
});
test('pinned execution and store methods cannot be replaced through a retained config object', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  s.config.executeAction = async () => { throw new Error('replacement'); }; s.store.cas = async () => false;
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'succeeded'); assert.equal(s.effects(), 1);
});
test('a failed completion write keeps unknown outcome rather than inventing success', async () => {
  const store = createMemoryPoppyOperationStore(); const original = store.cas.bind(store); let calls = 0;
  store.cas = async (...args: any[]) => { if (++calls > 1) throw new Error('SECRET disk down'); return (original as any)(...args); };
  const s = setup({ store }); await s.adapter.propose(proposal());
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal(out.status, 503); assert.equal(JSON.stringify(out).includes('SECRET'), false);
  assert.equal((await s.adapter.handle(request('op_one'))).body.state, 'in_progress');
});
test('stronger proof with the wrong action digest never reaches Gate or the provider', async () => {
  let checks = 0;
  const s = setup({ requireApprovalEvidence: true, verifyApprovalEvidence: async () => ({ satisfied: true, action_digest: `sha256:${'0'.repeat(64)}` }),
    resolveGateReceipt: () => { checks++; return null; } }); await s.adapter.propose(proposal());
  const out = await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user', extensions: { 'emiliaprotocol.ai/approval-evidence': { version: '1', evidence: {} } } }));
  assert.equal(out.status, 403); assert.equal(checks, 0); assert.equal(s.effects(), 0);
});
test('confirmed work stays readable without re-presenting optional proof metadata', async () => {
  const s = setup(); await s.adapter.propose(proposal());
  await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  assert.equal((await s.adapter.handle(request('op_one', '', undefined, owner({ extensions: { operations: { version: '1' } } })))).status, 200);
});
test('host reconciliation requires a pinned verifier and never trusts a caller terminal state', async () => {
  const s = setup({ executeAction: async () => { throw new Error('lost'); } }); await s.adapter.propose(proposal());
  await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  const record = await s.store.get(ISSUER, 'op_one');
  await assert.rejects(() => s.adapter.reconcile({ operation_id: 'op_one', revision: 1, action_digest: record!.action_digest, evidence: { valid: true, state: 'succeeded' } }), /unconfigured/);
});
test('authenticated provider outcome reconciles exactly one operation without execution', async () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const verifyProviderOutcome = ({ evidence }: any) => {
    if (!crypto.verify(null, Buffer.from(canonicalizeStrictJson(evidence.statement)), keys.publicKey, Buffer.from(evidence.signature, 'base64'))) return { valid: false };
    return { valid: true, ...evidence.statement };
  };
  let executions = 0;
  const s = setup({ executeAction: async () => { executions++; throw new Error('provider committed response lost'); }, verifyProviderOutcome });
  await s.adapter.propose(proposal()); await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }));
  const record = (await s.store.get(ISSUER, 'op_one'))!;
  const statement: any = { companyIssuer: ISSUER, operation_id: 'op_one', revision: 1, action_digest: record.action_digest,
    ownerFence: record.ownerFence, observedAction: record.observedAction, state: 'succeeded', summary: 'Provider confirmed the payment.', data: { provider_ref: 'p1' } };
  const sign = (value: any) => ({ statement: structuredClone(value), signature: crypto.sign(null, Buffer.from(canonicalizeStrictJson(value)), keys.privateKey).toString('base64') });
  const input = { operation_id: 'op_one', revision: 1, action_digest: record.action_digest };
  await assert.rejects(() => s.adapter.reconcile({ ...input, action_digest: `sha256:${'0'.repeat(64)}`, evidence: sign(statement) }), /binding_mismatch/);
  for (const changes of [{ companyIssuer: 'https://other.example' }, { operation_id: 'other' }, { revision: 2 }, { ownerFence: 'other' }, { observedAction: { amount: '900.00' } }]) {
    await assert.rejects(() => s.adapter.reconcile({ ...input, evidence: sign({ ...statement, ...changes }) }), /evidence_rejected/);
  }
  const forged = sign(statement); forged.statement.summary = 'Forgery';
  await assert.rejects(() => s.adapter.reconcile({ ...input, evidence: forged }), /evidence_rejected/);
  const final = await s.adapter.reconcile({ ...input, evidence: sign(statement) });
  assert.equal(final.state, 'succeeded'); assert.equal(executions, 1);
  assert.equal((await s.adapter.handle(request('op_one', '/confirm', { revision: 1, approved_by: 'user' }))).body.state, 'succeeded');
  assert.equal(executions, 1);
});
