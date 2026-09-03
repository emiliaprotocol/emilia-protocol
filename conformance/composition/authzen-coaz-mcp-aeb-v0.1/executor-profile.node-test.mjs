// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createExecutorProfile, executorDigest, runExecutorSuite, TEST_ONLY_fixture,
  TEST_ONLY_keyPair, TEST_ONLY_sign,
} from './executor-profile.mjs';

test('four core executor cases and two controls exercise actual callbacks', async () => {
  const report = await runExecutorSuite();
  assert.deepEqual(report.summary, { total: 6, passed: 6, failed: 0 });
  assert.equal(report.implementation.durable_store, false);
  assert.equal(report.implementation.real_provider, false);
  assert.equal(report.implementation.independent_implementation, false);
  assert.deepEqual(await runExecutorSuite(), report);
});

test('constructor has no silent public fixture defaults', () => {
  for (const config of [undefined, null, {}, [], { source: null }]) {
    assert.throws(() => createExecutorProfile(config));
  }
  const f = TEST_ONLY_fixture(); delete f.config.source.public_key;
  assert.throws(() => createExecutorProfile(f.config), /unexpected_or_missing_field/);
});

test('malformed requests, material arguments and caller-controlled configuration fail closed', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
  const junk = [null, undefined, [], {}, { operation_id: null, call: null }];
  for (const field of ['source', 'source_record', 'expected_action', 'approved_action', 'provider', 'reconcile',
    'mapping', 'mapping_digest', 'public_key', 'clock', 'machine_context', 'authenticated', 'receipt_id']) {
    junk.push({ ...f.transaction, [field]: field });
  }
  for (const field of ['amount', 'currency', 'beneficiary_account', 'payment_instruction_id']) {
    const tx = structuredClone(f.transaction); tx.call.params.arguments[field] = {};
    junk.push(tx);
    const missing = structuredClone(f.transaction); delete missing.call.params.arguments[field]; junk.push(missing);
  }
  const extra = structuredClone(f.transaction); extra.call.params.arguments.action_type = 'payment.release.1'; junk.push(extra);
  const getter = { operation_id: f.transaction.operation_id, get call() { throw new Error('must_not_run'); } }; junk.push(getter);
  const cyclic = { ...f.transaction }; cyclic.call = cyclic; junk.push(cyclic);
  for (const transaction of junk) {
    const r = await e.execute(transaction); assert.equal(r.admitted, false); assert.equal(e.state().state, 'UNUSED');
  }
  assert.equal(f.observed().calls, 0);
});

test('full source record is independently signed and exact envelope digest pinned', () => {
  for (const field of ['profile', 'source_id', 'key_id', 'audience', 'provider_id', 'mapping_digest', 'caid', 'action_digest']) {
    const f = TEST_ONLY_fixture(); f.config.source.record.body[field] = 'forged';
    f.config.source.record_digest = executorDigest(f.config.source.record);
    assert.throws(() => createExecutorProfile(f.config), /signature_invalid|wrong_signer_key/);
  }
  const f = TEST_ONLY_fixture();
  f.config.source.record = TEST_ONLY_sign(f.sourceBody, TEST_ONLY_keyPair('attacker').privateKey);
  f.config.source.record_digest = executorDigest(f.config.source.record);
  assert.throws(() => createExecutorProfile(f.config), /signature_invalid/);
});

test('valid source signatures cannot bypass pinned profile, audience, action and freshness', () => {
  for (const field of ['profile', 'audience', 'provider_id', 'mapping_digest', 'subject_id', 'client_id', 'caid', 'action_digest']) {
    const f = TEST_ONLY_fixture({ mutateSource: (body) => { body[field] = 'wrong'; } });
    assert.throws(() => createExecutorProfile(f.config), /source_binding_mismatch|source_action_binding_mismatch/);
  }
  for (const issued of [0, Date.parse('2030-01-01T00:00:00Z')]) {
    const f = TEST_ONLY_fixture({ mutateSource: (body) => { body.issued_at = issued; } });
    assert.throws(() => createExecutorProfile(f.config), /stale_or_invalid_window/);
  }
  const extra = TEST_ONLY_fixture({ mutateSource: (body) => { body.authenticated = true; } });
  assert.throws(() => createExecutorProfile(extra.config), /unexpected_or_missing_field/);
});

test('caller may not select a new operation or mutate full material action even with toy PDP ALLOW', async () => {
  for (const [field, value] of [['amount', '1260.00'], ['currency', 'USD'], ['beneficiary_account', `sha256:${'ee'.repeat(32)}`], ['payment_instruction_id', 'other']]) {
    const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config); f.transaction.call.params.arguments[field] = value;
    const r = await e.execute(f.transaction); assert.equal(r.pdp_decision, 'ALLOW'); assert.equal(r.reason, 'material_action_mismatch');
    assert.equal(f.observed().calls, 0);
  }
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
  const r = await e.execute({ ...f.transaction, operation_id: 'new-operation' });
  assert.equal(r.reason, 'operation_binding_mismatch'); assert.equal(f.observed().calls, 0);
});

test('pinned policy context may deny a valid source without becoming human approval', async () => {
  const f = TEST_ONLY_fixture({ mutateSource: (body) => { body.subject_id = 'bob@example.com'; } });
  f.config.machine_context.sub = 'bob@example.com'; const e = createExecutorProfile(f.config);
  const r = await e.execute(f.transaction); assert.equal(r.reason, 'machine_policy_denied');
  assert.equal(r.named_human_authorization_proven, false); assert.equal(f.observed().calls, 0);
});

test('construction snapshots pins, callbacks, source, context and timing settings', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
  let injected = 0;
  f.config.provider.invoke = () => { injected += 1; };
  f.config.provider.reconcile = () => { injected += 1; };
  f.config.clock = () => 0; f.config.timeout_ms = 0; f.config.machine_context.sub = 'attacker';
  f.config.source.record.body.action.beneficiary_account = 'attacker';
  f.config.provider.id = 'attacker'; f.config.provider.public_key = 'attacker';
  assert.equal((await e.execute(f.transaction)).admitted, true);
  assert.equal(f.observed().calls, 1); assert.equal(injected, 0);
  assert.throws(() => { e.execute = () => {}; }, TypeError);
});

test('provider sees an immutable material action; mutation throws and preserves uncertainty', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
  f.control.onInvoke = (request) => { request.action.beneficiary_account = 'attacker'; };
  const r = await e.execute(f.transaction); assert.equal(r.reservation.state, 'INDETERMINATE');
  assert.equal(f.observed().lastRequest.action.beneficiary_account, f.sourceBody.action.beneficiary_account);
  assert.equal((await e.execute(f.transaction)).reason, 'already_reserved'); assert.equal(f.observed().calls, 1);
});

test('reservation exists before synchronous reentrant provider callback', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config); let reentrant;
  f.control.onInvoke = () => { assert.equal(e.state().state, 'INDETERMINATE'); reentrant = e.execute(f.transaction); };
  await e.execute(f.transaction);
  assert.equal((await reentrant).reason, 'already_reserved'); assert.equal(f.observed().calls, 1);
});

test('parallel attempts reserve locally once; report snapshots cannot release custody', async () => {
  const f = TEST_ONLY_fixture({ mode: 'throw' }); const e = createExecutorProfile(f.config);
  const results = await Promise.all(Array.from({ length: 20 }, () => e.execute(structuredClone(f.transaction))));
  assert.equal(results.filter((r) => r.admitted).length, 1); assert.equal(f.observed().calls, 1);
  assert.throws(() => { e.state().state = 'UNUSED'; }, TypeError);
  assert.equal((await e.execute(f.transaction)).reason, 'already_reserved');
});

test('source freshness is checked again at execution', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config); f.advance(60000);
  assert.equal((await e.execute(f.transaction)).reason, 'stale_or_invalid_window'); assert.equal(f.observed().calls, 0);
});

test('all signed reconciliation bindings are checked without reexecution or release', async () => {
  for (const [field, value] of [['profile', 'wrong'], ['provider_id', 'wrong'], ['key_id', 'wrong'], ['audience', 'wrong'],
    ['operation_id', 'wrong'], ['source_digest', 'wrong'], ['mapping_digest', 'wrong'], ['caid', 'wrong'],
    ['action_digest', 'wrong'], ['outcome', 'UNKNOWN'], ['issued_at', 0], ['expires_at', 0], ['authenticated', true]]) {
    const f = TEST_ONLY_fixture({ mode: 'throw' }); const e = createExecutorProfile(f.config);
    await e.execute(f.transaction); f.control.evidence = f.providerResult({ [field]: value });
    const result = await e.reconcile(f.transaction.operation_id);
    assert.equal(result.reconciled, false, field); assert.equal(e.state().state, 'INDETERMINATE', field);
    assert.equal(f.observed().calls, 1); assert.equal((await e.execute(f.transaction)).reason, 'already_reserved');
  }
});

test('authenticated flag, embedded key and forged signatures establish nothing', async () => {
  const f = TEST_ONLY_fixture({ mode: 'throw' }); const e = createExecutorProfile(f.config); await e.execute(f.transaction);
  const wrongKey = f.providerResult({}, TEST_ONLY_keyPair('attacker').privateKey);
  const badSignature = f.providerResult(); badSignature.signature = 'A'.repeat(86);
  for (const evidence of [null, {}, { authenticated: true }, wrongKey, badSignature,
    { ...f.providerResult(), public_key: f.providerKeys.publicKey }]) {
    f.control.evidence = evidence;
    assert.equal((await e.reconcile(f.transaction.operation_id)).reconciled, false);
    assert.equal(e.state().state, 'INDETERMINATE');
  }
  assert.equal(f.observed().calls, 1);
});

test('successful reconciliation is authenticated provider evidence, never execution permission', async () => {
  for (const outcome of ['COMMITTED', 'NOT_COMMITTED']) {
    const f = TEST_ONLY_fixture({ mode: 'throw' }); const e = createExecutorProfile(f.config); await e.execute(f.transaction);
    f.control.evidence = f.providerResult({ outcome });
    const result = await e.reconcile(f.transaction.operation_id);
    assert.equal(result.reconciled, true); assert.equal(result.reservation.state, outcome);
    assert.equal(f.observed().calls, 1); assert.equal((await e.execute(f.transaction)).reason, 'already_reserved');
    assert.equal((await e.reconcile(f.transaction.operation_id)).reason, 'not_indeterminate');
    assert.equal(f.observed().reads, 1);
  }
});

test('unreserved operation cannot use reconciliation as an execution route', async () => {
  const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
  assert.equal((await e.reconcile(f.transaction.operation_id)).reason, 'not_indeterminate');
  assert.equal((await e.reconcile({ operation_id: f.transaction.operation_id, authenticated: true })).reason, 'operation_binding_mismatch');
  assert.deepEqual(e.counters(), { provider_invocations: 0, reconciliation_calls: 0 });
});

test('pending invocation cannot race reconciliation into a conflicting terminal state', async () => {
  const f = TEST_ONLY_fixture(); let finish;
  f.config.provider.invoke = () => new Promise((resolve) => { finish = resolve; });
  const e = createExecutorProfile(f.config); const execution = e.execute(f.transaction);
  assert.equal((await e.reconcile(f.transaction.operation_id)).reason, 'provider_call_pending');
  assert.equal(f.observed().reads, 0);
  finish(f.providerResult()); assert.equal((await execution).reservation.state, 'COMMITTED');
  assert.equal((await e.reconcile(f.transaction.operation_id)).reason, 'not_indeterminate');
});

test('timed-out reconciliation does not release uncertain custody', async () => {
  const f = TEST_ONLY_fixture({ mode: 'throw' });
  f.config.provider.reconcile = () => new Promise(() => {});
  const e = createExecutorProfile(f.config); await e.execute(f.transaction);
  const result = await e.reconcile(f.transaction.operation_id);
  assert.equal(result.reason, 'reconciliation_timeout'); assert.equal(e.state().state, 'INDETERMINATE');
  assert.equal((await e.execute(f.transaction)).reason, 'already_reserved'); assert.equal(f.observed().calls, 1);
});

test('null and forged immediate provider responses leave the one attempt indeterminate', async () => {
  for (const evidence of [null, { authenticated: true }, { body: {}, signature: 'A'.repeat(86) }]) {
    const f = TEST_ONLY_fixture(); f.control.evidence = evidence; const e = createExecutorProfile(f.config);
    assert.equal((await e.execute(f.transaction)).reservation.state, 'INDETERMINATE');
    assert.equal((await e.execute(f.transaction)).reason, 'already_reserved'); assert.equal(f.observed().calls, 1);
  }
});

test('late provider completion cannot overwrite a reconciled uncertain result', async () => {
  const f = TEST_ONLY_fixture(); let finish;
  f.config.provider.invoke = () => new Promise((resolve) => { finish = resolve; });
  const e = createExecutorProfile(f.config);
  assert.equal((await e.execute(f.transaction)).reservation.state, 'INDETERMINATE');
  assert.equal((await e.reconcile(f.transaction.operation_id)).reservation.state, 'COMMITTED');
  const final = e.state(); finish(f.providerResult({ outcome: 'NOT_COMMITTED' }));
  await Promise.resolve(); await Promise.resolve();
  assert.deepEqual(e.state(), final); assert.equal(e.counters().provider_invocations, 1);
});

test('scope explicitly excludes duplicate executor instances and restart recovery', async () => {
  const f = TEST_ONLY_fixture(); const first = createExecutorProfile(f.config); const second = createExecutorProfile(f.config);
  assert.equal((await first.execute(f.transaction)).admitted, true);
  assert.equal((await second.execute(f.transaction)).admitted, true);
  // This expected limitation must not be marketed as shared or durable custody.
  assert.equal(f.observed().calls, 2);
});

test('reconciliation uses the constructor-captured callback, never its later replacement', async () => {
  const f = TEST_ONLY_fixture({ mode: 'throw' }); const e = createExecutorProfile(f.config);
  let injected = 0; f.config.provider.reconcile = () => { injected += 1; return { authenticated: true }; };
  await e.execute(f.transaction);
  assert.equal((await e.reconcile(f.transaction.operation_id)).reconciled, true);
  assert.equal(injected, 0); assert.equal(f.observed().reads, 1); assert.equal(f.observed().calls, 1);
});

test('provider throwing non-Error values during reconciliation fails closed', async () => {
  const f = TEST_ONLY_fixture({ mode: 'throw' }); f.config.provider.reconcile = () => { throw null; };
  const e = createExecutorProfile(f.config); await e.execute(f.transaction);
  const result = await e.reconcile(f.transaction.operation_id);
  assert.equal(result.reconciled, false); assert.equal(result.reservation.state, 'INDETERMINATE');
});

test('source expiry crossing between translation and reservation refuses provider entry', async () => {
  const f = TEST_ONLY_fixture(); let reads = 0;
  f.config.clock = () => { reads += 1; return reads < 3 ? f.sourceBody.issued_at + 1000 : f.sourceBody.expires_at; };
  const e = createExecutorProfile(f.config); const result = await e.execute(f.transaction);
  assert.equal(result.reason, 'stale_or_invalid_window'); assert.equal(result.reservation.state, 'UNUSED');
  assert.equal(f.observed().calls, 0);
});

test('even an owner-pinned reentrant clock cannot split check and reserve', async () => {
  const f = TEST_ONLY_fixture(); let reads = 0; let nested; let e;
  f.config.clock = () => {
    reads += 1;
    if (reads === 3) nested = e.execute(structuredClone(f.transaction));
    return f.sourceBody.issued_at + 1000;
  };
  e = createExecutorProfile(f.config);
  const outer = await e.execute(f.transaction); const inner = await nested;
  assert.equal(outer.reason, 'already_reserved'); assert.equal(inner.admitted, true);
  assert.equal(f.observed().calls, 1);
});
