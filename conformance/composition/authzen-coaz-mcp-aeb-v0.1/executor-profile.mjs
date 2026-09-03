// SPDX-License-Identifier: Apache-2.0
// Local, same-team reference executor. No durable store, real PDP, real payment
// provider, physical-truth, complete-mediation, or independent-evaluation claim.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  canonicalBytes, DECLARED_RELEASE_PAYMENT_MAPPING, toyPdpDecide,
  translateWithCaid, typedSourceAction,
} from '../coaz-translation-v0.1/run.mjs';

export const EXECUTOR_PROFILE = 'AUTHZEN-COAZ-LOCAL-EXECUTOR-v0.1';
export const SOURCE_PROFILE = 'AUTHZEN-COAZ-PINNED-SOURCE-v0.1';
export const PROVIDER_PROFILE = 'AUTHZEN-COAZ-PROVIDER-EVIDENCE-v0.1';

// Snapshot only plain JSON data. In particular, getters, class instances,
// prototype tricks, functions and undefined cannot change what was checked.
function snapshot(value, ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object' || ancestors.has(value)) throw new Error('not_plain_json');
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null && !Array.isArray(value)) throw new Error('not_plain_json');
  if (Object.getOwnPropertySymbols(value).length) throw new Error('not_plain_json');
  ancestors.add(value);
  const out = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || key === '__proto__') throw new Error('not_plain_json');
    out[key] = snapshot(descriptor.value, ancestors);
  }
  ancestors.delete(value);
  return Object.freeze(out);
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_object');
  if (Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw new Error('unexpected_or_missing_field');
}

function string(value) {
  if (typeof value !== 'string' || !value.length) throw new Error('invalid_string');
  return value;
}

function integer(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('invalid_time');
  return value;
}

function bytes(value) {
  const result = canonicalBytes(value);
  if (!result.ok) throw new Error('not_canonicalizable');
  return Buffer.from(result.canonical, 'utf8');
}

export function executorDigest(value) {
  return `sha256:${crypto.createHash('sha256').update(bytes(value)).digest('hex')}`;
}

const MAPPING = snapshot(DECLARED_RELEASE_PAYMENT_MAPPING);
export const EXECUTOR_MAPPING_DIGEST = executorDigest(MAPPING);
const ACTION_KEYS = ['action_type', 'amount', 'currency', 'beneficiary_account', 'payment_instruction_id'];
const SOURCE_KEYS = ['profile', 'source_id', 'key_id', 'audience', 'provider_id', 'operation_id',
  'subject_id', 'client_id', 'mapping_digest', 'issued_at', 'expires_at', 'action', 'caid', 'action_digest'];
const RESULT_KEYS = ['profile', 'provider_id', 'key_id', 'audience', 'operation_id', 'source_digest',
  'mapping_digest', 'caid', 'action_digest', 'issued_at', 'expires_at', 'outcome'];

function validatedCall(call) {
  exact(call, ['jsonrpc', 'id', 'method', 'params']);
  if (call.jsonrpc !== '2.0' || call.method !== 'tools/call' || !Number.isSafeInteger(call.id)) throw new Error('invalid_mcp_call');
  exact(call.params, ['name', 'arguments']);
  if (call.params.name !== 'release_payment') throw new Error('wrong_tool');
  exact(call.params.arguments, ACTION_KEYS.filter((key) => key !== 'action_type'));
  for (const value of Object.values(call.params.arguments)) string(value);
  if (!/^(0|[1-9][0-9]*)\.[0-9]{2}$/.test(call.params.arguments.amount)
    || !/^[A-Z]{3}$/.test(call.params.arguments.currency)
    || !/^sha256:[0-9a-f]{64}$/.test(call.params.arguments.beneficiary_account)) throw new Error('invalid_material_field');
  return call;
}

function actionCall(action) {
  exact(action, ACTION_KEYS);
  if (action.action_type !== 'payment.release.1') throw new Error('wrong_action_type');
  const { action_type: ignored, ...args } = action;
  return validatedCall({ jsonrpc: '2.0', id: 0, method: 'tools/call', params: { name: 'release_payment', arguments: args } });
}

function fresh(body, now, maxAge) {
  integer(body.issued_at); integer(body.expires_at);
  if (body.issued_at > now || body.expires_at <= now || body.expires_at <= body.issued_at
    || now - body.issued_at > maxAge || body.expires_at - body.issued_at > maxAge) throw new Error('stale_or_invalid_window');
}

function publicKey(pem) {
  const key = crypto.createPublicKey(string(pem));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong_key_type');
  return key;
}

function verifiedEnvelope(envelope, key, keyId, keys) {
  exact(envelope, ['body', 'signature']); exact(envelope.body, keys);
  if (envelope.body.key_id !== keyId) throw new Error('wrong_signer_key');
  if (typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) throw new Error('invalid_signature_encoding');
  const signature = Buffer.from(envelope.signature, 'base64url');
  if (signature.toString('base64url') !== envelope.signature) throw new Error('invalid_signature_encoding');
  if (!crypto.verify(null, bytes(envelope.body), key, signature)) throw new Error('signature_invalid');
  return envelope.body;
}

/**
 * Construction is the executor owner's trusted configuration boundary.
 * source.record is obtained independently from the caller/translator and its
 * exact envelope digest and signing key are pinned here. It is NOT accepted in
 * execute(). A signature establishes this configured source's statement, not
 * physical truth, human approval, or an AuthZEN-signed decision.
 *
 * Callbacks are captured once and called without a mutable receiver. Their
 * internal implementation and the process owner remain trusted. The clock and
 * authenticated machine context are deployment inputs, not validated OAuth.
 */
export function createExecutorProfile(config) {
  exact(config, ['audience', 'source', 'provider', 'machine_context', 'clock', 'timeout_ms', 'max_age_ms']);
  exact(config.source, ['id', 'key_id', 'public_key', 'record_digest', 'record']);
  exact(config.provider, ['profile', 'id', 'key_id', 'public_key', 'audience', 'invoke', 'reconcile']);
  const audience = string(config.audience);
  const source = snapshot(config.source);
  const provider = snapshot({ profile: config.provider.profile, id: config.provider.id,
    key_id: config.provider.key_id, public_key: config.provider.public_key, audience: config.provider.audience });
  const machine = snapshot(config.machine_context);
  exact(machine, ['sub', 'client_id']); string(machine.sub); string(machine.client_id);
  const clock = config.clock; const invoke = config.provider.invoke; const fetchReconciliation = config.provider.reconcile;
  if ([clock, invoke, fetchReconciliation].some((fn) => typeof fn !== 'function')) throw new Error('missing_pinned_interface');
  const timeout = integer(config.timeout_ms); const maxAge = integer(config.max_age_ms);
  if (timeout === 0 || timeout > 60000 || maxAge === 0) throw new Error('invalid_timeout_or_age');
  if (provider.profile !== PROVIDER_PROFILE || provider.audience !== audience) throw new Error('wrong_provider_interface');
  const sourceKey = publicKey(source.public_key); const providerKey = publicKey(provider.public_key);
  if (sourceKey.export({ type: 'spki', format: 'der' }).equals(providerKey.export({ type: 'spki', format: 'der' }))) throw new Error('source_provider_keys_must_differ');
  const now = () => integer(Reflect.apply(clock, undefined, []));
  if (executorDigest(source.record) !== source.record_digest) throw new Error('source_record_pin_mismatch');
  const approved = verifiedEnvelope(source.record, sourceKey, source.key_id, SOURCE_KEYS);
  if (approved.profile !== SOURCE_PROFILE || approved.source_id !== source.id || approved.audience !== audience
    || approved.provider_id !== provider.id || approved.mapping_digest !== EXECUTOR_MAPPING_DIGEST
    || approved.subject_id !== machine.sub || approved.client_id !== machine.client_id) throw new Error('source_binding_mismatch');
  string(approved.operation_id); string(provider.id); string(provider.key_id); string(source.id); string(source.key_id);
  fresh(approved, now(), maxAge);
  const expected = translateWithCaid(MAPPING, actionCall(approved.action), machine);
  if (!expected.ok || expected.caid !== approved.caid || executorDigest(approved.action) !== approved.action_digest) throw new Error('source_action_binding_mismatch');
  // Stable key is provider + operation, never a caller token or receipt label.
  // Store is private, synchronous and limited to ONE live executor instance.
  // A second instance (even in this process) or restart has a new empty store.
  // Owners must route a protected operation through that same live instance;
  // a production executor needs shared durable atomic custody instead.
  const reservations = new Map();
  const slot = `${provider.id}\0${approved.operation_id}`;
  let invocationCount = 0; let reconciliationCount = 0; let invocationPending = false;
  const state = () => snapshot(reservations.get(slot) ?? { state: 'UNUSED' });
  const refuse = (reason, extra = {}) => snapshot({ admitted: false, reason, ...extra, reservation: state() });

  function resultBody(raw, enteredAt) {
    const envelope = snapshot(raw);
    const body = verifiedEnvelope(envelope, providerKey, provider.key_id, RESULT_KEYS);
    if (body.profile !== PROVIDER_PROFILE || body.provider_id !== provider.id || body.audience !== audience
      || body.operation_id !== approved.operation_id || body.source_digest !== source.record_digest
      || body.mapping_digest !== EXECUTOR_MAPPING_DIGEST || body.caid !== approved.caid
      || body.action_digest !== approved.action_digest) throw new Error('provider_evidence_binding_mismatch');
    if (!['COMMITTED', 'NOT_COMMITTED'].includes(body.outcome)) throw new Error('unknown_provider_outcome');
    fresh(body, now(), maxAge);
    if (body.issued_at < enteredAt) throw new Error('evidence_predates_entry');
    return { body, evidenceDigest: executorDigest(envelope) };
  }

  const requestForProvider = () => snapshot({ profile: EXECUTOR_PROFILE, provider_id: provider.id,
    audience, operation_id: approved.operation_id, source_digest: source.record_digest,
    mapping_digest: EXECUTOR_MAPPING_DIGEST, caid: approved.caid,
    action_digest: approved.action_digest, action: approved.action });

  async function execute(raw) {
    let transaction; let translated;
    try {
      transaction = snapshot(raw); exact(transaction, ['operation_id', 'call']);
      if (transaction.operation_id !== approved.operation_id) throw new Error('operation_binding_mismatch');
      fresh(approved, now(), maxAge);
      const call = validatedCall(transaction.call);
      translated = translateWithCaid(MAPPING, call, machine);
      if (!translated.ok) throw new Error('translation_refused');
    } catch (error) { return refuse(error instanceof Error ? error.message : 'input_validation_failed'); }
    const decision = toyPdpDecide(translated.request);
    const axes = { pdp_decision: decision.decision ? 'ALLOW' : 'DENY',
      authzen_role: 'MACHINE_POLICY_INPUT', named_human_authorization_proven: false };
    // Compare the FULL source action, not only the PDP's lossy tuple or a CAID
    // provided by the caller. Expected content comes only from the pinned record.
    if (translated.caid !== approved.caid || executorDigest(typedSourceAction(transaction.call)) !== approved.action_digest
      || !bytes(translated.source_action).equals(bytes(approved.action))) return refuse('material_action_mismatch', axes);
    if (!decision.decision) return refuse('machine_policy_denied', axes);
    if (reservations.has(slot)) return refuse('already_reserved', axes);
    let enteredAt;
    try { enteredAt = now(); fresh(approved, enteredAt, maxAge); }
    catch (error) { return refuse(error instanceof Error ? error.message : 'entry_clock_failed', axes); }
    // The injected clock is owner-pinned, but recheck after calling it so even
    // a reentrant clock cannot separate the final check from the local reserve.
    if (reservations.has(slot)) return refuse('already_reserved', axes);
    reservations.set(slot, { state: 'RESERVED', entered_at: enteredAt });
    const request = requestForProvider();
    // Reservation is set before invoking even synchronous/reentrant providers.
    invocationCount += 1;
    invocationPending = true;
    reservations.set(slot, { state: 'INDETERMINATE', entered_at: enteredAt });
    let timer;
    try {
      const pending = Promise.resolve(Reflect.apply(invoke, undefined, [request]));
      const result = await Promise.race([pending, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('provider_timeout')), timeout);
      })]);
      const { body, evidenceDigest } = resultBody(result, enteredAt);
      reservations.set(slot, { state: body.outcome, entered_at: enteredAt, evidence_digest: evidenceDigest });
      return snapshot({ admitted: true, ...axes, provider_evidence: 'VERIFIED', reservation: state() });
    } catch {
      // Includes throw-after-entry, timeout, malformed response and bad proof.
      // An uncertain operation never becomes UNUSED and cannot be blindly retried.
      return snapshot({ admitted: true, ...axes, provider_evidence: 'UNCONFIRMED', reservation: state() });
    } finally { invocationPending = false; if (timer !== undefined) clearTimeout(timer); }
  }

  async function reconcile(operationId) {
    if (operationId !== approved.operation_id) return refuse('operation_binding_mismatch');
    const before = reservations.get(slot);
    if (!before || before.state !== 'INDETERMINATE') return refuse('not_indeterminate');
    if (invocationPending) return refuse('provider_call_pending');
    reconciliationCount += 1;
    let timer;
    try {
      const pending = Promise.resolve(Reflect.apply(fetchReconciliation, undefined, [requestForProvider()]));
      const raw = await Promise.race([pending, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('reconciliation_timeout')), timeout);
      })]);
      const { body, evidenceDigest } = resultBody(raw, before.entered_at);
      // An overlapping reconciliation cannot overwrite an already closed result.
      if (reservations.get(slot).state !== 'INDETERMINATE') return refuse('already_reconciled');
      reservations.set(slot, { state: body.outcome, entered_at: before.entered_at, evidence_digest: evidenceDigest });
      return snapshot({ reconciled: true, provider_evidence: 'VERIFIED', reservation: state() });
    } catch (error) { return snapshot({ reconciled: false,
      reason: error instanceof Error ? error.message : 'provider_reconciliation_failed', reservation: state() }); }
    finally { if (timer !== undefined) clearTimeout(timer); }
  }

  return Object.freeze({ execute, reconcile, state,
    counters: () => Object.freeze({ provider_invocations: invocationCount, reconciliation_calls: reconciliationCount }) });
}

// Explicitly TEST ONLY. Deterministic public fixture keys are never a default
// of createExecutorProfile(), and prove no external issuer/provider identity.
export function TEST_ONLY_keyPair(label) {
  const seed = crypto.createHash('sha256').update(`EMILIA-PUBLIC-AUTHZEN-EXECUTOR-FIXTURE:${label}`).digest();
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }) };
}

export function TEST_ONLY_sign(body, privateKey) {
  return { body: structuredClone(body), signature: crypto.sign(null, bytes(body), privateKey).toString('base64url') };
}

export function TEST_ONLY_fixture({ mode = 'success', mutateSource } = {}) {
  const sourceKeys = TEST_ONLY_keyPair('source'); const providerKeys = TEST_ONLY_keyPair('provider');
  let time = Date.parse('2026-09-03T12:00:00Z');
  const call = { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'release_payment', arguments: {
    amount: '1250.00', currency: 'EUR', beneficiary_account: `sha256:${'6b'.repeat(32)}`, payment_instruction_id: 'pi_9912' } } };
  const machine = { sub: 'alice@example.com', client_id: 'test-agent' };
  const translated = translateWithCaid(MAPPING, call, machine);
  const sourceBody = { profile: SOURCE_PROFILE, source_id: 'test:payment-instruction-record', key_id: 'test:source-key',
    audience: 'test:executor', provider_id: 'test:payment-provider', operation_id: 'test:operation-9912',
    subject_id: machine.sub, client_id: machine.client_id, mapping_digest: EXECUTOR_MAPPING_DIGEST,
    issued_at: time - 1000, expires_at: time + 59000, action: translated.source_action,
    caid: translated.caid, action_digest: executorDigest(translated.source_action) };
  if (mutateSource) mutateSource(sourceBody);
  const record = TEST_ONLY_sign(sourceBody, sourceKeys.privateKey);
  let calls = 0; let reads = 0; let lastRequest;
  const control = { mode, evidence: undefined, onInvoke: undefined };
  const providerResult = (changes = {}, key = providerKeys.privateKey) => TEST_ONLY_sign({
    profile: PROVIDER_PROFILE, provider_id: 'test:payment-provider', key_id: 'test:provider-key', audience: 'test:executor',
    operation_id: sourceBody.operation_id, source_digest: executorDigest(record), mapping_digest: EXECUTOR_MAPPING_DIGEST,
    caid: sourceBody.caid, action_digest: sourceBody.action_digest, issued_at: time, expires_at: time + 59000,
    outcome: 'COMMITTED', ...changes,
  }, key);
  const config = { audience: 'test:executor', source: { id: sourceBody.source_id, key_id: 'test:source-key',
    public_key: sourceKeys.publicKey, record_digest: executorDigest(record), record },
  provider: { profile: PROVIDER_PROFILE, id: 'test:payment-provider', key_id: 'test:provider-key',
    public_key: providerKeys.publicKey, audience: 'test:executor',
    invoke(request) {
      calls += 1; lastRequest = request;
      if (control.onInvoke) control.onInvoke(request);
      if (control.mode === 'throw') throw new Error('provider_entered_then_response_lost');
      if (control.mode === 'timeout') return new Promise(() => {});
      return control.evidence === undefined ? providerResult() : control.evidence;
    },
    reconcile(request) { reads += 1; lastRequest = request; return control.evidence === undefined ? providerResult() : control.evidence; },
  }, machine_context: machine, clock: () => time, timeout_ms: 5, max_age_ms: 60000 };
  return { config, call, transaction: { operation_id: sourceBody.operation_id, call }, control, providerResult,
    sourceKeys, providerKeys, sourceBody, advance: (ms) => { time += ms; },
    observed: () => ({ calls, reads, lastRequest }) };
}

/** Deterministic report: assertions fail the runner, never fabricate a pass. */
export async function runExecutorSuite() {
  const cases = [];
  async function run(id, action) { const observed = await action(); cases.push({ id, passed: true, observed }); }
  await run('executor_exact_allow_invokes_once', async () => {
    const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config); const r = await e.execute(f.transaction);
    assert.equal(r.reservation.state, 'COMMITTED'); assert.equal(f.observed().calls, 1);
    return { ...r, ...e.counters(), callback_calls: f.observed().calls };
  });
  await run('executor_changed_beneficiary_refused_before_entry', async () => {
    const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
    f.transaction.call.params.arguments.beneficiary_account = `sha256:${'ee'.repeat(32)}`;
    const r = await e.execute(f.transaction);
    assert.equal(r.pdp_decision, 'ALLOW'); assert.equal(r.reason, 'material_action_mismatch'); assert.equal(f.observed().calls, 0);
    return { ...r, ...e.counters(), callback_calls: f.observed().calls };
  });
  await run('executor_concurrent_replay_has_one_provider_entry', async () => {
    const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
    const results = await Promise.all([e.execute(f.transaction), e.execute(structuredClone(f.transaction))]);
    assert.equal(results.filter((r) => r.admitted).length, 1); assert.equal(results[1].reason, 'already_reserved'); assert.equal(f.observed().calls, 1);
    return { admitted_attempts: 1, refused_attempts: 1, ...e.counters(), callback_calls: f.observed().calls };
  });
  await run('executor_timeout_preserved_then_authenticated_reconciliation', async () => {
    const f = TEST_ONLY_fixture({ mode: 'timeout' }); const e = createExecutorProfile(f.config);
    const first = await e.execute(f.transaction); assert.equal(first.reservation.state, 'INDETERMINATE');
    const replay = await e.execute(f.transaction); assert.equal(replay.reason, 'already_reserved');
    f.control.evidence = f.providerResult({ provider_id: 'test:wrong-provider' });
    const wrong = await e.reconcile(f.transaction.operation_id); assert.equal(wrong.reconciled, false);
    assert.equal(e.state().state, 'INDETERMINATE');
    f.control.evidence = f.providerResult(); const closed = await e.reconcile(f.transaction.operation_id);
    assert.equal(closed.reconciled, true); assert.equal(closed.reservation.state, 'COMMITTED'); assert.equal(f.observed().calls, 1);
    return { first_state: first.reservation.state, replay_refused: true, wrong_provider_refused: true,
      final_state: e.state().state, ...e.counters(), callback_calls: f.observed().calls };
  });
  await run('executor_source_pin_substitution_refused', async () => {
    const f = TEST_ONLY_fixture(); f.config.source.record.body.action.beneficiary_account = `sha256:${'ee'.repeat(32)}`;
    assert.throws(() => createExecutorProfile(f.config), /source_record_pin_mismatch/);
    return { constructed: false, callback_calls: f.observed().calls };
  });
  await run('executor_transaction_configuration_spoof_refused', async () => {
    const f = TEST_ONLY_fixture(); const e = createExecutorProfile(f.config);
    const r = await e.execute({ ...f.transaction, source: f.config.source });
    assert.equal(r.admitted, false); assert.equal(f.observed().calls, 0);
    return { reason: r.reason, callback_calls: f.observed().calls };
  });
  return { profile: EXECUTOR_PROFILE, implementation: { scope: 'ONE_LIVE_EXECUTOR_INSTANCE',
    independent_implementation: false, real_pdp: false, real_provider: false, durable_store: false,
    distributed_store: false, physical_truth_proven: false, human_authorization_proven: false },
  summary: { total: cases.length, passed: cases.length, failed: 0 }, cases };
}
