// SPDX-License-Identifier: Apache-2.0
/** Bounded mock-provider/attempt-store tests; not live Stripe or PostgreSQL. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createEg1Harness, createGate } from '../index.js';
import {
  createStripeDurableRefundManifest,
  createStripeRefundDurableStore,
  createStripeRefundDurableConnector,
  guardStripeRefundDurable,
  reconcileStripeRefundDurable,
  stripeRefundAttemptDigests,
} from './stripe-refund-durable.js';
import { createStripeManifest, guardStripeMutation } from './stripe.js';
import { deriveOAuthTransactionTokenReplayUnit } from '../../verify/aeb-wimse-oauth-adapter.js';

// Read from the manifest rather than a module constant, so a regression test
// run against older connector code fails for the defect it targets.
const DURABLE_ACTION_TYPE = createStripeDurableRefundManifest().actions
  .find((entry) => entry.match?.tool === 'create_refund').action_type;
const accountId = 'acct_authorized';
const job = {
  payment_intent: 'pi_refund_test',
  amount: 5000,
  operation_id: 'refund:order-123:01',
};
const action = (p = job, account = accountId, tenant = 'tenant:finance', environment = 'test') => ({
  action_type: DURABLE_ACTION_TYPE, tenant_id: tenant, environment,
  provider_account_id: account,
  payment_intent: p.payment_intent, amount: p.amount,
  operation_id: p.operation_id,
});

class AttemptStore {
  durable = true;
  ownershipFenced = true;
  compareAndSwap = true;
  atomicEvidenceBinding = true;
  row = null;
  rows = new Map();
  serial = 0;
  stale = false;

  async reserve(binding) {
    // Models the PTE unique provider-scoped attempt_id and request digest.
    if (this.rows.has(binding.attempt_id)
        || [...this.rows.values()].some((row) => row.binding.request_digest === binding.request_digest)) {
      return { reserved: false, reason: 'attempt_exists' };
    }
    const owner = `owner:${++this.serial}`;
    const row = { binding, owner, state: 'RESERVED', evidence: null };
    this.rows.set(binding.attempt_id, row);
    this.row = row;
    return { reserved: true, owner };
  }

  async transition({ tenant_id, attempt_id, owner, expected_state, next_state }) {
    const row = this.rows.get(attempt_id);
    if (!row || row.binding.tenant_id !== tenant_id || row.owner !== owner
        || row.state !== expected_state) return false;
    row.state = next_state;
    return true;
  }

  async reconcile({ tenant_id, attempt_id, owner, expected_state, next_state, evidence }) {
    const row = this.rows.get(attempt_id);
    if (!row || row.binding.tenant_id !== tenant_id || row.owner !== owner
        || row.state !== expected_state || next_state !== 'COMMITTED'
        || evidence.request_digest !== row.binding.request_digest
        || evidence.provider_account_id !== row.binding.provider_account_id) return false;
    row.state = next_state;
    row.evidence = evidence;
    return true;
  }

  // No lookup(): recovery must work on the exported PTE DDL, which has no
  // lookup_attempt function, by reading the deterministic binding directly.

  async read(binding) {
    const row = this.rows.get(binding.attempt_id);
    if (!row || row.binding.request_digest !== binding.request_digest) return null;
    // These are the deterministic profile digests the production PTE store
    // derives in its configured resolver.
    const { stripeRefundAttemptDigests } = await import('./stripe-refund-durable.js');
    return { ...row.binding, ...stripeRefundAttemptDigests(row.binding),
      state: row.state, evidence_digest: row.evidence?.evidence_digest ?? null,
      lease_stale: this.stale };
  }

  async recover(binding) {
    const row = this.rows.get(binding.attempt_id);
    if (!row || !this.stale || ['COMMITTED', 'RELEASED', 'ESCALATED'].includes(row.state)) {
      return { recovered: false, reason: 'attempt_not_stale' };
    }
    row.owner = `owner:${++this.serial}`;
    row.state = row.state === 'RESERVED' ? 'RESERVED' : 'INDETERMINATE';
    this.stale = false;
    return { recovered: true, owner: row.owner, state: row.state };
  }
}

function provider({ loseFirstResponse = false } = {}) {
  const calls = [];
  const refunds = [];
  let account = accountId;
  let listFailure = false;
  let more = false;
  let cacheEnabled = true;
  return {
    calls, records: refunds,
    setAccount(value) { account = value; },
    setListFailure(value) { listFailure = value; },
    setMore(value) { more = value; },
    expireIdempotencyCache() { cacheEnabled = false; },
    accounts: { async retrieve() { return { id: account }; } },
    refunds: {
      async create(params, options) {
        calls.push({ params, options });
        const prior = cacheEnabled
          ? refunds.find((refund) => refund.metadata.emilia_idempotency_key === options.idempotencyKey)
          : null;
        if (prior) return prior;
        const refund = {
          id: `re_${refunds.length + 1}`, payment_intent: params.payment_intent,
          amount: params.amount, metadata: params.metadata,
          created: Math.floor(Date.now() / 1000), status: 'pending',
        };
        refunds.push(refund);
        if (loseFirstResponse) throw new Error('response lost after Stripe accepted');
        return refund;
      },
      async list({ payment_intent }) {
        if (listFailure) throw new Error('Stripe unavailable');
        return { data: refunds.filter((refund) => refund.payment_intent === payment_intent), has_more: more };
      },
    },
  };
}

async function fixture({ p = job, store = new AttemptStore(), stripe = provider(),
  legacyManifest = false, metadataKey = new Uint8Array(32).fill(17),
  tenantId = 'tenant:finance', environment = 'test', harness: sharedHarness } = {}) {
  const harness = sharedHarness ?? createEg1Harness({ action: action(p, accountId, tenantId, environment) });
  const gate = createGate({
    manifest: legacyManifest ? createStripeManifest() : createStripeDurableRefundManifest(),
    trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy, rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true,
  });
  const connector = await createStripeRefundDurableConnector({
    stripe, gate, store, tenant_id: tenantId, environment,
    metadata_hmac_sha256_key: metadataKey,
    resolve_operation: (reference) => {
      assert.equal(reference, 'refund-job-01');
      return p;
    },
  });
  return { connector, harness, gate, store, stripe };
}

test('lost response remains indeterminate; fresh approval after restart never re-enters Stripe; positive matching evidence commits', async () => {
  const firstTxn = deriveOAuthTransactionTokenReplayUnit(
    'payments.example', 'wimse://payments.example/workloads/payment-executor', 'txn-first');
  const freshTxn = deriveOAuthTransactionTokenReplayUnit(
    'payments.example', 'wimse://payments.example/workloads/payment-executor', 'txn-fresh');
  assert.notEqual(firstTxn, freshTxn);
  const store = new AttemptStore();
  const stripe = provider({ loseFirstResponse: true });
  const first = await fixture({ store, stripe });
  const firstResult = await guardStripeRefundDurable(first.connector, {
    operation_reference: 'refund-job-01', receipt: first.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(firstResult.state, 'INDETERMINATE');
  assert.equal(stripe.calls.length, 1);
  assert.equal(store.row.state, 'INDETERMINATE');
  assert.equal(stripe.calls[0].params.metadata.emilia_operation_id, job.operation_id);
  assert.equal(stripe.calls[0].params.metadata.emilia_origin_tag.length, 64);

  const restarted = await fixture({ store, stripe });
  stripe.expireIdempotencyCache();
  const secondResult = await guardStripeRefundDurable(restarted.connector, {
    operation_reference: 'refund-job-01', receipt: restarted.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(secondResult.reason, 'operation_already_reserved');
  assert.equal(stripe.calls.length, 1);
  assert.equal((await reconcileStripeRefundDurable(restarted.connector, 'refund-job-01')).reason, 'attempt_owner_active');
  store.stale = true;
  const oldOwner = store.row.owner;
  const recovery = await reconcileStripeRefundDurable(restarted.connector, 'refund-job-01');
  assert.deepEqual(recovery, { ok: true, state: 'COMMITTED', refund_id: 're_1' });
  assert.notEqual(store.row.owner, oldOwner);
  assert.equal(store.row.state, 'COMMITTED');
  assert.equal(store.row.evidence.evidence_id, 're_1');
  assert.equal(stripe.calls.length, 1);
  assert.equal((await reconcileStripeRefundDurable(restarted.connector, 'refund-job-01')).state, 'COMMITTED');
});

test('same operation with changed amount is fenced, while two equal refunds with distinct operation IDs execute', async () => {
  const store = new AttemptStore();
  const stripe = provider();
  const first = await fixture({ store, stripe });
  assert.equal((await guardStripeRefundDurable(first.connector, {
    operation_reference: 'refund-job-01', receipt: first.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  const changed = await fixture({ store, stripe, p: { ...job, amount: 4000 } });
  assert.equal((await guardStripeRefundDurable(changed.connector, {
    operation_reference: 'refund-job-01', receipt: changed.harness.mint({ outcome: 'allow_with_signoff' }),
  })).reason, 'operation_already_reserved');
  assert.equal(stripe.calls.length, 1);
  const secondOp = await fixture({ store, stripe, p: { ...job, operation_id: 'refund:order-123:02' } });
  assert.equal((await guardStripeRefundDurable(secondOp.connector, {
    operation_reference: 'refund-job-01', receipt: secondOp.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  assert.equal(stripe.calls.length, 2);
  assert.notEqual(stripe.calls[0].options.idempotencyKey, stripe.calls[1].options.idempotencyKey);
});

test('old manifest lacking account binding refuses; wrong signed account never reaches Stripe', async () => {
  const legacy = await fixture({ legacyManifest: true });
  const old = await guardStripeRefundDurable(legacy.connector, {
    operation_reference: 'refund-job-01', receipt: legacy.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(old.state, 'REFUSED');
  assert.equal(legacy.stripe.calls.length, 0);
  assert.equal(legacy.store.row, null);
  // A durable-typed entry whose field list omits the namespace and account.
  const weakened = createStripeDurableRefundManifest();
  weakened.actions = weakened.actions.map((entry) => entry.action_type === DURABLE_ACTION_TYPE
    ? { ...entry, execution_binding: { required_fields: ['action_type', 'payment_intent', 'amount', 'operation_id'] } }
    : entry);
  const weakHarness = createEg1Harness({ action: action() });
  const weakStripe = provider();
  const weakStore = new AttemptStore();
  const weakConnector = await createStripeRefundDurableConnector({
    stripe: weakStripe, store: weakStore,
    gate: createGate({
      manifest: weakened, trustedKeys: [weakHarness.publicKey], approverKeys: weakHarness.approverKeys,
      quorumPolicy: weakHarness.quorumPolicy, rpId: weakHarness.rpId,
      allowedOrigins: weakHarness.allowedOrigins, allowEphemeralStore: true,
    }),
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: () => job,
  });
  assert.deepEqual(await guardStripeRefundDurable(weakConnector, {
    operation_reference: 'refund-job-01', receipt: weakHarness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'REFUSED', reason: 'stripe_account_binding_profile_required' });
  assert.equal(weakStripe.calls.length, 0);
  assert.equal(weakStore.row, null);
  const wrongHarness = createEg1Harness({ action: action(job, 'acct_someone_else') });
  const wrongGate = createGate({
    manifest: createStripeDurableRefundManifest(), trustedKeys: [wrongHarness.publicKey],
    approverKeys: wrongHarness.approverKeys, quorumPolicy: wrongHarness.quorumPolicy,
    rpId: wrongHarness.rpId, allowedOrigins: wrongHarness.allowedOrigins,
    allowEphemeralStore: true,
  });
  const wrongStripe = provider();
  const wrongConnector = await createStripeRefundDurableConnector({
    stripe: wrongStripe, gate: wrongGate, store: new AttemptStore(),
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: () => job,
  });
  assert.equal((await guardStripeRefundDurable(wrongConnector, {
    operation_reference: 'refund-job-01', receipt: wrongHarness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'REFUSED');
  assert.equal(wrongStripe.calls.length, 0);
  const current = await fixture();
  current.stripe.setAccount('acct_other');
  assert.deepEqual(await guardStripeRefundDurable(current.connector, {
    operation_reference: 'refund-job-01', receipt: current.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'REFUSED', reason: 'stripe_account_changed' });
  assert.equal(current.stripe.calls.length, 0);
  assert.equal(current.store.row, null);
});

test('a weaker manifest resolved between preflight and Gate callback cannot enter Stripe', async () => {
  const fixtureValue = await fixture();
  const weakGate = {
    check: fixtureValue.gate.check.bind(fixtureValue.gate),
    async run(_input, effect) {
      return effect({ allow: true, requirement: { receipt_required: true,
        execution_binding: { required_fields: ['action_type', 'payment_intent', 'amount', 'operation_id'] } } });
    },
  };
  const connector = await createStripeRefundDurableConnector({
    stripe: fixtureValue.stripe, gate: weakGate, store: fixtureValue.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: () => job,
  });
  const result = await guardStripeRefundDurable(connector, {
    operation_reference: 'refund-job-01',
    receipt: fixtureValue.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.state, 'INDETERMINATE');
  assert.equal(fixtureValue.stripe.calls.length, 0);
});

test('a Gate callback invoked twice cannot make a second provider-entry attempt', async () => {
  const fixtureValue = await fixture();
  let secondCallbackError;
  const duplicateGate = {
    check: fixtureValue.gate.check.bind(fixtureValue.gate),
    async run(input, effect) {
      const authorization = await fixtureValue.gate.check({ ...input, consumptionMode: 'none' });
      const first = await effect(authorization);
      try {
        await effect(authorization);
      } catch (error) {
        secondCallbackError = error;
      }
      return { ok: true, result: first };
    },
  };
  const connector = await createStripeRefundDurableConnector({
    stripe: fixtureValue.stripe, gate: duplicateGate, store: fixtureValue.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: () => job,
  });
  const result = await guardStripeRefundDurable(connector, {
    operation_reference: 'refund-job-01',
    receipt: fixtureValue.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.state, 'COMMITTED');
  assert.equal(secondCallbackError?.message, 'stripe_refund_provider_callback_already_claimed');
  assert.equal(fixtureValue.stripe.calls.length, 1);
});

test('a callback resumed after Gate refusal cannot enter Stripe after RELEASED', async () => {
  const fixtureValue = await fixture();
  let resumeCallback;
  const held = new Promise((resolve) => { resumeCallback = resolve; });
  let pendingCallback;
  const lateGate = {
    check: fixtureValue.gate.check.bind(fixtureValue.gate),
    async run(input, effect) {
      const authorization = await fixtureValue.gate.check({ ...input, consumptionMode: 'none' });
      pendingCallback = held.then(() => effect(authorization)).catch((error) => error);
      return { ok: false, authorization: { reason: 'gate_refused' } };
    },
  };
  const connector = await createStripeRefundDurableConnector({
    stripe: fixtureValue.stripe, gate: lateGate, store: fixtureValue.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: () => job,
  });
  const result = await guardStripeRefundDurable(connector, {
    operation_reference: 'refund-job-01',
    receipt: fixtureValue.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.state, 'RELEASED');
  resumeCallback();
  assert.equal((await pendingCallback)?.message, 'stripe_refund_provider_callback_closed');
  assert.equal(fixtureValue.stripe.calls.length, 0);
  assert.equal(fixtureValue.store.row.state, 'RELEASED');
});

test('an in-flight account probe cannot enter Stripe after Gate returns refusal', async () => {
  const stripe = provider();
  let resumeProbe;
  const held = new Promise((resolve) => { resumeProbe = resolve; });
  const retrieve = stripe.accounts.retrieve;
  let probes = 0;
  stripe.accounts.retrieve = async () => {
    probes += 1;
    if (probes === 4) await held;
    return retrieve();
  };
  const fixtureValue = await fixture({ stripe });
  let pendingCallback;
  const earlyGate = {
    check: fixtureValue.gate.check.bind(fixtureValue.gate),
    async run(input, effect) {
      const authorization = await fixtureValue.gate.check({ ...input, consumptionMode: 'none' });
      pendingCallback = effect(authorization).catch((error) => error);
      return { ok: false, authorization: { reason: 'gate_refused' } };
    },
  };
  const connector = await createStripeRefundDurableConnector({
    stripe, gate: earlyGate, store: fixtureValue.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: () => job,
  });
  const result = await guardStripeRefundDurable(connector, {
    operation_reference: 'refund-job-01',
    receipt: fixtureValue.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.state, 'RELEASED');
  resumeProbe();
  assert.equal((await pendingCallback)?.message, 'stripe_refund_provider_callback_closed');
  assert.equal(stripe.calls.length, 0);
});

test('metadata HMAC rotation prevents unverifiable recovery instead of guessing success', async () => {
  const store = new AttemptStore();
  const stripe = provider({ loseFirstResponse: true });
  const first = await fixture({ store, stripe });
  assert.equal((await guardStripeRefundDurable(first.connector, {
    operation_reference: 'refund-job-01', receipt: first.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'INDETERMINATE');
  const changedKey = await fixture({ store, stripe, metadataKey: new Uint8Array(32).fill(19) });
  store.stale = true;
  const result = await reconcileStripeRefundDurable(changedKey.connector, 'refund-job-01');
  assert.equal(result.state, 'INDETERMINATE');
  // The genuine refund still carries this operation's ID and digests, so a tag
  // under the rotated key is a conflict, never positive evidence.
  assert.equal(result.reason, 'provider_effect_conflicting');
  assert.equal(stripe.calls.length, 1);
});

test('provider idempotency keys include tenant namespace, not just operation ID', async () => {
  const one = await fixture();
  const two = await fixture({ tenantId: 'tenant:other' });
  assert.equal((await guardStripeRefundDurable(one.connector, {
    operation_reference: 'refund-job-01', receipt: one.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  assert.equal((await guardStripeRefundDurable(two.connector, {
    operation_reference: 'refund-job-01', receipt: two.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  assert.notEqual(one.stripe.calls[0].options.idempotencyKey, two.stripe.calls[0].options.idempotencyKey);
});

test('concurrent fresh approvals for one operation make only one provider entry', async () => {
  const { connector, harness, stripe } = await fixture();
  const results = await Promise.all([
    guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    }),
    guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    }),
  ]);
  assert.equal(results.filter((result) => result.ok === true && result.state === 'COMMITTED').length, 1);
  // The loser reads the winner's attempt: still in flight, or already committed.
  assert.equal(results.filter((result) => result.ok === false
    && ['operation_already_reserved', 'operation_already_committed'].includes(result.reason)).length, 1);
  assert.equal(stripe.calls.length, 1);
});

test('stale RESERVED never invokes provider; stale INVOKING recovers as uncertain, not retryable', async () => {
  const reservedStore = new AttemptStore();
  const originalReservedTransition = reservedStore.transition.bind(reservedStore);
  reservedStore.transition = async (input) => input.expected_state === 'RESERVED'
    ? false : originalReservedTransition(input);
  const reserved = await fixture({ store: reservedStore });
  assert.equal((await guardStripeRefundDurable(reserved.connector, {
    operation_reference: 'refund-job-01', receipt: reserved.harness.mint({ outcome: 'allow_with_signoff' }),
  })).reason, 'attempt_transition_failed');
  assert.equal(reservedStore.row.state, 'RESERVED');
  reservedStore.stale = true;
  assert.equal((await reconcileStripeRefundDurable(reserved.connector, 'refund-job-01')).reason, 'attempt_not_invoked');
  assert.equal(reserved.stripe.calls.length, 0);

  const invokingStore = new AttemptStore();
  const originalInvokingTransition = invokingStore.transition.bind(invokingStore);
  invokingStore.transition = async (input) => input.expected_state === 'INVOKING'
    ? false : originalInvokingTransition(input);
  const invoking = await fixture({ store: invokingStore });
  assert.equal((await guardStripeRefundDurable(invoking.connector, {
    operation_reference: 'refund-job-01', receipt: invoking.harness.mint({ outcome: 'allow_with_signoff' }),
  })).reason, 'attempt_freeze_failed');
  assert.equal(invokingStore.row.state, 'INVOKING');
  invokingStore.stale = true;
  const recovered = await reconcileStripeRefundDurable(invoking.connector, 'refund-job-01');
  assert.equal(recovered.state, 'COMMITTED');
  assert.equal(invoking.stripe.calls.length, 1);
  assert.equal(invokingStore.row.state, 'COMMITTED');
});

test('production store factory feeds account-pinned deterministic digests into existing PTE PostgreSQL RPC', async () => {
  const queries = [];
  const fakePool = () => ({
    async connect() {
      return {
        async query(sql, params = []) {
          queries.push({ sql, params });
          if (sql.includes('reserve_attempt(')) return {
            rowCount: 1, rows: [{ applied: true, reason: null }],
          };
          return { rowCount: null, rows: [] };
        },
        release() {},
      };
    },
  });
  const store = createStripeRefundDurableStore({
    pool: fakePool(), recovery_pool: fakePool(),
    owner_hmac_sha256_key: new Uint8Array(32).fill(27),
    tenant_id: 'tenant:finance', provider_account_id: accountId,
    environment: 'test', authorize_recovery: () => false,
  });
  const binding = {
    tenant_id: 'tenant:finance', provider_id: 'stripe',
    provider_account_id: accountId, environment: 'test',
    attempt_id: `stripe-refund:${'a'.repeat(64)}`,
    request_digest: `sha256:${'b'.repeat(64)}`,
  };
  assert.equal((await store.reserve(binding)).reserved, true);
  const reserve = queries.find(({ sql }) => sql.includes('reserve_attempt('));
  const digests = stripeRefundAttemptDigests(binding);
  assert.deepEqual(reserve.params.slice(0, 9), [
    binding.tenant_id, 'stripe', accountId, 'test', binding.attempt_id,
    digests.operation_digest, binding.request_digest,
    digests.action_digest, digests.config_digest,
  ]);
  await assert.rejects(store.reserve({ ...binding, provider_account_id: 'acct_other' }), /namespace mismatch/);
  assert.equal(queries.filter(({ sql }) => sql.includes('reserve_attempt(')).length, 1);
});

test('missing, incomplete, unavailable, mismatched, and duplicate provider results never prove non-effect', async () => {
  for (const mode of ['empty', 'incomplete', 'unavailable', 'mismatch', 'duplicate']) {
    const store = new AttemptStore();
    const stripe = provider({ loseFirstResponse: true });
    const { connector, harness } = await fixture({ store, stripe });
    assert.equal((await guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    })).state, 'INDETERMINATE');
    if (mode === 'empty') stripe.records.length = 0;
    if (mode === 'incomplete') stripe.setMore(true);
    if (mode === 'unavailable') stripe.setListFailure(true);
    if (mode === 'mismatch') stripe.records[0].metadata = { ...stripe.records[0].metadata, emilia_origin_tag: 'forged' };
    if (mode === 'duplicate') stripe.records.push({ ...stripe.records[0], id: 're_2' });
    store.stale = true;
    const result = await reconcileStripeRefundDurable(connector, 'refund-job-01');
    assert.equal(result.state, 'INDETERMINATE', mode);
    assert.notEqual(result.reason, 'NOT_COMMITTED', mode);
    assert.equal(store.row.state, 'INDETERMINATE', mode);
    assert.equal(stripe.calls.length, 1, mode);
  }
});

test('one approval cannot be spent under a second environment or tenant namespace', async () => {
  const stripe = provider();
  const home = await fixture({ stripe });
  const receipt = home.harness.mint({ outcome: 'allow_with_signoff' });
  for (const other of [
    await fixture({ stripe, harness: home.harness, environment: 'test-2' }),
    await fixture({ stripe, harness: home.harness, tenantId: 'tenant:other' }),
  ]) {
    const result = await guardStripeRefundDurable(other.connector, {
      operation_reference: 'refund-job-01', receipt,
    });
    assert.equal(result.state, 'REFUSED');
    assert.equal(other.store.row, null);
  }
  assert.equal(stripe.calls.length, 0);
  assert.equal((await guardStripeRefundDurable(home.connector, {
    operation_reference: 'refund-job-01', receipt,
  })).state, 'COMMITTED');
  assert.equal(stripe.calls.length, 1);
});

test('a listed refund carrying this operation metadata but mismatched fields keeps recovery indeterminate', async () => {
  const conflicts = {
    amount: (refund) => ({ ...refund, id: 're_conflict', amount: refund.amount - 1 }),
    request_digest: (refund) => ({ ...refund, id: 're_conflict',
      metadata: { ...refund.metadata, emilia_request_digest: `sha256:${'0'.repeat(64)}` } }),
    origin_tag: (refund) => ({ ...refund, id: 're_conflict',
      metadata: { ...refund.metadata, emilia_origin_tag: 'f'.repeat(64) } }),
  };
  for (const [name, conflict] of Object.entries(conflicts)) {
    const store = new AttemptStore();
    const stripe = provider({ loseFirstResponse: true });
    const { connector, harness } = await fixture({ store, stripe });
    assert.equal((await guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    })).state, 'INDETERMINATE', name);
    stripe.records.push(conflict(stripe.records[0]));
    store.stale = true;
    assert.deepEqual(await reconcileStripeRefundDurable(connector, 'refund-job-01'),
      { ok: false, state: 'INDETERMINATE', reason: 'provider_effect_conflicting' }, name);
    assert.equal(store.row.state, 'INDETERMINATE', name);
    assert.equal(stripe.calls.length, 1, name);
  }
});

test('pre-reservation failures return refusals with reasons and record nothing', async () => {
  const cases = [
    ['stripe_account_probe_failed', (f) => { f.stripe.accounts.retrieve = async () => { throw new Error('down'); }; }],
    ['refund_operation_unavailable', null, () => { throw new Error('job store down'); }],
    ['refund_operation_invalid', null, () => ({ ...job, amount: -1 })],
    ['refund_operation_invalid', null, () => ({ ...job, payment_intent: 'ch_not_a_pi' })],
  ];
  for (const [reason, mutate, resolver] of cases) {
    const value = await fixture();
    const connector = resolver
      ? await createStripeRefundDurableConnector({
        stripe: value.stripe, gate: value.gate, store: value.store,
        tenant_id: 'tenant:finance', environment: 'test',
        metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: resolver,
      })
      : value.connector;
    if (mutate) mutate(value);
    assert.deepEqual(await guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: value.harness.mint({ outcome: 'allow_with_signoff' }),
    }), { ok: false, state: 'REFUSED', reason }, reason);
    assert.deepEqual(await reconcileStripeRefundDurable(connector, 'refund-job-01'),
      { ok: false, state: 'INDETERMINATE', reason }, reason);
    assert.equal(value.store.row, null, reason);
    assert.equal(value.stripe.calls.length, 0, reason);
  }
  const value = await fixture();
  assert.deepEqual(await guardStripeRefundDurable(value.connector, { operation_reference: 'x', receipt: null }),
    { ok: false, state: 'REFUSED', reason: 'refund_operation_reference_invalid' });
  assert.deepEqual(await guardStripeRefundDurable({}, { operation_reference: 'refund-job-01', receipt: null }),
    { ok: false, state: 'REFUSED', reason: 'stripe_refund_connector_unconfigured' });
  assert.equal(value.stripe.calls.length, 0);
});

test('a committed refund for a distinct operation on the same payment intent is not a conflict', async () => {
  const store = new AttemptStore();
  const stripe = provider({ loseFirstResponse: true });
  const first = await fixture({ store, stripe });
  assert.equal((await guardStripeRefundDurable(first.connector, {
    operation_reference: 'refund-job-01', receipt: first.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'INDETERMINATE');
  const second = await fixture({ store, stripe: provider(), p: { ...job, operation_id: 'refund:order-123:02' } });
  const secondRefund = await guardStripeRefundDurable(second.connector, {
    operation_reference: 'refund-job-01', receipt: second.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(secondRefund.state, 'COMMITTED');
  // Same payment intent and amount, different operation: listed beside ours.
  stripe.records.push({ ...secondRefund.refund, id: 're_other_operation' });
  store.stale = true;
  assert.deepEqual(await reconcileStripeRefundDurable(first.connector, 'refund-job-01'),
    { ok: true, state: 'COMMITTED', refund_id: 're_1' });
  assert.equal(stripe.calls.length, 1);
});

/** A job whose field reads return `first` for `reads` reads, then `later`. */
function shiftingJob(field, later, { reads = 2, first = job[field] } = {}) {
  const counts = { payment_intent: 0, amount: 0, operation_id: 0 };
  const value = {};
  for (const key of Object.keys(counts)) {
    Object.defineProperty(value, key, {
      enumerable: true,
      get() {
        counts[key] += 1;
        if (key !== field) return job[key];
        if (typeof later === 'function' && counts[key] > reads) return later();
        return counts[key] <= reads ? first : later;
      },
    });
  }
  return { value, counts };
}

test('the refund job is read once into a frozen snapshot; values that change between reads never reach Stripe', async () => {
  const evil = [
    ['amount', -4200, 2],
    ['amount', '4200', 2],
    ['payment_intent', 'ch_3NotAPaymentIntent', 1],
    ['operation_id', `refund:${'x'.repeat(600)}`, 2],
  ];
  for (const [field, later, reads] of evil) {
    // The approval covers the value a later read returns, so only a missing
    // validation of that value could let it through.
    const approved = { ...job, [field]: later };
    const shifting = shiftingJob(field, later, { reads });
    const value = await fixture({ harness: createEg1Harness({ action: action(approved) }) });
    const connector = await createStripeRefundDurableConnector({
      stripe: value.stripe, gate: value.gate, store: value.store,
      tenant_id: 'tenant:finance', environment: 'test',
      metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: () => shifting.value,
    });
    const result = await guardStripeRefundDurable(connector, {
      operation_reference: 'refund-job-01', receipt: value.harness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(result.state, 'REFUSED', `${field}=${String(later).slice(0, 20)}`);
    assert.equal(value.stripe.calls.length, 0, `${field}=${String(later).slice(0, 20)}`);
    assert.equal(value.store.row, null, `${field}=${String(later).slice(0, 20)}`);
    assert.deepEqual(shifting.counts, { payment_intent: 1, amount: 1, operation_id: 1 });
  }

  // Approval for the first-read values: exactly those values are sent, and a
  // later non-safe-integer read cannot turn the call into a throw.
  const shifting = shiftingJob('amount', 42.5);
  const value = await fixture();
  const connector = await createStripeRefundDurableConnector({
    stripe: value.stripe, gate: value.gate, store: value.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: () => shifting.value,
  });
  const committed = await guardStripeRefundDurable(connector, {
    operation_reference: 'refund-job-01', receipt: value.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(committed.state, 'COMMITTED');
  assert.equal(value.stripe.calls.length, 1);
  assert.deepEqual(
    { ...value.stripe.calls[0].params, metadata: value.stripe.calls[0].params.metadata.emilia_operation_id },
    { payment_intent: job.payment_intent, amount: job.amount, metadata: job.operation_id },
  );
  assert.deepEqual(shifting.counts, { payment_intent: 1, amount: 1, operation_id: 1 });

  const refusals = {
    throwingGetter: () => shiftingJob('amount', () => { throw new Error('getter'); }, { reads: 0 }).value,
    // `then` answers undefined so the await succeeds and the field read throws.
    throwingProxy: () => new Proxy({}, { get(_t, key) { if (key === 'then') return undefined; throw new Error('trap'); } }),
    fractional: () => ({ ...job, amount: 42.5 }),
    stringifiedIntent: () => ({ ...job, payment_intent: { toString: () => job.payment_intent } }),
  };
  for (const [name, resolver] of Object.entries(refusals)) {
    const refused = await fixture();
    const refusedConnector = await createStripeRefundDurableConnector({
      stripe: refused.stripe, gate: refused.gate, store: refused.store,
      tenant_id: 'tenant:finance', environment: 'test',
      metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: resolver,
    });
    assert.deepEqual(await guardStripeRefundDurable(refusedConnector, {
      operation_reference: 'refund-job-01', receipt: refused.harness.mint({ outcome: 'allow_with_signoff' }),
    }), { ok: false, state: 'REFUSED', reason: 'refund_operation_invalid' }, name);
    assert.equal(refused.stripe.calls.length, 0, name);
    assert.equal(refused.store.row, null, name);
  }
});

test('an approval minted for the durable profile cannot execute on the legacy refund adapter, and the reverse', async () => {
  const legacyCalls = [];
  const legacyStripe = { refunds: { async create(params, options) {
    legacyCalls.push({ params, options });
    return { id: `re_legacy_${legacyCalls.length}`, ...params };
  } } };
  const legacyParams = { payment_intent: job.payment_intent, amount: job.amount, operation_id: job.operation_id };
  const gateFor = (harness, manifest) => createGate({
    manifest, trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy, rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true,
  });

  // Durable approval on the legacy path: neither a legacy Gate nor a durable
  // Gate lets guardStripeMutation() spend it. It still executes once durably.
  const durable = await fixture();
  const receipt = durable.harness.mint({ outcome: 'allow_with_signoff' });
  for (const manifest of [createStripeManifest(), createStripeDurableRefundManifest()]) {
    await assert.rejects(guardStripeMutation(gateFor(durable.harness, manifest), legacyStripe, {
      op: 'refund.create', params: legacyParams, receipt,
    }), (error) => error.code === 'EMILIA_RECEIPT_REQUIRED');
  }
  assert.equal(legacyCalls.length, 0);
  assert.equal((await guardStripeRefundDurable(durable.connector, {
    operation_reference: 'refund-job-01', receipt,
  })).state, 'COMMITTED');
  assert.equal(durable.stripe.calls.length, 1);
  // The binding is the profile's own action type.
  assert.notEqual(DURABLE_ACTION_TYPE, 'stripe.refund.create');
  const { STRIPE_REFUND_DURABLE_ACTION_TYPE } = await import('./stripe-refund-durable.js');
  assert.equal(STRIPE_REFUND_DURABLE_ACTION_TYPE, DURABLE_ACTION_TYPE);

  // Legacy approval on the durable path, with and without the durable fields.
  for (const legacyAction of [
    { action_type: 'stripe.refund.create', ...legacyParams },
    { ...action(), action_type: 'stripe.refund.create' },
  ]) {
    const legacyHarness = createEg1Harness({ action: legacyAction });
    const value = await fixture({ harness: legacyHarness });
    const result = await guardStripeRefundDurable(value.connector, {
      operation_reference: 'refund-job-01', receipt: legacyHarness.mint({ outcome: 'allow_with_signoff' }),
    });
    assert.equal(result.state, 'REFUSED');
    assert.equal(value.stripe.calls.length, 0);
    assert.equal(value.store.row, null);
    // That legacy approval still works on the unchanged legacy path.
    await guardStripeMutation(gateFor(legacyHarness, createStripeManifest()), legacyStripe, {
      op: 'refund.create', params: legacyParams, receipt: legacyHarness.mint({ outcome: 'allow_with_signoff' }),
    });
  }
  assert.equal(legacyCalls.length, 2);
  assert.deepEqual(Object.keys(legacyCalls[0].params).sort(), ['amount', 'payment_intent']);
});

test('a lost attempt row cannot become a second refund: the first create looks for this operation at Stripe', async () => {
  // Restore from a backup that predates the attempt, after Stripe's
  // idempotency cache expired: the matching refund commits, no second create.
  const stripe = provider();
  const original = await fixture({ stripe });
  assert.equal((await guardStripeRefundDurable(original.connector, {
    operation_reference: 'refund-job-01', receipt: original.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  stripe.expireIdempotencyCache();
  const restored = await fixture({ stripe, store: new AttemptStore() });
  const afterRestore = await guardStripeRefundDurable(restored.connector, {
    operation_reference: 'refund-job-01', receipt: restored.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(stripe.calls.length, 1);
  assert.equal(stripe.records.length, 1);
  assert.equal(afterRestore.ok, true);
  assert.equal(afterRestore.state, 'COMMITTED');
  assert.equal(afterRestore.reason, 'provider_effect_already_present');
  assert.equal(afterRestore.refund.id, 're_1');
  assert.equal(restored.store.row.state, 'COMMITTED');
  assert.equal(restored.store.row.evidence.evidence_id, 're_1');

  // A second tenant on the same account, with its own separately minted
  // approval: the existing refund carries this operation ID, so it conflicts.
  const other = await fixture({ stripe, tenantId: 'tenant:other' });
  assert.deepEqual(await guardStripeRefundDurable(other.connector, {
    operation_reference: 'refund-job-01', receipt: other.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'INDETERMINATE', reason: 'provider_effect_conflicting' });
  assert.equal(stripe.calls.length, 1);
  assert.equal(other.store.row.state, 'INDETERMINATE');

  // Ambiguous, incomplete, or unavailable views never create and never release.
  const holds = {
    provider_effect_ambiguous: (s) => { s.records.push({ ...s.records[0], id: 're_2' }); },
    provider_lookup_incomplete: (s) => { s.setMore(true); },
    provider_lookup_unavailable: (s) => { s.setListFailure(true); },
  };
  for (const [reason, arrange] of Object.entries(holds)) {
    const held = provider();
    const first = await fixture({ stripe: held });
    assert.equal((await guardStripeRefundDurable(first.connector, {
      operation_reference: 'refund-job-01', receipt: first.harness.mint({ outcome: 'allow_with_signoff' }),
    })).state, 'COMMITTED', reason);
    held.expireIdempotencyCache();
    arrange(held);
    const lost = await fixture({ stripe: held, store: new AttemptStore() });
    assert.deepEqual(await guardStripeRefundDurable(lost.connector, {
      operation_reference: 'refund-job-01', receipt: lost.harness.mint({ outcome: 'allow_with_signoff' }),
    }), { ok: false, state: 'INDETERMINATE', reason }, reason);
    assert.equal(held.calls.length, 1, reason);
    assert.equal(lost.store.row.state, 'INDETERMINATE', reason);
  }

  // Negative control: a refund for a distinct operation on the same payment
  // intent does not block this operation's first create.
  const shared = provider();
  const distinct = await fixture({ stripe: shared, p: { ...job, operation_id: 'refund:order-123:02' } });
  assert.equal((await guardStripeRefundDurable(distinct.connector, {
    operation_reference: 'refund-job-01', receipt: distinct.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  const mine = await fixture({ stripe: shared });
  const mineResult = await guardStripeRefundDurable(mine.connector, {
    operation_reference: 'refund-job-01', receipt: mine.harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(mineResult.state, 'COMMITTED');
  assert.equal(mineResult.reason, undefined);
  assert.equal(shared.calls.length, 2);
});

test('an operation that already has an attempt reports what that attempt is', async () => {
  // A Gate refusal before Stripe releases the attempt: later approvals are
  // told the operation is closed, not that its outcome is uncertain.
  const released = await fixture();
  const refusingGate = {
    check: released.gate.check.bind(released.gate),
    async run() { return { ok: false, authorization: { reason: 'receipt_expired' } }; },
  };
  const refusingConnector = await createStripeRefundDurableConnector({
    stripe: released.stripe, gate: refusingGate, store: released.store,
    tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17), resolve_operation: () => job,
  });
  assert.deepEqual(await guardStripeRefundDurable(refusingConnector, {
    operation_reference: 'refund-job-01', receipt: released.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'RELEASED', reason: 'receipt_expired' });
  assert.deepEqual(await guardStripeRefundDurable(released.connector, {
    operation_reference: 'refund-job-01', receipt: released.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'REFUSED', reason: 'operation_closed_released' });
  assert.equal(released.stripe.calls.length, 0);

  const committed = await fixture();
  assert.equal((await guardStripeRefundDurable(committed.connector, {
    operation_reference: 'refund-job-01', receipt: committed.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'COMMITTED');
  assert.deepEqual(await guardStripeRefundDurable(committed.connector, {
    operation_reference: 'refund-job-01', receipt: committed.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'COMMITTED', reason: 'operation_already_committed' });
  assert.equal(committed.stripe.calls.length, 1);

  const uncertain = await fixture({ stripe: provider({ loseFirstResponse: true }) });
  assert.equal((await guardStripeRefundDurable(uncertain.connector, {
    operation_reference: 'refund-job-01', receipt: uncertain.harness.mint({ outcome: 'allow_with_signoff' }),
  })).state, 'INDETERMINATE');
  assert.deepEqual(await guardStripeRefundDurable(uncertain.connector, {
    operation_reference: 'refund-job-01', receipt: uncertain.harness.mint({ outcome: 'allow_with_signoff' }),
  }), { ok: false, state: 'INDETERMINATE', reason: 'operation_already_reserved' });
  assert.equal(uncertain.stripe.calls.length, 1);
});

test('a receipt whose shape makes the Gate check throw is refused before anything is recorded', async () => {
  const value = await fixture();
  const hostile = { get payload() { throw new Error('boom'); } };
  assert.deepEqual(await guardStripeRefundDurable(value.connector, {
    operation_reference: 'refund-job-01', receipt: hostile,
  }), { ok: false, state: 'REFUSED', reason: 'gate_check_failed' });
  assert.equal(value.store.row, null);
  assert.equal(value.stripe.calls.length, 0);
});
