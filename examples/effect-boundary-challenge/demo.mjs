// SPDX-License-Identifier: Apache-2.0
/** A small executable trace. Mock provider and attempt store; no live money. */
import assert from 'node:assert/strict';
import { createEg1Harness, createGate } from '../../packages/gate/index.js';
import {
  createStripeDurableRefundManifest,
  createStripeRefundDurableConnector,
  guardStripeRefundDurable,
  reconcileStripeRefundDurable,
} from '../../packages/gate/adapters/stripe-refund-durable.js';

const job = Object.freeze(/** @type {{ payment_intent: string, amount: number, operation_id: string }} */ ({
  payment_intent: 'pi_refund_test', amount: 5000,
  operation_id: 'refund:order-123:01',
}));
const actionType = createStripeDurableRefundManifest().actions
  .find((entry) => entry.match?.tool === 'create_refund').action_type;

class AttemptStore {
  durable = true;
  ownershipFenced = true;
  compareAndSwap = true;
  atomicEvidenceBinding = true;
  rows = new Map();
  serial = 0;
  stale = false;

  async reserve(binding) {
    if (this.rows.has(binding.attempt_id)) return { reserved: false, reason: 'attempt_exists' };
    const owner = `owner:${++this.serial}`;
    this.rows.set(binding.attempt_id, { binding, owner, state: 'RESERVED', evidence: null });
    return { reserved: true, owner };
  }

  async transition({ tenant_id, attempt_id, owner, expected_state, next_state }) {
    const row = this.rows.get(attempt_id);
    if (!row || row.binding.tenant_id !== tenant_id || row.owner !== owner
        || row.state !== expected_state) return false;
    row.state = next_state;
    return true;
  }

  async heartbeat({ tenant_id, attempt_id, owner }) {
    const row = this.rows.get(attempt_id);
    return Boolean(row) && row.binding.tenant_id === tenant_id && row.owner === owner
      && ['RESERVED', 'INVOKING', 'INDETERMINATE'].includes(row.state);
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

  async read(binding) {
    const row = this.rows.get(binding.attempt_id);
    if (!row || row.binding.request_digest !== binding.request_digest) return null;
    const { stripeRefundAttemptDigests } = await import('../../packages/gate/adapters/stripe-refund-durable.js');
    return {
      ...row.binding, ...stripeRefundAttemptDigests(row.binding),
      state: row.state, evidence_digest: row.evidence?.evidence_digest ?? null,
      lease_stale: this.stale,
    };
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

  get state() { return [...this.rows.values()][0]?.state ?? null; }
}

function mockProvider() {
  const refunds = [];
  let loseResponse = true;
  let lookupUnavailable = false;
  let entries = 0;
  return {
    refunds,
    get entries() { return entries; },
    setLookupUnavailable(value) { lookupUnavailable = value; },
    accounts: { async retrieve() { return { id: 'acct_authorized' }; } },
    refundsApi: {
      async create(params) {
        entries += 1;
        const refund = {
          id: `re_${entries}`, payment_intent: params.payment_intent,
          amount: params.amount, metadata: params.metadata,
          created: Math.floor(Date.now() / 1000), status: 'pending',
        };
        refunds.push(refund);
        if (loseResponse) { loseResponse = false; throw new Error('response lost after acceptance'); }
        return refund;
      },
      async list({ payment_intent }) {
        if (lookupUnavailable) throw new Error('provider status unavailable');
        return { data: refunds.filter((item) => item.payment_intent === payment_intent), has_more: false };
      },
    },
  };
}

async function client(store, provider, operation = job, idPrefix = 'first') {
  const harness = createEg1Harness({ action: {
    action_type: actionType, tenant_id: 'tenant:finance', environment: 'test',
    provider_account_id: 'acct_authorized', ...operation,
  }, idPrefix });
  const gate = createGate({
    manifest: createStripeDurableRefundManifest(),
    trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy, rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins, allowEphemeralStore: true,
  });
  const connector = await createStripeRefundDurableConnector({
    stripe: { accounts: provider.accounts, refunds: provider.refundsApi },
    gate, store, tenant_id: 'tenant:finance', environment: 'test',
    metadata_hmac_sha256_key: new Uint8Array(32).fill(17),
    resolve_operation: (reference) => {
      assert.equal(reference, 'refund-job-01');
      return operation;
    },
  });
  return { connector, receipt: harness.mint({ outcome: 'allow_with_signoff' }) };
}

const store = new AttemptStore();
const provider = mockProvider();
const trace = [];
const first = await client(store, provider);
const initial = await guardStripeRefundDurable(first.connector, {
  operation_reference: 'refund-job-01', receipt: first.receipt,
});
assert.equal(initial.state, 'INDETERMINATE');
assert.equal(provider.entries, 1);
assert.equal(provider.refunds.length, 1);
trace.push({ step: 1, state: initial.state, provider_entries: provider.entries });

// New Gate, new valid approval, same durable store and provider. The mock
// provider has no idempotency cache: a second entry would create a duplicate.
const restarted = await client(store, provider, job, 'restarted');
assert.notEqual(first.receipt.payload.receipt_id, restarted.receipt.payload.receipt_id);
const fresh = await guardStripeRefundDurable(restarted.connector, {
  operation_reference: 'refund-job-01', receipt: restarted.receipt,
});
assert.equal(fresh.reason, 'operation_already_reserved');
assert.equal(provider.entries, 1);
trace.push({ step: 2, state: fresh.state, reason: fresh.reason, provider_entries: provider.entries });

provider.setLookupUnavailable(true);
store.stale = true;
const unavailable = await reconcileStripeRefundDurable(restarted.connector, 'refund-job-01');
assert.equal(unavailable.state, 'INDETERMINATE');
assert.equal(store.state, 'INDETERMINATE');
assert.equal(provider.entries, 1);
trace.push({ step: 3, state: unavailable.state, reason: unavailable.reason, provider_entries: provider.entries });

provider.setLookupUnavailable(false);
store.stale = true;
const reconciled = await reconcileStripeRefundDurable(restarted.connector, 'refund-job-01');
assert.equal(reconciled.state, 'COMMITTED');
assert.equal(store.state, 'COMMITTED');
assert.equal(provider.entries, 1);
trace.push({ step: 4, state: reconciled.state, refund_id: reconciled.refund_id, provider_entries: provider.entries });

const changed = await client(store, provider, { ...job, amount: 4000 }, 'changed');
const mutation = await guardStripeRefundDurable(changed.connector, {
  operation_reference: 'refund-job-01', receipt: changed.receipt,
});
assert.equal(mutation.ok, false);
// The operation's existing attempt blocks the changed request. Its request
// digest does not match that attempt, so the connector reports its generic
// hold rather than a distinct amount-mismatch refusal. The original attempt
// stays COMMITTED and no second attempt is recorded.
assert.equal(mutation.state, 'INDETERMINATE');
assert.equal(mutation.reason, 'operation_already_reserved');
assert.equal(store.state, 'COMMITTED');
assert.equal(store.rows.size, 1);
assert.equal(provider.entries, 1);
trace.push({ step: 5, state: mutation.state, reason: mutation.reason, provider_entries: provider.entries });

console.log(JSON.stringify({
  profile: 'EMILIA-EFFECT-BOUNDARY-CHALLENGE-v1',
  scope: 'real Gate and durable connector; mock provider and attempt store; no money moved',
  trace,
}, null, 2));
