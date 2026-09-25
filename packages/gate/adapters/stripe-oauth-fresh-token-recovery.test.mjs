// SPDX-License-Identifier: Apache-2.0
/**
 * Combined seam regression, not end-to-end OAuth or live Stripe conformance.
 * The OAuth replay-unit derivation and in-memory fence are real; the EG1
 * harness represents two independently valid Gate approvals, not JWTs issued
 * by an Authorization Server. The mock Stripe client implements idempotent
 * create and loses the first response after accepting the $50 partial refund.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createEg1Harness, createGate } from '../index.js';
import { createStripeManifest, guardStripeMutation } from './stripe.js';
import { deriveOAuthTransactionTokenReplayUnit } from '../../verify/aeb-wimse-oauth-adapter.js';
import { InMemoryAebConsumptionStore } from '../../verify/aeb-adapter-contract.js';

const action = {
  action_type: 'stripe.refund.create',
  payment_intent: 'pi_synthetic_100_dollars',
  amount: 5000,
  operation_id: 'refund:order-123:partial-01',
};

test('fresh txn and approval cannot turn one lost-response refund into a second effect', async () => {
  const trustDomain = 'payments.example';
  const workload = 'wimse://payments.example/workloads/payment-executor';
  const firstTxn = deriveOAuthTransactionTokenReplayUnit(trustDomain, workload, 'txn-refund-first');
  const freshTxn = deriveOAuthTransactionTokenReplayUnit(trustDomain, workload, 'txn-refund-second');
  assert.notEqual(firstTxn, freshTxn);
  const txnFence = new InMemoryAebConsumptionStore();
  assert.equal(txnFence.reserve('attempt:first', [firstTxn]), true);
  assert.equal(txnFence.commit('attempt:first'), true);
  assert.equal(txnFence.reserve('attempt:same-txn', [firstTxn]), false);
  assert.equal(txnFence.reserve('attempt:fresh-txn', [freshTxn]), true);

  const harness = createEg1Harness({ action });
  const gate = createGate({
    manifest: createStripeManifest(),
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    quorumPolicy: harness.quorumPolicy,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true, // fixture only; production needs durable state
  });
  const requests = [];
  const effects = new Map();
  const stripe = {
    refunds: {
      async create(params, options) {
        requests.push({ params, options });
        const key = options?.idempotencyKey;
        assert.match(key, /^emilia:stripe:refund:v1:[0-9a-f]{64}$/);
        if (effects.has(key)) return effects.get(key);
        const result = { id: 're_synthetic_one_effect', ...params };
        effects.set(key, result);
        throw new Error('provider accepted refund but the response was lost');
      },
    },
  };
  const firstReceipt = harness.mint({ outcome: 'allow_with_signoff' });
  const freshReceipt = harness.mint({ outcome: 'allow_with_signoff' });
  assert.notEqual(firstReceipt.payload.receipt_id, freshReceipt.payload.receipt_id);

  await assert.rejects(
    guardStripeMutation(gate, stripe, { op: 'refund.create', params: action, receipt: firstReceipt }),
    (error) => error.emiliaGateOutcome?.outcome === 'indeterminate',
  );
  await assert.rejects(
    guardStripeMutation(gate, stripe, { op: 'refund.create', params: action, receipt: firstReceipt }),
    (error) => error.gate?.reason?.includes('replay'),
  );
  assert.equal(requests.length, 1, 'the first approval cannot be replayed');

  const recovered = await guardStripeMutation(gate, stripe, {
    op: 'refund.create', params: action, receipt: freshReceipt,
  });
  assert.equal(recovered.result.id, 're_synthetic_one_effect');
  assert.equal(requests.length, 2, 'the fresh approval reaches the mock provider');
  assert.equal(requests[0].options.idempotencyKey, requests[1].options.idempotencyKey);
  assert.equal(effects.size, 1, 'the mock provider accepted only one refund effect');
  assert.deepEqual(requests.map(({ params }) => params), [
    { payment_intent: action.payment_intent, amount: action.amount },
    { payment_intent: action.payment_intent, amount: action.amount },
  ]);

  const withoutOperationId = { payment_intent: action.payment_intent, amount: action.amount };
  await assert.rejects(
    guardStripeMutation(gate, stripe, {
      op: 'refund.create', params: withoutOperationId,
      receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    }),
    /operation_id/,
  );
  assert.equal(requests.length, 2, 'missing business-operation ID never reaches the provider');
});
