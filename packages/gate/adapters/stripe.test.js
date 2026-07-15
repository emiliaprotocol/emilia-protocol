// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGate, createEg1Harness } from '../index.js';
import { createStripeManifest, guardStripeMutation, STRIPE_OPS } from './stripe.js';

function fakeStripe() {
  const calls = [];
  return {
    calls,
    payouts: { create: async (p) => { calls.push(['payout', p]); return { id: 'po_1', ...p }; } },
    refunds: { create: async (p) => { calls.push(['refund', p]); return { id: 're_1', ...p }; } },
    accounts: { updateExternalAccount: async (acct, ext, u) => { calls.push(['ext', { acct, ext, u }]); return { id: ext }; } },
  };
}
function setup(action) {
  const harness = createEg1Harness({ action });
  return { harness, gate: createGate({ manifest: createStripeManifest(), trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, quorumPolicy: harness.quorumPolicy, rpId: harness.rpId, allowedOrigins: harness.allowedOrigins }), stripe: fakeStripe() };
}
const PAYOUT = { action_type: 'stripe.payout.create', amount: 40000, currency: 'usd', destination: 'acct_x' };

test('exposes the destructive Stripe ops', () => {
  assert.deepEqual([...STRIPE_OPS].sort(), ['bank_account.change', 'payout.create', 'refund.create']);
});

test('payout WITHOUT a receipt never reaches Stripe', async () => {
  const { gate, stripe } = setup(PAYOUT);
  await assert.rejects(
    () => guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' } }),
    (e) => e.code === 'EMILIA_RECEIPT_REQUIRED' && e.status === 428,
  );
  assert.equal(stripe.calls.length, 0);
});

test('payout WITH a valid Class-A receipt executes and returns reliance', async () => {
  const { gate, harness, stripe } = setup(PAYOUT);
  const { result, reliance } = await guardStripeMutation(gate, stripe, {
    op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' }, receipt: harness.mint({ outcome: 'allow_with_signoff' }),
  });
  assert.equal(result.id, 'po_1');
  assert.equal(String(reliance.verdict).toLowerCase(), 'rely');
});

test('payout refuses an inflated amount (drift)', async () => {
  const { gate, harness, stripe } = setup(PAYOUT);
  const receipt = harness.mint({ outcome: 'allow_with_signoff' }); // authorizes 40000
  await assert.rejects(
    () => guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 999999, currency: 'usd', destination: 'acct_x' }, receipt }),
    (e) => /binding/.test(e.gate.reason),
  );
  assert.equal(stripe.calls.length, 0);
});

test('payout refuses a replayed receipt', async () => {
  const { gate, harness, stripe } = setup(PAYOUT);
  const receipt = harness.mint({ outcome: 'allow_with_signoff' });
  const params = { amount: 40000, currency: 'usd', destination: 'acct_x' };
  await guardStripeMutation(gate, stripe, { op: 'payout.create', params, receipt });
  await assert.rejects(() => guardStripeMutation(gate, stripe, { op: 'payout.create', params, receipt }), (e) => /replay/.test(e.gate.reason));
  assert.equal(stripe.calls.length, 1);
});

test('payout-destination change requires quorum', async () => {
  const action = { action_type: 'stripe.bank_account.change', account: 'acct_x', external_account: 'ba_new' };
  const { gate, harness, stripe } = setup(action);
  const params = { account: 'acct_x', external_account: 'ba_new' };
  await assert.rejects(
    () => guardStripeMutation(gate, stripe, { op: 'bank_account.change', params, receipt: harness.mint({ outcome: 'allow_with_signoff' }) }),
    (e) => /assurance/.test(e.gate.reason),
  );
  const quorum = harness.mint({ outcome: 'allow_with_signoff', quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 } });
  const { result } = await guardStripeMutation(gate, stripe, { op: 'bank_account.change', params, receipt: quorum });
  assert.equal(result.id, 'ba_new');
});
