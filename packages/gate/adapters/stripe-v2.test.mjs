// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createStripeAllowanceConnectorV2, stripeAllowanceConnectorIdentity,
  guardStripeAllowanceMutation } from './stripe.js';
import { issueGateAllowance, allowanceDigest } from '../allowance.js';
import { createMemoryCapabilityStore } from '../capability-receipt.js';
function client(livemode = false) {
  const calls = [];
  return { calls,
    accounts: { retrieve: async (...args) => { calls.push(['account', ...args]); return { id: 'acct_fixed' }; } },
    balance: { retrieve: async (...args) => { calls.push(['balance', ...args]); return { object: 'balance', livemode }; } },
    payouts: { create: async (...args) => { calls.push(['payout', ...args]); return { id: 'po_synthetic' }; } } };
}
function fixture(connectorId) {
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const issued = issueGateAllowance({
    authorizationReceipt: { '@version': 'EP-RECEIPT-v1', payload: { receipt_id: 'receipt:v2',
      claim: { action_type: 'gate.allowance.issue', capability_only: true } } },
    allowance: { allowance_id: 'allowance:stripe-v2', tenant_id: 'tenant:test', subject_id: 'agent:test',
      audience: 'gate:test', connector_id: connectorId, action_type: 'stripe.payout.create', revision: 1,
      supersedes_allowance_digest: null, presentation_digest: `sha256:${'1'.repeat(64)}`,
      issued_at: '2026-07-30T17:59:00.000Z', valid_from: '2026-07-30T18:00:00.000Z',
      expires_at: '2026-07-31T18:00:00.000Z', constraints: { currency: 'USD', aggregate_amount: 50_000,
        max_amount_per_action: 5_000, material_fields: ['action_type', 'amount', 'currency', 'destination', 'operation_id'],
        operation_id_field: 'operation_id', amount_field: 'amount', currency_field: 'currency',
        target_field: 'destination', allowed_targets: ['acct_known'], allowed_values: {} } },
    signer: { issuer_id: 'customer:test', key_id: 'key:test', private_key: keys.privateKey },
    capabilityIssuerPrivateKey: keys.privateKey, capabilityRevocationMode: 'direct',
  });
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(issued.capabilityReceipt), true);
  const status = { ok: true, status_epoch: 1, status_head_digest: `sha256:${'a'.repeat(64)}` };
  assert.equal(store.advanceAllowanceStatus({ allowance_profile_id: 'tenant:test/allowance:stripe-v2',
    allowance_digest: allowanceDigest(issued.allowance), revision: 1,
    status_epoch: 1, status_head_digest: status.status_head_digest,
    expected_status_epoch: null, expected_status_head_digest: null, status: 'active' }).ok, true);
  return { params: { amount: 4_000, currency: 'USD', destination: 'acct_known' }, operationId: 'stripe:v2:1',
    allowance: issued.allowance, capabilityReceipt: issued.capabilityReceipt, secret: issued.secret, store,
    verifyAuthorizationReceipt: () => true, verifyAllowanceStatus: () => status,
    trustedAllowanceKeys: { 'key:test': { issuer_id: 'customer:test', public_key: publicKey } },
    trustedCapabilityIssuerKeys: [publicKey], expected: { allowance_id: 'allowance:stripe-v2',
      tenant_id: 'tenant:test', subject_id: 'agent:test', audience: 'gate:test', authorizer_id: 'customer:test' },
    now: Date.parse('2026-07-30T18:00:00.000Z') };
}

test('v2 probes mode/account under fixed Connect context and never takes scope from action callers', async () => {
  const stripe = client();
  const connector = await createStripeAllowanceConnectorV2({ stripe, stripeAccount: 'acct_fixed' });
  assert.equal(stripeAllowanceConnectorIdentity(connector), 'stripe:acct_fixed:test');
  assert.deepEqual(stripe.calls, [ ['account', null, {}, { stripeAccount: 'acct_fixed' }],
    ['balance', {}, { stripeAccount: 'acct_fixed' }] ]);
  stripe.payouts.create = async () => { throw new Error('replacement method must not run'); };
  const options = fixture('stripe:acct_fixed:test');
  const before = structuredClone(options.store.getState(options.allowance.capability_id));
  for (const extra of [{ provider_env: 'stripe:acct_fixed:live' }, { retry_epoch_digest: allowanceDigest(options.allowance) },
    { attemptGroup: '2' }, { stripeAccount: 'acct_other' }, { providerEnv: 'stripe:acct_other:test' }]) {
    const result = await guardStripeAllowanceMutation({ connector, ...options, ...extra });
    assert.equal(result.ok, false);
    assert.deepEqual(options.store.getState(options.allowance.capability_id), before);
    assert.equal(stripe.calls.filter(([op]) => op === 'payout').length, 0);
  }
  const result = await guardStripeAllowanceMutation({ connector, ...options });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.budget_guarantee.mode, 'local_store_only');
  const payout = stripe.calls.find(([op]) => op === 'payout');
  assert.deepEqual(payout[2].stripeAccount, 'acct_fixed');
  assert.match(payout[2].idempotencyKey, /^ep2_[A-Za-z0-9]{43}$/);
  assert.equal(payout[1].metadata.ep_replay_key, payout[2].idempotencyKey);
  assert.equal(options.store.getState(options.allowance.capability_id).consumed_amount, 4_000);
  const retry = await guardStripeAllowanceMutation({ connector, ...options, operationId: 'stripe:v2:2' });
  assert.equal(retry.ok, false);
  assert.equal(stripe.calls.filter(([op]) => op === 'payout').length, 1);
});

test('v2 signed authority must name the probed mode; expired or invalid authority never enters provider', async () => {
  const stripe = client(true);
  const connector = await createStripeAllowanceConnectorV2({ stripe, stripeAccount: 'acct_fixed' });
  assert.equal(stripeAllowanceConnectorIdentity(connector), 'stripe:acct_fixed:live');
  const testAllowance = fixture('stripe:acct_fixed:test');
  assert.equal((await guardStripeAllowanceMutation({ connector, ...testAllowance })).reason, 'connector_mismatch');
  const expired = fixture('stripe:acct_fixed:live');
  assert.equal((await guardStripeAllowanceMutation({ connector, ...expired,
    now: Date.parse('2026-08-01T00:00:00Z') })).ok, false);
  const invalid = fixture('stripe:acct_fixed:live');
  const tampered = structuredClone(invalid.allowance);
  tampered.connector_id = 'stripe:acct_fixed:test';
  assert.equal((await guardStripeAllowanceMutation({ connector, ...invalid, allowance: tampered })).ok, false);
  assert.equal(stripe.calls.filter(([op]) => op === 'payout').length, 0);
});

test('v2 unknown mode, mismatched account or failed identity probe prevents connector construction', async () => {
  for (const mode of [undefined, null, 'false', 0]) {
    const unknown = client();
    unknown.balance.retrieve = async () => ({ object: 'balance', livemode: mode });
    await assert.rejects(createStripeAllowanceConnectorV2({ stripe: unknown, stripeAccount: 'acct_fixed' }));
  }
  const mismatch = client();
  mismatch.accounts.retrieve = async () => ({ id: 'acct_other' });
  await assert.rejects(createStripeAllowanceConnectorV2({ stripe: mismatch, stripeAccount: 'acct_fixed' }));
  const failed = client();
  failed.balance.retrieve = async () => { throw new Error('probe unavailable'); };
  await assert.rejects(createStripeAllowanceConnectorV2({ stripe: failed, stripeAccount: 'acct_fixed' }));
  assert.equal(failed.calls.filter(([op]) => op === 'payout').length, 0);
});
