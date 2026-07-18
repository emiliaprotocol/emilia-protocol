// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import {
  executeWithCapability,
  executeWithThreshold,
  delegateCapabilityReceipt,
  createMemoryCapabilityStore,
  mintCapabilityReceipt,
  reconstructCapabilitySecret,
  splitCapabilitySecret,
  verifyCapabilityReceipt,
} from './capability-receipt.js';

const NOW = Date.parse('2026-07-18T22:00:00.000Z');

function baseReceipt({ privateKey, publicKey, receiptId = 'base_1' } = {}) {
  const payload = {
    receipt_id: receiptId,
    created_at: new Date(NOW - 1000).toISOString(),
    subject: 'operator@example.test',
    claim: { action_type: 'payment.release', outcome: 'allow' },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url') },
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function issuer() {
  const keys = generateKeyPairSync('ed25519');
  return { ...keys, receipt: baseReceipt({ privateKey: keys.privateKey, publicKey: keys.publicKey }) };
}

function options(overrides = {}) {
  return {
    budget: { amount: 100, currency: 'USD' },
    expiry: NOW + 60_000,
    issuerPrivateKey: overrides.issuerPrivateKey,
    ...overrides,
  };
}

test('capability metadata is issuer-signed and tamper-evident', () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const trusted = keys.receipt.public_key;
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: [trusted] }).ok, true);

  const tampered = structuredClone(minted.capabilityReceipt);
  tampered.capability.budget.amount = 1_000_000;
  assert.equal(verifyCapabilityReceipt(tampered, { trustedIssuerKeys: [trusted] }).ok, false);
  assert.equal(verifyCapabilityReceipt(minted.capabilityReceipt, { trustedIssuerKeys: ['wrong'] }).reason, 'capability_issuer_not_trusted');
});

test('atomic capability spending enforces the budget and consumes indeterminate effects', async () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    secret: minted.secret,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
  };

  const first = await executeWithCapability({
    ...common,
    operationId: 'op_1',
    action: { amount: 30, currency: 'USD', destination: 'acct_a' },
    executeAction: async () => 'settled',
  });
  assert.equal(first.ok, true);
  assert.equal(first.result, 'settled');
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 30);

  const [left, right] = await Promise.all([
    executeWithCapability({ ...common, operationId: 'op_2', action: { amount: 60, currency: 'USD' }, executeAction: async () => 'left' }),
    executeWithCapability({ ...common, operationId: 'op_3', action: { amount: 60, currency: 'USD' }, executeAction: async () => 'right' }),
  ]);
  assert.equal([left.ok, right.ok].filter(Boolean).length, 1);
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 90);

  const indeterminate = await executeWithCapability({
    ...common,
    operationId: 'op_4',
    action: { amount: 10, currency: 'USD' },
    executeAction: async () => { throw new Error('provider response lost'); },
  });
  assert.equal(indeterminate.ok, false);
  assert.equal(indeterminate.reason, 'effect_indeterminate');
  assert.equal(store.getState(minted.capabilityReceipt.capability.id).consumed_amount, 100);
});

test('capability refuses invalid secret, currency, and unverified base authority', async () => {
  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({ issuerPrivateKey: keys.privateKey }));
  const store = createMemoryCapabilityStore();
  store.registerCapability(minted.capabilityReceipt);
  const common = {
    capabilityReceipt: minted.capabilityReceipt,
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
    operationId: 'bad_1',
    executeAction: async () => assert.fail('effect must not run'),
  };
  assert.equal((await executeWithCapability({ ...common, secret: Buffer.alloc(32), action: { amount: 1, currency: 'USD' } })).reason, 'invalid_secret');
  assert.equal((await executeWithCapability({ ...common, secret: minted.secret, action: { amount: 1, currency: 'EUR' } })).reason, 'capability action currency does not match the budget');
  assert.equal((await executeWithCapability({ ...common, secret: minted.secret, verifyBaseReceipt: () => false, action: { amount: 1, currency: 'USD' } })).reason, 'base_receipt_rejected');
});

test('threshold capability uses unique Shamir shares and requires m-of-n', async () => {
  const secret = Buffer.alloc(32, 7);
  const shares = splitCapabilitySecret(secret, { m: 2, n: 3 }, { randomBytesFn: () => Buffer.alloc(66, 9) });
  assert.equal(Buffer.compare(reconstructCapabilitySecret(shares.slice(0, 2), { m: 2, n: 3 }), secret), 0);
  assert.throws(() => reconstructCapabilitySecret([shares[0]], { m: 2, n: 3 }), /insufficient/);
  assert.throws(() => reconstructCapabilitySecret([shares[0], shares[0]], { m: 2, n: 3 }), /duplicate/);

  const keys = issuer();
  const minted = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    threshold: { m: 2, n: 3 },
    secret,
    capabilityId: 'threshold_1',
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(minted.capabilityReceipt), true);
  const result = await executeWithThreshold({
    capabilityReceipt: minted.capabilityReceipt,
    shares: minted.shares.slice(0, 2),
    action: { amount: 25, currency: 'USD' },
    store,
    trustedIssuerKeys: [keys.receipt.public_key],
    verifyBaseReceipt: () => true,
    now: NOW,
    operationId: 'threshold_op_1',
    executeAction: async () => 'threshold-settled',
  });
  assert.equal(result.ok, true);
  assert.equal(result.result, 'threshold-settled');
});

test('delegation burns parent budget before registering a spendable child', async () => {
  const keys = issuer();
  const parent = mintCapabilityReceipt(keys.receipt, options({
    issuerPrivateKey: keys.privateKey,
    capabilityId: 'parent_1',
    secret: Buffer.alloc(32, 8),
  }));
  const store = createMemoryCapabilityStore();
  assert.equal(store.registerCapability(parent.capabilityReceipt), true);

  const child = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 40, currency: 'USD' },
    expiry: NOW + 30_000,
    delegateId: 'pilot-operator',
    capabilityId: 'child_1',
    secret: Buffer.alloc(32, 9),
    store,
    now: NOW,
  });
  assert.equal(child.ok, true);
  assert.equal(child.capabilityReceipt.capability.delegation_chain.at(-1).parent_capability_id, 'parent_1');
  assert.equal(store.getState('parent_1').consumed_amount, 40);
  assert.equal(store.getState('child_1').budget_amount, 40);

  const tooLarge = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: keys.privateKey,
    trustedIssuerKeys: [keys.receipt.public_key],
    budget: { amount: 61, currency: 'USD' },
    expiry: NOW + 30_000,
    delegateId: 'pilot-operator',
    capabilityId: 'child_2',
    store,
    now: NOW,
  });
  assert.equal(tooLarge.ok, false);
  assert.equal(tooLarge.reason, 'budget_exceeded');
  assert.equal(store.getState('parent_1').consumed_amount, 40);
});
