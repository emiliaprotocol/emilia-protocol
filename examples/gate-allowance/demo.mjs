#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto, {
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

import {
  allowanceDigest,
  issueGateAllowance,
  verifyGateAllowance,
} from '../../packages/gate/allowance.js';
import {
  capabilityBaseReceiptDigest,
  createMemoryCapabilityStore,
} from '../../packages/gate/capability-receipt.js';
import {
  createStripeAllowanceConnector,
  guardStripeAllowanceMutation,
} from '../../packages/gate/adapters/stripe.js';
import { canonicalize } from '../../packages/gate/execution-binding.js';

const NOW = Date.parse('2026-07-30T18:00:00.000Z');
const TENANT_ID = 'tenant:allowance-demo';
const SUBJECT_ID = 'agent:finance:demo';
const AUDIENCE = 'gate:finance:demo';
const AUTHORIZER_ID = 'customer:allowance-demo';
const CONNECTOR_ID = 'stripe:acct_demo';

function digest(label) {
  return `sha256:${crypto.createHash('sha256').update(label).digest('hex')}`;
}

function exportPublicKey(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

const customerKeys = generateKeyPairSync('ed25519');
const capabilityIssuerKeys = generateKeyPairSync('ed25519');
const customerPublicKey = exportPublicKey(customerKeys.publicKey);
const capabilityIssuerPublicKey = exportPublicKey(capabilityIssuerKeys.publicKey);

const allowanceSigner = {
  issuer_id: AUTHORIZER_ID,
  key_id: 'key:allowance-demo-customer',
  private_key: customerKeys.privateKey,
};

const trustedAllowanceKeys = {
  'key:allowance-demo-customer': {
    issuer_id: AUTHORIZER_ID,
    public_key: customerPublicKey,
  },
};
const capabilityStore = createMemoryCapabilityStore();

function makeAuthorizationReceipt(receiptId, actionType = 'gate.allowance.issue') {
  const payload = {
    receipt_id: receiptId,
    created_at: new Date(NOW - 1_000).toISOString(),
    subject: 'owner@example.test',
    claim: {
      action_type: actionType,
      outcome: 'allow',
      capability_only: true,
    },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(
        null,
        Buffer.from(canonicalize(payload)),
        customerKeys.privateKey,
      ).toString('base64url'),
    },
    public_key: customerPublicKey,
  };
}

function verifyAuthorizationReceipt(receipt) {
  if (
    receipt?.['@version'] !== 'EP-RECEIPT-v1'
    || receipt?.signature?.algorithm !== 'Ed25519'
    || receipt?.public_key !== customerPublicKey
    || receipt?.payload?.claim?.capability_only !== true
  ) {
    return { ok: false, reason: 'authorization_receipt_rejected' };
  }
  const publicKey = createPublicKey({
    key: Buffer.from(receipt.public_key, 'base64url'),
    type: 'spki',
    format: 'der',
  });
  return verify(
    null,
    Buffer.from(canonicalize(receipt.payload)),
    publicKey,
    Buffer.from(receipt.signature.value, 'base64url'),
  )
    ? { ok: true }
    : { ok: false, reason: 'authorization_signature_invalid' };
}

/** @param {any} options */
function allowanceInput({
  receipt,
  allowanceId,
  presentationLabel,
  aggregateAmount,
  maxAmountPerAction,
  allowedTargets,
  revision = 1,
  supersedesAllowanceDigest = null,
}) {
  return {
    allowance_id: allowanceId,
    tenant_id: TENANT_ID,
    subject_id: SUBJECT_ID,
    audience: AUDIENCE,
    connector_id: CONNECTOR_ID,
    action_type: 'stripe.payout.create',
    revision,
    supersedes_allowance_digest: supersedesAllowanceDigest,
    authorization_receipt_digest: capabilityBaseReceiptDigest(receipt),
    presentation_digest: digest(presentationLabel),
    issued_at: '2026-07-30T17:59:00.000Z',
    valid_from: '2026-07-30T18:00:00.000Z',
    expires_at: '2026-07-31T18:00:00.000Z',
    constraints: {
      currency: 'USD',
      aggregate_amount: aggregateAmount,
      max_amount_per_action: maxAmountPerAction,
      material_fields: [
        'action_type',
        'amount',
        'currency',
        'destination',
        'operation_id',
      ],
      operation_id_field: 'operation_id',
      amount_field: 'amount',
      currency_field: 'currency',
      target_field: 'destination',
      allowed_targets: allowedTargets,
      allowed_values: {},
    },
  };
}

/**
 * @param {any} options
 * @returns {any}
 */
function issue({
  receipt,
  allowanceId,
  presentationLabel,
  aggregateAmount,
  maxAmountPerAction,
  allowedTargets,
  revision = 1,
  supersedesAllowanceDigest = null,
  predecessorAllowance,
}) {
  const issued = issueGateAllowance({
    authorizationReceipt: receipt,
    allowance: allowanceInput({
      receipt,
      allowanceId,
      presentationLabel,
      aggregateAmount,
      maxAmountPerAction,
      allowedTargets,
      revision,
      supersedesAllowanceDigest,
    }),
    ...(predecessorAllowance ? { predecessorAllowance } : {}),
    signer: allowanceSigner,
    capabilityIssuerPrivateKey: capabilityIssuerKeys.privateKey,
  });
  assert.equal(capabilityStore.registerCapability(issued.capabilityReceipt), true);
  return { ...issued, store: capabilityStore };
}

function expected(allowanceId) {
  return {
    allowance_id: allowanceId,
    tenant_id: TENANT_ID,
    subject_id: SUBJECT_ID,
    audience: AUDIENCE,
    connector_id: CONNECTOR_ID,
    authorizer_id: AUTHORIZER_ID,
  };
}

function executionOptions(active, operationId) {
  return {
    allowance: active.allowance,
    capabilityReceipt: active.capabilityReceipt,
    secret: active.secret,
    operationId,
    store: active.store,
    verifyAuthorizationReceipt,
    verifyAllowanceStatus: (_allowance, context) => ({
      ok: context.allowance_digest === activeAllowanceDigest,
      reason: 'allowance_superseded',
      status_epoch: activeStatus.status_epoch,
      status_head_digest: activeStatus.status_head_digest,
    }),
    trustedAllowanceKeys,
    trustedCapabilityIssuerKeys: [capabilityIssuerPublicKey],
    expected: expected(active.allowance.allowance_id),
    now: NOW,
  };
}

function createLocalStripeClient() {
  /** @type {any[]} */
  const calls = [];
  return {
    calls,
    accounts: {
      retrieve: async () => ({ id: 'acct_demo' }),
    },
    payouts: {
      create: async (params, requestOptions) => {
        localStripe.calls.push({
          params: structuredClone(params),
          requestOptions: structuredClone(requestOptions),
        });
        if (params.destination === 'acct_timeout') {
          throw new Error('synthetic provider response lost after entry');
        }
        return { id: `po_demo_${localStripe.calls.length}`, ...params };
      },
    },
  };
}

const localStripe = createLocalStripeClient();
const stripeConnector = await createStripeAllowanceConnector({
  stripe: localStripe,
});

const firstReceipt = makeAuthorizationReceipt('receipt:allowance-demo:01');
let active = issue({
  receipt: firstReceipt,
  allowanceId: 'allowance:stripe-demo:01',
  presentationLabel: 'reviewed allowance: known-a and timeout',
  aggregateAmount: 10_000,
  maxAmountPerAction: 5_000,
  allowedTargets: ['acct_known_a', 'acct_timeout'],
});
let activeAllowanceDigest = allowanceDigest(active.allowance);
let activeStatus = {
  status_epoch: 1,
  status_head_digest: digest('allowance-status:1'),
};

// Publish the opening status head before any spend is reserved. A spend whose
// asserted status has no counterpart in the store is refused with
// `allowance_status_not_initialized`, so an allowance that was signed but never
// published cannot authorize anything. Initialization is the one advance that
// asserts a null predecessor head; every later one names the head it replaces,
// which is what makes the chain non-forkable.
assert.equal((await capabilityStore.advanceAllowanceStatus({
  allowance_profile_id: `${TENANT_ID}/${active.allowance.allowance_id}`,
  allowance_digest: activeAllowanceDigest,
  revision: active.allowance.revision,
  expected_status_epoch: null,
  expected_status_head_digest: null,
  ...activeStatus,
  status: 'active',
})).ok, true);

assert.equal(
  verifyGateAllowance(active.allowance, {
    trusted_keys: trustedAllowanceKeys,
    now: NOW,
    expected_allowance_id: active.allowance.allowance_id,
    expected_tenant_id: TENANT_ID,
    expected_subject_id: SUBJECT_ID,
    expected_audience: AUDIENCE,
    expected_connector_id: CONNECTOR_ID,
    expected_authorizer_id: AUTHORIZER_ID,
  }).accepted,
  true,
);

const allowed = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 2_500, currency: 'USD', destination: 'acct_known_a' },
  ...executionOptions(active, 'payout:demo:01'),
});
assert.equal(allowed.ok, true);
assert.equal(allowed.remaining, 7_500);

const disallowedTarget = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 1_000, currency: 'USD', destination: 'acct_new_b' },
  ...executionOptions(active, 'payout:demo:target-refused'),
});
assert.equal(disallowedTarget.reason, 'allowance_target_not_allowed');

const oversized = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 5_001, currency: 'USD', destination: 'acct_known_a' },
  ...executionOptions(active, 'payout:demo:oversized'),
});
assert.equal(oversized.reason, 'allowance_per_action_limit_exceeded');

const indeterminate = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 1_000, currency: 'USD', destination: 'acct_timeout' },
  ...executionOptions(active, 'payout:demo:timeout'),
});
assert.equal(indeterminate.reason, 'effect_indeterminate');

const blindRetry = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 1_000, currency: 'USD', destination: 'acct_timeout' },
  ...executionOptions(active, 'payout:demo:timeout'),
});
assert.equal(blindRetry.reason, 'operation_already_committed');

// The exception is not a one-event bypass. The customer reviews and signs a new
// allowance with a new authorization receipt and capability. The successor
// signs the predecessor digest, and the local status source changes which
// revision is current. The old artifact remains immutable but no longer passes
// the mandatory current-status check.
const retired = active;
const successorReceipt = makeAuthorizationReceipt(
  'receipt:allowance-demo:02',
  'gate.allowance.supersede',
);
const successor = issue({
  receipt: successorReceipt,
  allowanceId: retired.allowance.allowance_id,
  presentationLabel: `successor to ${allowanceDigest(active.allowance)}: add acct_new_b`,
  aggregateAmount: 20_000,
  maxAmountPerAction: 7_500,
  allowedTargets: ['acct_known_a', 'acct_new_b', 'acct_timeout'],
  revision: 2,
  supersedesAllowanceDigest: allowanceDigest(retired.allowance),
  predecessorAllowance: retired.allowance,
});
active = successor;
activeAllowanceDigest = allowanceDigest(active.allowance);
const successorStatus = {
  status_epoch: 2,
  status_head_digest: digest('allowance-status:2'),
};
assert.equal((await capabilityStore.advanceAllowanceStatus({
  allowance_profile_id: `${TENANT_ID}/${active.allowance.allowance_id}`,
  allowance_digest: activeAllowanceDigest,
  revision: active.allowance.revision,
  expected_status_epoch: activeStatus.status_epoch,
  expected_status_head_digest: activeStatus.status_head_digest,
  ...successorStatus,
  status: 'active',
})).ok, true);
activeStatus = successorStatus;

const retiredRefused = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 1_000, currency: 'USD', destination: 'acct_known_a' },
  ...executionOptions(retired, 'payout:demo:retired'),
});
assert.equal(retiredRefused.reason, 'allowance_superseded');

const newlyAllowed = await guardStripeAllowanceMutation({
  connector: stripeConnector,
  params: { amount: 6_000, currency: 'USD', destination: 'acct_new_b' },
  ...executionOptions(active, 'payout:demo:successor'),
});
assert.equal(newlyAllowed.ok, true);
assert.equal(newlyAllowed.remaining, 14_000);

console.log(JSON.stringify({
  profile: 'EP-GATE-ALLOWANCE-v1',
  first_allowance: {
    allowed: allowed.ok,
    remaining_after_allowed_payout: allowed.remaining,
    disallowed_target: disallowedTarget.reason,
    oversized: oversized.reason,
    timeout: indeterminate.reason,
    blind_retry: blindRetry.reason,
  },
  successor_allowance: {
    allowance_id: active.allowance.allowance_id,
    retired_allowance: retiredRefused.reason,
    newly_allowed: newlyAllowed.ok,
    remaining: newlyAllowed.remaining,
  },
  provider_calls: localStripe.calls.length,
  credential_custody: 'local_process_only',
  hosted_service: 'not_used',
}, null, 2));
