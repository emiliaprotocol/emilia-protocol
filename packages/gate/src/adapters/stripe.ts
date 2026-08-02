// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — Stripe / payments System-of-Record adapter.
 *
 * "Install this before your agent can move money." Wraps the destructive Stripe
 * operations so a payout, refund, or payout-destination change never reaches
 * Stripe without a valid, sufficiently-assured, non-replayed receipt bound to
 * THIS amount/destination. A receipt for $100 to acct_A cannot authorize
 * $10,000 to acct_B.
 *
 *   import Stripe from 'stripe';
 *   import { createGate } from '@emilia-protocol/gate';
 *   import { createStripeManifest, guardStripeMutation } from '@emilia-protocol/gate/adapters/stripe';
 *
 *   const gate = createGate({ manifest: createStripeManifest(), trustedKeys: [ISSUER], store: sharedConsumptionStore });
 *   await guardStripeMutation(gate, new Stripe(key), {
 *     op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' }, receipt,
 *   });
 */
import { canonicalActuatorObject, createAdapter, manifestFromPack } from './_kit.js';
import { executeWithGateAllowance } from '../allowance.js';

export const STRIPE_ACTION_PACK = Object.freeze([
  Object.freeze({
    id: 'stripe.payout.create', label: 'Stripe payout', action_type: 'stripe.payout.create',
    risk: 'critical', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'stripe', tool: 'create_payout' },
    why: 'Moves money out. Bind amount/currency/destination to a named human approval.',
    execution_binding: { required_fields: ['action_type', 'amount', 'currency', 'destination'] },
  }),
  Object.freeze({
    id: 'stripe.refund.create', label: 'Stripe refund', action_type: 'stripe.refund.create',
    risk: 'high', receipt_required: true, assurance_class: 'class_a',
    match: { protocol: 'stripe', tool: 'create_refund' },
    why: 'Returns funds. Bind the payment and amount so a refund cannot be silently inflated.',
    execution_binding: { required_fields: ['action_type', 'payment_intent', 'amount'] },
  }),
  Object.freeze({
    id: 'stripe.bank_account.change', label: 'Stripe payout-destination change', action_type: 'stripe.bank_account.change',
    risk: 'critical', receipt_required: true, assurance_class: 'quorum',
    match: { protocol: 'stripe', tool: 'update_external_account' },
    why: 'Changes WHERE future money flows. Quorum: the classic redirect-the-payouts attack.',
    execution_binding: { required_fields: ['action_type', 'account', 'external_account'] },
  }),
]);

const OPS = {
  'payout.create': {
    selector: { protocol: 'stripe', tool: 'create_payout' },
    observed: (p) => ({ action_type: 'stripe.payout.create', amount: p.amount, currency: p.currency, destination: p.destination }),
    perform: (stripe, p) => stripe.payouts.create({ amount: p.amount, currency: p.currency, destination: p.destination }),
  },
  'refund.create': {
    selector: { protocol: 'stripe', tool: 'create_refund' },
    observed: (p) => ({ action_type: 'stripe.refund.create', payment_intent: p.payment_intent, amount: p.amount }),
    perform: (stripe, p) => stripe.refunds.create({ payment_intent: p.payment_intent, amount: p.amount }),
  },
  'bank_account.change': {
    selector: { protocol: 'stripe', tool: 'update_external_account' },
    observed: (p) => ({ action_type: 'stripe.bank_account.change', account: p.account, external_account: p.external_account }),
    perform: (stripe, p) => stripe.accounts.updateExternalAccount(p.account, p.external_account, p.update || {}),
  },
};

const adapter = createAdapter({ system: 'stripe', ops: OPS });
export const STRIPE_OPS = adapter.OPS;
const stripeAllowanceConnectors = new WeakMap<object, {
  stripe: any;
  connectorInstanceId: string;
}>();

export function createStripeManifest(extraActions = []) {
  return manifestFromPack(STRIPE_ACTION_PACK, extraActions);
}

/**
 * Guard a destructive Stripe mutation behind the gate.
 * @param {object} gate    a gate built with createStripeManifest()
 * @param {object} stripe  a Stripe-like client (the official `stripe` SDK or compatible)
 * @param {object} args    { op:'payout.create'|'refund.create'|'bank_account.change', params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches Stripe
 */
export function guardStripeMutation(gate, stripe, args) {
  return adapter.guard(gate, stripe, args);
}

/**
 * Bind a Stripe client to the account identity returned by a trusted provider
 * identity probe. The returned opaque connector is created during trusted
 * deployment setup; action callers cannot pair an arbitrary client with a
 * caller-asserted account string.
 */
export async function createStripeAllowanceConnector({
  stripe,
}: {
  stripe?: any;
} = {}) {
  if (!stripe?.payouts || typeof stripe.payouts.create !== 'function'
      || !stripe?.accounts || typeof stripe.accounts.retrieve !== 'function') {
    throw new TypeError('createStripeAllowanceConnector requires a Stripe payouts client');
  }
  const account = await stripe.accounts.retrieve();
  if (!account || typeof account.id !== 'string'
      || !/^acct_[A-Za-z0-9_]{1,240}$/.test(account.id)) {
    throw new TypeError('Stripe account identity probe returned an invalid account');
  }
  const connectorInstanceId = `stripe:${account.id}`;
  const connector = Object.freeze({});
  stripeAllowanceConnectors.set(connector, { stripe, connectorInstanceId });
  return connector;
}

/**
 * Execute a typed Stripe payout under a signed Gate allowance.
 *
 * The Stripe client and credentials remain in the caller's process. This
 * adapter constructs the exact closed action that the signed allowance names;
 * generic Stripe methods are deliberately not exposed through this path.
 */
export function guardStripeAllowanceMutation({
  connector,
  params,
  operationId,
  ...allowanceOptions
}) {
  const configured = stripeAllowanceConnectors.get(connector);
  if (!configured) throw new TypeError('guardStripeAllowanceMutation requires a configured Stripe allowance connector');
  const { stripe, connectorInstanceId } = configured;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new TypeError('guardStripeAllowanceMutation requires payout params');
  }
  const input = canonicalActuatorObject({
    amount: params.amount,
    currency: params.currency,
    destination: params.destination,
  });
  const action = {
    action_type: 'stripe.payout.create',
    amount: input.amount,
    currency: input.currency,
    destination: input.destination,
    operation_id: operationId,
  };
  return executeWithGateAllowance({
    ...allowanceOptions,
    expected: {
      ...(allowanceOptions.expected || {}),
      connector_id: connectorInstanceId,
    },
    action,
    operationId,
    executeAction: (verifiedAction) => stripe.payouts.create(
      {
        amount: verifiedAction.amount,
        currency: verifiedAction.currency,
        destination: verifiedAction.destination,
      },
      { idempotencyKey: verifiedAction.operation_id },
    ),
  });
}

export default {
  STRIPE_ACTION_PACK,
  STRIPE_OPS,
  createStripeManifest,
  guardStripeMutation,
  createStripeAllowanceConnector,
  guardStripeAllowanceMutation,
};
