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
import { allowanceDigest, executeWithGateAllowance } from '../allowance.js';
import { PROVIDER_SLOT_SPECS, authorizationInstanceDigest, deriveProviderReplayKey, deriveProviderReplayKeyV2, } from '../provider-replay-key.js';
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
        // default_for_currency is the material effect of this operation: it is what makes the
        // external account the payout destination. It is bound so a receipt for "attach but do
        // not default" cannot be replayed as "make this the default".
        execution_binding: { required_fields: ['action_type', 'account', 'external_account', 'default_for_currency'] },
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
        // The only update field this operation forwards is default_for_currency, and only as a
        // strict boolean. Anything else a caller puts in an `update` object never reaches Stripe:
        // the actuator is rebuilt from the VERIFIED observed fields, never from the caller object.
        observed: (p) => ({
            action_type: 'stripe.bank_account.change',
            account: p.account,
            external_account: p.external_account,
            ...(typeof p.default_for_currency === 'boolean' ? { default_for_currency: p.default_for_currency } : {}),
        }),
        actuator: (_p, observed) => ({
            ...observed,
            // An absent field yields an empty update; the pack's execution_binding then refuses the
            // call before perform() because default_for_currency is a required bound field.
            update: typeof observed.default_for_currency === 'boolean'
                ? { default_for_currency: observed.default_for_currency }
                : {},
        }),
        perform: (stripe, p) => stripe.accounts.updateExternalAccount(p.account, p.external_account, p.update),
    },
};
const adapter = createAdapter({ system: 'stripe', ops: OPS });
export const STRIPE_OPS = adapter.OPS;
const stripeAllowanceConnectors = new WeakMap();
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
export async function createStripeAllowanceConnector({ stripe, } = {}) {
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
 * Opt-in v2 setup. The client, credentials and endpoint must be controlled by
 * trusted deployment code and remain fixed for this connector's lifetime.
 * A caller-provided fake SDK is not provider authentication. Connect account
 * context is fixed here and reused on account/mode probes and every payout.
 * These read-only probes do not prove retention or durable replay history.
 */
export async function createStripeAllowanceConnectorV2({ stripe, stripeAccount }) {
    if (typeof stripeAccount !== 'string' || !/^acct_[A-Za-z0-9_]{1,110}$/.test(stripeAccount)
        || typeof stripe?.accounts?.retrieve !== 'function'
        || typeof stripe?.balance?.retrieve !== 'function'
        || typeof stripe?.payouts?.create !== 'function') {
        throw new TypeError('Stripe v2 requires a fixed account and account/balance/payout client');
    }
    const requestOptions = Object.freeze({ stripeAccount });
    const account = await stripe.accounts.retrieve(null, {}, requestOptions);
    if (!account || account.id !== stripeAccount) {
        throw new TypeError('Stripe v2 account probe does not match the fixed request account');
    }
    const balance = await stripe.balance.retrieve({}, requestOptions);
    if (!balance || balance.object !== 'balance' || typeof balance.livemode !== 'boolean') {
        throw new TypeError('Stripe v2 balance probe did not establish execution mode');
    }
    const connectorInstanceId = `stripe:${stripeAccount}:${balance.livemode ? 'live' : 'test'}`;
    // Capture the method so action callers cannot replace it after construction.
    // Changing the underlying SDK credentials remains outside this trust boundary.
    const create = stripe.payouts.create.bind(stripe.payouts);
    const connector = Object.freeze({});
    stripeAllowanceConnectors.set(connector, {
        stripe: { payouts: { create } }, connectorInstanceId, requestOptions, replayVersion: 2,
    });
    return connector;
}
/** Public setup metadata only, not evidence of authority or provider effect. */
export function stripeAllowanceConnectorIdentity(connector) {
    return stripeAllowanceConnectors.get(connector)?.connectorInstanceId ?? null;
}
// Frozen contract: changes require a new slot id/commitment, never mutation.
const STRIPE_V2_SLOT = Object.freeze({
    ...PROVIDER_SLOT_SPECS['stripe.idempotency-key'],
    slot_id: 'stripe.idempotency-key.v2', prefix: 'ep2_',
});
const STRIPE_V2_CARRIAGE_DIGEST = 'sha256:9dc14bb6776332a3bb7ba41d3939e117fdd1074c811ffd03f51b335c44428416';
/**
 * Execute a typed Stripe payout under a signed Gate allowance.
 *
 * The Stripe client and credentials remain in the caller's process. This
 * adapter constructs the exact closed action that the signed allowance names;
 * generic Stripe methods are deliberately not exposed through this path.
 */
export function guardStripeAllowanceMutation({ connector, params, operationId, attemptGroup = '1', ...allowanceOptions }) {
    const configured = stripeAllowanceConnectors.get(connector);
    if (!configured)
        throw new TypeError('guardStripeAllowanceMutation requires a configured Stripe allowance connector');
    // This adapter has no authenticated, durable epoch-rotation mechanism.
    // Keep the historical default stable; a request caller cannot release the
    // provider fence by choosing another group. This does not detect store rollback.
    if (attemptGroup !== '1') {
        return Promise.resolve({ ok: false, reason: 'provider_replay_epoch_rotation_unsupported' });
    }
    if (configured.replayVersion === 2
        && ['provider_env', 'providerEnv', 'retry_epoch_digest', 'stripeAccount']
            .some((key) => Object.hasOwn(allowanceOptions, key))) {
        return Promise.resolve({ ok: false, reason: 'provider_replay_scope_override_refused' });
    }
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
    // The Stripe Idempotency-Key is no longer the caller-supplied operation id.
    // It is derived from the authorization instance: this allowance artifact
    // bound to this one material payout. Consequences of that, stated plainly:
    //
    //  - A retry of the SAME payout under a NEW operation id sends the SAME
    //    Idempotency-Key, so Stripe returns its stored result instead of paying
    //    twice. Under the old behaviour a retry with a fresh operation id was a
    //    fresh Stripe request.
    //  - A DIFFERENT payout under the same allowance (different amount, currency
    //    or destination) derives a different key, so the allowance's aggregate
    //    budget still works.
    //  - Two IDENTICAL payouts under one allowance derive the same key. The Gate
    //    already refuses that: the capability action fence is unique on
    //    (operation_namespace, action_fence_digest) for live operations, and
    //    allowanceActionFenceDigest deliberately excludes the operation id field.
    //    So the derived key follows the fence the Gate already enforces rather
    //    than opening a hole. This path supports only the stable group '1'. A
    //    second identical payout requires separate authority; caller-selected
    //    groups are not authenticated retry epochs and are refused above.
    //  - Stripe prunes keys after at least 24 hours. Beyond that window Stripe
    //    stops being a second consumer of this authorization and the fence is
    //    ours alone. See PROVIDER_KEY_RETENTION_MEASUREMENT.
    //
    // The operation id keeps its existing role unchanged: it is still the
    // allowance's operation binding (action[operation_id_field] === operationId)
    // and still the capability ledger's operation key. Only the value handed to
    // Stripe changes.
    let allowanceArtifactDigest;
    try {
        allowanceArtifactDigest = allowanceDigest(allowanceOptions.allowance);
    }
    catch {
        return Promise.resolve({ ok: false, reason: 'allowance_action_shape_invalid' });
    }
    const instance = authorizationInstanceDigest({
        authorization_digest: allowanceArtifactDigest,
        profile: 'stripe.payout.create',
        material_action: {
            action_type: action.action_type,
            amount: action.amount,
            currency: action.currency,
            destination: action.destination,
        },
    });
    if (instance.ok !== true) {
        return Promise.resolve({ ok: false, reason: `provider_replay_key_${instance.reason}` });
    }
    const replayKey = configured.replayVersion === 2
        ? deriveProviderReplayKeyV2({
            authorization_digest: instance.digest,
            caid: 'stripe.payout.create',
            provider_env: connectorInstanceId,
            // The signed allowance artifact selects one stable epoch. Verification
            // happens inside executeWithGateAllowance before executeAction can run.
            // No caller rotation or durable epoch history is invented here.
            retry_epoch_digest: allowanceArtifactDigest,
            slot_spec: STRIPE_V2_SLOT,
            carriage_contract_digest: STRIPE_V2_CARRIAGE_DIGEST,
        })
        : deriveProviderReplayKey({
            authorization_digest: instance.digest,
            caid: 'stripe.payout.create',
            provider_env: connectorInstanceId,
            attempt_group: '1',
            slot_spec: PROVIDER_SLOT_SPECS['stripe.idempotency-key'],
        });
    if (replayKey.ok !== true) {
        return Promise.resolve({ ok: false, reason: `provider_replay_key_${replayKey.reason}` });
    }
    return executeWithGateAllowance({
        ...allowanceOptions,
        expected: {
            ...(allowanceOptions.expected || {}),
            connector_id: connectorInstanceId,
        },
        action,
        operationId,
        executeAction: (verifiedAction) => {
            // Invariant guard, not an input path. executeWithGateAllowance has
            // already required the verified action's field set to equal the
            // allowance's material_fields exactly, so this can only fire if that
            // contract changes underneath. If it ever does, no money moves.
            if (verifiedAction.amount !== action.amount
                || verifiedAction.currency !== action.currency
                || verifiedAction.destination !== action.destination
                || verifiedAction.action_type !== action.action_type) {
                throw new Error('stripe_replay_key_binding_mismatch');
            }
            return stripe.payouts.create({
                amount: verifiedAction.amount,
                currency: verifiedAction.currency,
                destination: verifiedAction.destination,
                // Echoed into metadata as well as the header because Stripe's own
                // signed webhook events carry metadata and do not carry the
                // Idempotency-Key. This is the recomputable join key inside Stripe's
                // authenticated record. It is not a Stripe attestation about the
                // authorization; Stripe stores an opaque string it was handed.
                metadata: { ep_replay_key: replayKey.key },
            }, { ...configured.requestOptions, idempotencyKey: replayKey.key });
        },
    });
}
export default {
    STRIPE_ACTION_PACK,
    STRIPE_OPS,
    createStripeManifest,
    guardStripeMutation,
    createStripeAllowanceConnector,
    createStripeAllowanceConnectorV2,
    stripeAllowanceConnectorIdentity,
    guardStripeAllowanceMutation,
};
//# sourceMappingURL=stripe.js.map