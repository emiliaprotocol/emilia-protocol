// SPDX-License-Identifier: Apache-2.0
/**
 * Opt-in Stripe refund recovery on the existing Proposal-to-Effect PostgreSQL
 * attempt store. The legacy Stripe adapter is intentionally unchanged.
 *
 * COMMITTED here means Stripe accepted creation of a refund object, not that
 * money has settled or that the refund's later status is successful.
 */
import crypto from 'node:crypto';
import { canonicalActuatorObject, hashCanonical, manifestFromPack } from './_kit.js';
import { STRIPE_ACTION_PACK } from './stripe.js';
import { verifyExecutionBinding } from '../execution-binding.js';
import { createProposalToEffectPostgresStore, } from '../proposal-to-effect-postgres.js';
const PROFILE = 'EMILIA-STRIPE-REFUND-DURABLE-v1';
const PROVIDER_ID = 'stripe';
const SELECTOR = Object.freeze({ protocol: 'stripe', tool: 'create_refund' });
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9:._/@-]{7,199}$/;
const PAYMENT_INTENT = /^pi_[A-Za-z0-9_]{1,240}$/;
const STRIPE_ACCOUNT = /^acct_[A-Za-z0-9_]{1,240}$/;
const REFUND_ID = /^re_[A-Za-z0-9_]{1,240}$/;
const REQUIRED_FIELDS = Object.freeze([
    'action_type', 'provider_account_id', 'payment_intent', 'amount', 'operation_id',
]);
const connectors = new WeakMap();
/**
 * Build a manifest whose refund receipt binds the provider account as well as
 * the payment, amount, and operation. The direct adapter's older manifest is
 * intentionally not changed and is refused by this durable connector.
 */
export function createStripeDurableRefundManifest(extraActions = []) {
    const pack = STRIPE_ACTION_PACK.map((item) => item.id === 'stripe.refund.create'
        ? {
            ...item,
            execution_binding: { required_fields: [...REQUIRED_FIELDS] },
        }
        : item);
    return manifestFromPack(pack, extraActions);
}
function digest(value) {
    return `sha256:${hashCanonical(value)}`;
}
function assertIdentifier(value, name) {
    if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
        throw new TypeError(`${name} is invalid`);
    }
}
function assertRefund(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError('trusted refund operation is invalid');
    }
    const p = value;
    if (!PAYMENT_INTENT.test(String(p.payment_intent ?? ''))
        || !Number.isSafeInteger(p.amount) || Number(p.amount) <= 0
        || typeof p.operation_id !== 'string' || !OPERATION_ID.test(p.operation_id)) {
        throw new TypeError('trusted refund operation is invalid');
    }
}
function context(config, p) {
    const action = canonicalActuatorObject({
        action_type: 'stripe.refund.create',
        provider_account_id: config.account_id,
        payment_intent: p.payment_intent,
        amount: p.amount,
        operation_id: p.operation_id,
    });
    const idempotencyKey = `emilia:stripe:refund:durable:v1:${hashCanonical({
        purpose: 'stripe.refund.create', tenant_id: config.tenant_id,
        provider_account_id: config.account_id, environment: config.environment,
        operation_id: p.operation_id,
    })}`;
    // Attempt identity is stable across fresh receipts and OAuth proofs. The
    // request digest pins every material/provider field before Stripe entry.
    const attemptId = `stripe-refund:${hashCanonical({
        tenant_id: config.tenant_id, account_id: config.account_id,
        environment: config.environment, operation_id: p.operation_id,
    })}`;
    const binding = {
        tenant_id: config.tenant_id,
        provider_id: PROVIDER_ID,
        provider_account_id: config.account_id,
        environment: config.environment,
        attempt_id: attemptId,
        request_digest: digest({
            profile: PROFILE, tenant_id: config.tenant_id, provider_id: PROVIDER_ID,
            account_id: config.account_id, environment: config.environment,
            action, idempotency_key: idempotencyKey,
        }),
    };
    // This is a local CAID profile over the exact Stripe refund material; it is
    // not a claim of a registered global Stripe action definition.
    const caidAction = { ...action, action_type: 'stripe.refund.create.1' };
    const caid = `caid:1:stripe.refund.create.1:jcs-sha256:${Buffer.from(hashCanonical(caidAction), 'hex').toString('base64url')}`;
    const metadata = {
        emilia_operation_id: p.operation_id,
        emilia_request_digest: binding.request_digest,
        emilia_idempotency_key: idempotencyKey,
        emilia_origin_tag: crypto.createHmac('sha256', config.metadata_key)
            .update(PROFILE).update('\0').update(binding.request_digest)
            .digest('hex'),
    };
    return { action, binding, caid, idempotencyKey, metadata };
}
/** Deterministic PTE digests: no parallel journal or process-local binding map. */
export function stripeRefundAttemptDigests(binding) {
    if (binding.provider_id !== PROVIDER_ID || !STRIPE_ACCOUNT.test(binding.provider_account_id)
        || !/^stripe-refund:[0-9a-f]{64}$/.test(binding.attempt_id)
        || !/^sha256:[0-9a-f]{64}$/.test(binding.request_digest)) {
        throw new TypeError('Stripe refund attempt binding is invalid');
    }
    return {
        operation_digest: digest({ profile: PROFILE, attempt_id: binding.attempt_id }),
        action_digest: binding.request_digest,
        config_digest: digest({ profile: PROFILE, provider_id: PROVIDER_ID,
            account_id: binding.provider_account_id, environment: binding.environment }),
    };
}
/** Configure the existing PTE PostgreSQL machinery for this Stripe profile. */
export function createStripeRefundDurableStore(options) {
    assertIdentifier(options.tenant_id, 'tenant_id');
    assertIdentifier(options.environment, 'environment');
    if (!STRIPE_ACCOUNT.test(options.provider_account_id))
        throw new TypeError('Stripe account is invalid');
    const { tenant_id, provider_account_id, environment, authorize_recovery, ...storeOptions } = options;
    return createProposalToEffectPostgresStore({
        ...storeOptions,
        resolve_binding_digests(binding) {
            if (binding.tenant_id !== tenant_id || binding.provider_account_id !== provider_account_id
                || binding.environment !== environment) {
                throw new TypeError('Stripe refund attempt namespace mismatch');
            }
            return stripeRefundAttemptDigests(binding);
        },
        async authorize_recovery(snapshot) {
            if (snapshot.tenant_id !== tenant_id || snapshot.provider_id !== PROVIDER_ID
                || snapshot.provider_account_id !== provider_account_id
                || snapshot.environment !== environment)
                return false;
            const digests = stripeRefundAttemptDigests(snapshot);
            if (snapshot.operation_digest !== digests.operation_digest
                || snapshot.action_digest !== digests.action_digest
                || snapshot.config_digest !== digests.config_digest)
                return false;
            return authorize_recovery(snapshot);
        },
    });
}
/**
 * The operation resolver must read the business system's immutable refund job,
 * not echo agent-supplied payment fields or mint an ID for each retry.
 */
export async function createStripeRefundDurableConnector(input) {
    if (!input?.stripe?.accounts || typeof input.stripe.accounts.retrieve !== 'function'
        || typeof input.stripe?.refunds?.create !== 'function'
        || typeof input.stripe.refunds.list !== 'function'
        || typeof input.gate?.check !== 'function' || typeof input.gate.run !== 'function'
        || typeof input.resolve_operation !== 'function'
        || !(input.metadata_hmac_sha256_key instanceof Uint8Array)
        || input.metadata_hmac_sha256_key.byteLength < 32
        || !input.store?.durable || !input.store.ownershipFenced
        || !input.store.compareAndSwap || !input.store.atomicEvidenceBinding
        || typeof input.store.reserve !== 'function' || typeof input.store.reconcile !== 'function'
        || typeof input.store.recover !== 'function') {
        throw new TypeError('durable Stripe refund connector configuration is invalid');
    }
    assertIdentifier(input.tenant_id, 'tenant_id');
    assertIdentifier(input.environment, 'environment');
    const account = await input.stripe.accounts.retrieve();
    if (!STRIPE_ACCOUNT.test(String(account?.id ?? ''))) {
        throw new TypeError('Stripe account identity probe failed');
    }
    const connector = Object.freeze({
        profile: PROFILE, account_id: account.id,
        tenant_id: input.tenant_id, environment: input.environment,
    });
    connectors.set(connector, {
        ...input, account_id: connector.account_id,
        metadata_key: Buffer.from(input.metadata_hmac_sha256_key),
    });
    return connector;
}
async function resolve(connector, reference) {
    const config = connectors.get(connector);
    if (!config)
        throw new TypeError('unconfigured Stripe refund connector');
    assertIdentifier(reference, 'refund operation reference');
    const account = await config.stripe.accounts.retrieve();
    if (account?.id !== config.account_id)
        throw new Error('stripe_account_changed');
    const trusted = await config.resolve_operation(reference);
    assertRefund(trusted);
    // Never retain a mutable business-system object across async Gate/store work.
    const p = canonicalActuatorObject({
        payment_intent: trusted.payment_intent,
        amount: trusted.amount,
        operation_id: trusted.operation_id,
    });
    return { config, p, ...context(config, p) };
}
function positiveRefundEvidence(record, resolved) {
    if (!record || !REFUND_ID.test(String(record.id ?? ''))
        || record.payment_intent !== resolved.p.payment_intent
        || record.amount !== resolved.p.amount
        || !Number.isSafeInteger(record.created)
        || Number(record.created) <= 0 || Number(record.created) * 1000 > Date.now() + 300_000
        || !record.metadata || typeof record.metadata !== 'object'
        || Array.isArray(record.metadata))
        return null;
    const metadata = record.metadata;
    if (metadata.emilia_operation_id !== resolved.p.operation_id
        || metadata.emilia_request_digest !== resolved.binding.request_digest
        || metadata.emilia_idempotency_key !== resolved.idempotencyKey
        || metadata.emilia_origin_tag !== resolved.metadata.emilia_origin_tag)
        return null;
    const observedAt = new Date(Number(record.created) * 1000).toISOString();
    return {
        ...resolved.binding,
        operation_id: resolved.p.operation_id,
        caid: resolved.caid,
        action_digest: resolved.binding.request_digest,
        evidence_id: record.id,
        observed_at: observedAt,
        outcome: 'COMMITTED',
        evidence_digest: digest({
            profile: PROFILE, provider_id: PROVIDER_ID,
            account_id: resolved.config.account_id, id: record.id,
            payment_intent: record.payment_intent, amount: record.amount,
            created: record.created, metadata: resolved.metadata,
        }),
    };
}
function attemptRef(binding, owner) {
    return { tenant_id: binding.tenant_id, attempt_id: binding.attempt_id, owner };
}
async function markIndeterminate(store, binding, owner) {
    return store.transition({ ...attemptRef(binding, owner), expected_state: 'INVOKING', next_state: 'INDETERMINATE' });
}
async function commitVerified(store, binding, owner, evidence) {
    return store.reconcile({
        ...attemptRef(binding, owner), expected_state: 'INDETERMINATE',
        next_state: 'COMMITTED', evidence,
    });
}
/**
 * At most one provider-entry attempt for a stable business operation on this
 * covered connector, assuming every mutation uses it, each Stripe account has
 * one owning tenant for this profile, and the durable PTE store is configured
 * correctly. An existing, uncertain or terminal attempt
 * never calls Stripe again, even with fresh receipts or after Stripe's
 * idempotency-key retention window.
 */
export async function guardStripeRefundDurable(connector, input) {
    const resolved = await resolve(connector, input.operation_reference);
    const { config, p, action, binding, idempotencyKey, metadata } = resolved;
    const preflight = await config.gate.check({
        selector: SELECTOR, receipt: input.receipt, observedAction: action,
        consumptionMode: 'none',
    });
    if (preflight.allow !== true) {
        return { ok: false, state: 'REFUSED', reason: preflight.reason || 'gate_refused' };
    }
    const required = preflight.requirement?.execution_binding?.required_fields;
    if (preflight.requirement?.receipt_required !== true
        || !Array.isArray(required)
        || REQUIRED_FIELDS.some((field) => !required.includes(field))) {
        return { ok: false, state: 'REFUSED', reason: 'stripe_account_binding_profile_required' };
    }
    let reservation;
    try {
        reservation = await config.store.reserve(binding);
    }
    catch {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_store_unavailable' };
    }
    if (!reservation.reserved) {
        return { ok: false, state: 'INDETERMINATE', reason: 'operation_already_reserved' };
    }
    const { owner } = reservation;
    if (!await config.store.transition({
        ...attemptRef(binding, owner), expected_state: 'RESERVED', next_state: 'INVOKING',
    }).catch(() => false)) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_transition_failed' };
    }
    let entered = false;
    let callbackOpen = true;
    let callbackClaimed = false;
    let providerEvidence = null;
    let gateResult = null;
    try {
        gateResult = await config.gate.run({
            selector: SELECTOR, receipt: input.receipt, observedAction: action,
        }, async (authorization) => {
            // A Gate implementation must not turn one reserved attempt into more
            // than one provider call, even if it invokes or resumes the callback
            // more than once.
            if (!callbackOpen)
                throw new Error('stripe_refund_provider_callback_closed');
            if (callbackClaimed)
                throw new Error('stripe_refund_provider_callback_already_claimed');
            callbackClaimed = true;
            const currentRequired = authorization?.requirement?.execution_binding?.required_fields;
            if (authorization?.allow !== true || authorization.requirement?.receipt_required !== true
                || !Array.isArray(currentRequired)
                || REQUIRED_FIELDS.some((field) => !currentRequired.includes(field))
                || verifyExecutionBinding({
                    requirement: authorization.requirement,
                    receipt: input.receipt,
                    observedAction: action,
                }).ok !== true) {
                throw new Error('stripe_account_binding_profile_changed');
            }
            const account = await config.stripe.accounts.retrieve();
            if (!callbackOpen)
                throw new Error('stripe_refund_provider_callback_closed');
            if (account?.id !== config.account_id)
                throw new Error('stripe_account_changed');
            entered = true;
            const result = await config.stripe.refunds.create({
                payment_intent: p.payment_intent, amount: p.amount, metadata,
            }, { idempotencyKey });
            providerEvidence = positiveRefundEvidence(result, resolved);
            if (!providerEvidence)
                throw new Error('stripe_refund_response_unverified');
            return result;
        });
    }
    catch {
        // Even a known client exception can mean Stripe accepted the refund and
        // its response was lost. Do not retry or free the operation ID.
    }
    finally {
        callbackOpen = false;
    }
    if (!await markIndeterminate(config.store, binding, owner).catch(() => false)) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_freeze_failed' };
    }
    if (providerEvidence) {
        const committed = await commitVerified(config.store, binding, owner, providerEvidence).catch(() => false);
        if (committed) {
            return gateResult?.ok === true
                ? { ok: true, state: 'COMMITTED', refund: gateResult.result ?? null,
                    reliance: gateResult.packet ?? null, execution: gateResult.execution ?? null }
                : { ok: false, state: 'COMMITTED', reason: 'provider_created_gate_outcome_unknown' };
        }
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_commit_failed' };
    }
    if (!entered && gateResult?.ok === false) {
        const released = await config.store.transition({
            ...attemptRef(binding, owner), expected_state: 'INDETERMINATE', next_state: 'RELEASED',
        }).catch(() => false);
        return { ok: false, state: released ? 'RELEASED' : 'INDETERMINATE',
            reason: gateResult.authorization?.reason || 'gate_refused' };
    }
    return { ok: false, state: 'INDETERMINATE', reason: entered
            ? 'stripe_refund_outcome_unknown' : 'provider_entry_unknown' };
}
/**
 * Recovery never calls refunds.create. A bounded list query supplies positive
 * evidence only if exactly one matching refund is found and the page is
 * complete. Empty, incomplete, unavailable, or conflicting results stay
 * INDETERMINATE; none proves NOT_COMMITTED.
 * The server-secret tag narrows accidental/external collision, but it can be
 * copied by an actor with access to both the Stripe metadata and refund-write
 * credentials. A matching object proves existence, not exclusive authorship.
 */
export async function reconcileStripeRefundDurable(connector, operation_reference) {
    const resolved = await resolve(connector, operation_reference);
    const { config, binding, p } = resolved;
    const lookup = {
        tenant_id: binding.tenant_id, provider_id: binding.provider_id,
        provider_account_id: binding.provider_account_id,
        environment: binding.environment, request_digest: binding.request_digest,
    };
    const found = await config.store.lookup(lookup).catch(() => null);
    if (!found)
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_not_found_or_unavailable' };
    if (found.attempt_id !== binding.attempt_id) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_binding_mismatch' };
    }
    const snapshot = await config.store.read(found).catch(() => null);
    if (!snapshot)
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_unavailable' };
    const expectedDigests = stripeRefundAttemptDigests(binding);
    if (snapshot.operation_digest !== expectedDigests.operation_digest
        || snapshot.action_digest !== expectedDigests.action_digest
        || snapshot.config_digest !== expectedDigests.config_digest) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_binding_mismatch' };
    }
    if (snapshot.state === 'COMMITTED') {
        return /^sha256:[0-9a-f]{64}$/.test(String(snapshot.evidence_digest ?? ''))
            ? { ok: true, state: 'COMMITTED', reason: 'previously_verified' }
            : { ok: false, state: 'INDETERMINATE', reason: 'terminal_without_provider_evidence' };
    }
    if (snapshot.state === 'RELEASED' || snapshot.state === 'ESCALATED') {
        return { ok: false, state: snapshot.state, reason: 'attempt_terminal' };
    }
    // A live owner might still be entering Stripe; recovery must not steal it.
    if (!snapshot.lease_stale) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_owner_active' };
    }
    const recovered = await config.store.recover(found).catch(() => ({ recovered: false }));
    if (!recovered.recovered) {
        return { ok: false, state: 'INDETERMINATE', reason: 'attempt_recovery_refused' };
    }
    if (recovered.state === 'RESERVED') {
        // No provider entry occurred in RESERVED. Do not invent a provider result;
        // the operation remains held for an explicit owner decision.
        return { ok: false, state: 'RESERVED', reason: 'attempt_not_invoked' };
    }
    let page;
    try {
        page = await config.stripe.refunds.list({ payment_intent: p.payment_intent, limit: 100 });
    }
    catch {
        return { ok: false, state: 'INDETERMINATE', reason: 'provider_lookup_unavailable' };
    }
    if (!Array.isArray(page?.data) || page.has_more !== false) {
        return { ok: false, state: 'INDETERMINATE', reason: 'provider_lookup_incomplete' };
    }
    const matches = page.data.map((item) => positiveRefundEvidence(item, resolved)).filter(Boolean);
    if (matches.length !== 1) {
        return { ok: false, state: 'INDETERMINATE',
            reason: matches.length === 0 ? 'provider_effect_unproven' : 'provider_effect_ambiguous' };
    }
    const committed = await commitVerified(config.store, binding, recovered.owner, matches[0]).catch(() => false);
    return committed
        ? { ok: true, state: 'COMMITTED', refund_id: matches[0].evidence_id }
        : { ok: false, state: 'INDETERMINATE', reason: 'attempt_commit_failed' };
}
export default {
    createStripeDurableRefundManifest,
    stripeRefundAttemptDigests,
    createStripeRefundDurableStore,
    createStripeRefundDurableConnector,
    guardStripeRefundDurable,
    reconcileStripeRefundDurable,
};
//# sourceMappingURL=stripe-refund-durable.js.map