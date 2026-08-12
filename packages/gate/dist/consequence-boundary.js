// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. A relying party pins the adapters, evidence
 * requirement, and local authorization policy. This module verifies the AEB
 * join against one frozen action, durably fences every native replay unit,
 * records dispatch custody, and invokes one provider adapter. It does not
 * acquire approvals, mint authority, or require an EMILIA receipt.
 */
import crypto from 'node:crypto';
import { aebReservationKey, authorizeAebExecutionDurable, canonicalizeAeb, digestAeb, reconcileAebExecutionDurable, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
export const CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-CONSEQUENCE-BOUNDARY-v1';
export const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = 'EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const AUTHORIZATION_INSTANCE = /^[A-Za-z0-9_.:-]{1,256}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function dataRecord(value) {
    if (!isObject(value))
        return null;
    try {
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null)
            return null;
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const keys = Reflect.ownKeys(descriptors);
        if (keys.some((key) => typeof key !== 'string'))
            return null;
        const record = {};
        for (const key of keys) {
            const descriptor = descriptors[key];
            if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))
                return null;
            record[key] = descriptor.value;
        }
        return record;
    }
    catch {
        return null;
    }
}
function exactKeys(value, expected) {
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length
        && actual.every((key, index) => key === wanted[index]);
}
function identifier(value) {
    return typeof value === 'string'
        && IDENTIFIER.test(value)
        && Buffer.byteLength(value, 'utf8') <= 256;
}
function digest(value) {
    return typeof value === 'string' && DIGEST.test(value);
}
function canonicalInstant(value) {
    if (typeof value !== 'string')
        return false;
    const milliseconds = Date.parse(value);
    return Number.isFinite(milliseconds)
        && new Date(milliseconds).toISOString() === value;
}
function cloneFrozen(value) {
    const clone = JSON.parse(canonicalizeAeb(value));
    if (clone === null || typeof clone !== 'object')
        return clone;
    const stack = [clone];
    while (stack.length > 0) {
        const current = stack.pop();
        for (const child of Object.values(current)) {
            if (child !== null && typeof child === 'object')
                stack.push(child);
        }
        Object.freeze(current);
    }
    return clone;
}
function secureAttemptStore(value) {
    return isObject(value)
        && value.durable === true
        && value.ownershipFenced === true
        && value.compareAndSwap === true
        && value.atomicEvidenceBinding === true
        && typeof value.reserve === 'function'
        && typeof value.transition === 'function'
        && typeof value.reconcile === 'function';
}
function validEvidence(value) {
    const record = dataRecord(value);
    return record !== null
        && exactKeys(record, ['evidence_id', 'observed_at', 'evidence_digest'])
        && identifier(record.evidence_id)
        && canonicalInstant(record.observed_at)
        && digest(record.evidence_digest);
}
function normalizeEffectOutcome(value) {
    const record = dataRecord(value);
    if (!record || !identifier(record.state))
        return null;
    if (record.state === 'INDETERMINATE') {
        return exactKeys(record, ['state', 'reason']) && identifier(record.reason)
            ? { state: 'INDETERMINATE', reason: record.reason }
            : null;
    }
    if (record.state === 'EXECUTED') {
        return exactKeys(record, ['state', 'evidence', 'result'])
            && validEvidence(record.evidence)
            ? {
                state: 'EXECUTED',
                evidence: cloneFrozen(record.evidence),
                result: record.result,
            }
            : null;
    }
    if (record.state === 'FAILED') {
        return exactKeys(record, ['state', 'evidence', 'reason'])
            && validEvidence(record.evidence)
            && identifier(record.reason)
            ? {
                state: 'FAILED',
                evidence: cloneFrozen(record.evidence),
                reason: record.reason,
            }
            : null;
    }
    return null;
}
function publicAttempt(attempt) {
    const { owner: _owner, ...binding } = attempt;
    return cloneFrozen(binding);
}
function validAttemptBinding(value) {
    const record = dataRecord(value);
    return record !== null
        && exactKeys(record, [
            'tenant_id',
            'provider_id',
            'provider_account_id',
            'environment',
            'attempt_id',
            'request_digest',
            'provider_idempotency_key',
        ])
        && identifier(record.tenant_id)
        && identifier(record.provider_id)
        && identifier(record.provider_account_id)
        && identifier(record.environment)
        && identifier(record.attempt_id)
        && digest(record.request_digest)
        && identifier(record.provider_idempotency_key);
}
function opaqueOwner(value) {
    return typeof value === 'string'
        && Buffer.byteLength(value, 'utf8') >= 16
        && Buffer.byteLength(value, 'utf8') <= 1024
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function validAttemptReference(value) {
    const record = dataRecord(value);
    if (!record || !exactKeys(record, [
        'tenant_id',
        'provider_id',
        'provider_account_id',
        'environment',
        'attempt_id',
        'request_digest',
        'provider_idempotency_key',
        'owner',
    ]) || !opaqueOwner(record.owner))
        return false;
    const { owner: _owner, ...binding } = record;
    return validAttemptBinding(binding);
}
export function consequenceBoundaryRequestDigest(input) {
    return digestAeb({
        domain: `${CONSEQUENCE_BOUNDARY_VERSION}:REQUEST`,
        provider: input.provider,
        operation_id: input.operation_id,
        caid: input.caid,
        action: input.action,
        evaluation_digest: input.evaluation_digest,
        provider_idempotency_key: input.provider_idempotency_key,
    });
}
/**
 * Derive the provider retry/reconciliation key from one exact action and one
 * authorization instance. Canonical encoding avoids ambiguous concatenation;
 * provider coordinates prevent the same key from crossing provider domains.
 *
 * A deployment may claim provider-side duplicate suppression only when its
 * pinned adapter profile establishes native idempotency, a sufficient
 * retention horizon, payload-mismatch refusal, and lookup by this exact key.
 */
export function consequenceBoundaryProviderIdempotencyKey(input) {
    if (!isObject(input)
        || !isObject(input.provider)
        || !identifier(input.provider.tenant_id)
        || !identifier(input.provider.provider_id)
        || !identifier(input.provider.provider_account_id)
        || !identifier(input.provider.environment)
        || !identifier(input.caid)
        || !digest(input.action_digest)
        || typeof input.authorization_instance !== 'string'
        || !AUTHORIZATION_INSTANCE.test(input.authorization_instance)) {
        throw new TypeError('provider_idempotency_binding_invalid');
    }
    const derived = digestAeb({
        domain: CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN,
        provider: input.provider,
        caid: input.caid,
        action_digest: input.action_digest,
        authorization_instance: input.authorization_instance,
    });
    return `epcb1:${derived.slice('sha256:'.length)}`;
}
function refused(reason) {
    return Object.freeze({
        state: 'REFUSED',
        invoked: false,
        retry_allowed: false,
        reason,
    });
}
function indeterminate(reason, invoked, attempt) {
    return Object.freeze({
        state: 'INDETERMINATE',
        invoked,
        retry_allowed: false,
        reason,
        ...(attempt ? { attempt } : {}),
    });
}
/**
 * Build one relying-party-controlled consequence boundary. Presented evidence
 * never selects adapters, trust roots, requirements, or local policy.
 */
export function createConsequenceBoundary(options) {
    if (!isObject(options)
        || !identifier(options.executor_id)
        || !isObject(options.provider)
        || !identifier(options.provider.tenant_id)
        || !identifier(options.provider.provider_id)
        || !identifier(options.provider.provider_account_id)
        || !identifier(options.provider.environment)
        || !isObject(options.aeb)
        || !isObject(options.aeb.config)
        || !isObject(options.aeb.adapters)
        || !isObject(options.aeb.store)
        || !isObject(options.attempts)
        || !secureAttemptStore(options.attempts.store)
        || (options.attempts.create_id !== undefined
            && typeof options.attempts.create_id !== 'function')
        || typeof options.attempts.recover !== 'function'
        || typeof options.local_authorize !== 'function'
        || typeof options.invoke !== 'function'
        || (options.now !== undefined && typeof options.now !== 'function')) {
        throw new TypeError('consequence_boundary_configuration_invalid');
    }
    const provider = cloneFrozen(options.provider);
    const now = options.now ?? (() => new Date().toISOString());
    const createAttemptId = options.attempts.create_id
        ?? (() => `attempt:${crypto.randomUUID()}`);
    async function run(input) {
        let action;
        let evaluation;
        let evaluationDigest;
        let decisionNow;
        try {
            action = cloneFrozen(input?.action);
            evaluation = cloneFrozen(input?.evaluation);
            evaluationDigest = digestAeb(evaluation);
            decisionNow = now();
            if (!canonicalInstant(decisionNow))
                throw new Error('clock_invalid');
        }
        catch {
            return refused('execution_input_invalid');
        }
        if (evaluation.executor_id !== options.executor_id) {
            return refused('executor_binding_mismatch');
        }
        const verification = verifyAebEvaluation(evaluation, {
            mode: 'execution',
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts: input.artifacts,
            expected_action: action,
            current_statuses: input.current_statuses,
            now: decisionNow,
        });
        if (!verification.valid || !verification.execution_authorizing) {
            const composition = dataRecord(evaluation.composition);
            if (verification.checks.schema
                && verification.checks.signature
                && verification.checks.pinned_config
                && verification.checks.current_status
                && composition
                && digest(composition.action_digest)
                && composition.action_digest !== digestAeb(action)) {
                return refused('exact_action_binding_mismatch');
            }
            return refused(verification.reasons[0] ?? 'evaluation_not_verified');
        }
        let localAuthorization = false;
        try {
            localAuthorization = await options.local_authorize(cloneFrozen({
                action,
                evaluation,
                evaluation_digest: evaluationDigest,
                provider,
            })) === true;
        }
        catch {
            localAuthorization = false;
        }
        if (!localAuthorization)
            return refused('local_authorization_denied');
        const authorization = await authorizeAebExecutionDurable(evaluation, {
            verification,
            local_authorization: true,
            store: options.aeb.store,
            execution_conditions: input.execution_conditions,
            additional_replay_keys: input.additional_replay_keys,
        });
        if (!authorization.invoke_allowed || !authorization.reservation_key) {
            return authorization.state === 'RECONCILIATION_REQUIRED'
                ? indeterminate(authorization.reason, false)
                : refused(authorization.reason);
        }
        const reservationKey = authorization.reservation_key;
        const actionDigest = digestAeb(action);
        const providerIdempotencyKey = consequenceBoundaryProviderIdempotencyKey({
            provider,
            caid: evaluation.caid,
            action_digest: actionDigest,
            authorization_instance: evaluation.consumption_nonce,
        });
        const requestDigest = consequenceBoundaryRequestDigest({
            provider,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action,
            evaluation_digest: evaluationDigest,
            provider_idempotency_key: providerIdempotencyKey,
        });
        let attemptId;
        try {
            attemptId = await createAttemptId({
                operation_id: evaluation.operation_id,
                request_digest: requestDigest,
            });
            if (!identifier(attemptId))
                throw new Error('attempt_id_invalid');
        }
        catch {
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused('attempt_allocation_failed');
        }
        const attemptBinding = cloneFrozen({
            ...provider,
            attempt_id: attemptId,
            request_digest: requestDigest,
            provider_idempotency_key: providerIdempotencyKey,
        });
        let reserved;
        try {
            reserved = await options.attempts.store.reserve(attemptBinding);
        }
        catch {
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused('attempt_store_unavailable');
        }
        if (!reserved.reserved) {
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused(reserved.reason || 'attempt_conflict');
        }
        const attempt = {
            ...attemptBinding,
            owner: reserved.owner,
        };
        try {
            const started = await options.attempts.store.transition({
                ...attempt,
                expected_state: 'RESERVED',
                next_state: 'INVOKING',
            });
            if (!started) {
                await options.aeb.store.release(reservationKey).catch(() => false);
                return refused('attempt_start_conflict');
            }
        }
        catch {
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused('attempt_store_unavailable');
        }
        let rawOutcome;
        try {
            rawOutcome = await options.invoke(cloneFrozen({
                action,
                operation_id: evaluation.operation_id,
                caid: evaluation.caid,
                evaluation_digest: evaluationDigest,
                authorization_program_digest: authorization.program_digest,
                provider_idempotency_key: providerIdempotencyKey,
                attempt: attemptBinding,
            }));
        }
        catch {
            await options.attempts.store.transition({
                ...attempt,
                expected_state: 'INVOKING',
                next_state: 'INDETERMINATE',
            }).catch(() => false);
            return indeterminate('provider_outcome_indeterminate', true, publicAttempt(attempt));
        }
        const frozen = await options.attempts.store.transition({
            ...attempt,
            expected_state: 'INVOKING',
            next_state: 'INDETERMINATE',
        }).catch(() => false);
        if (!frozen) {
            return indeterminate('attempt_freeze_failed', true, publicAttempt(attempt));
        }
        const outcome = normalizeEffectOutcome(rawOutcome);
        if (!outcome) {
            return indeterminate('provider_outcome_invalid', true, publicAttempt(attempt));
        }
        if (outcome.state === 'INDETERMINATE') {
            return indeterminate(identifier(outcome.reason) ? outcome.reason : 'provider_outcome_indeterminate', true, publicAttempt(attempt));
        }
        if (!validEvidence(outcome.evidence)) {
            return indeterminate('provider_evidence_invalid', true, publicAttempt(attempt));
        }
        // A one-time authorization is burned after any provider invocation with an
        // authoritative terminal outcome. A later attempt requires a new action
        // instance and a fresh authorization, even when this attempt FAILED.
        const consumed = await reconcileAebExecutionDurable(options.aeb.store, reservationKey, 'COMMITTED');
        if (consumed.state !== 'CONSUMED') {
            return indeterminate('authorization_consumption_unconfirmed', true, publicAttempt(attempt));
        }
        const terminalState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
        const providerEvidence = cloneFrozen({
            ...attemptBinding,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action_digest: actionDigest,
            evidence_id: outcome.evidence.evidence_id,
            observed_at: outcome.evidence.observed_at,
            outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
            evidence_digest: outcome.evidence.evidence_digest,
        });
        const terminal = await options.attempts.store.reconcile({
            ...attempt,
            expected_state: 'INDETERMINATE',
            next_state: terminalState,
            evidence: providerEvidence,
        }).catch(() => false);
        if (!terminal) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, publicAttempt(attempt));
        }
        if (outcome.state === 'EXECUTED') {
            return Object.freeze({
                state: 'EXECUTED',
                invoked: true,
                retry_allowed: false,
                result: outcome.result,
                evidence: outcome.evidence,
                attempt: attemptBinding,
            });
        }
        return Object.freeze({
            state: 'FAILED',
            invoked: true,
            retry_allowed: false,
            reason: identifier(outcome.reason) ? outcome.reason : 'provider_refused_effect',
            evidence: outcome.evidence,
            attempt: attemptBinding,
        });
    }
    async function reconcile(input) {
        let action;
        let evaluation;
        let attemptBinding;
        let evaluationDigest;
        try {
            action = cloneFrozen(input?.action);
            evaluation = cloneFrozen(input?.evaluation);
            evaluationDigest = digestAeb(evaluation);
            attemptBinding = cloneFrozen(input?.attempt);
            if (!validAttemptBinding(attemptBinding))
                throw new Error('attempt_invalid');
        }
        catch {
            return refused('reconciliation_input_invalid');
        }
        if (evaluation.executor_id !== options.executor_id) {
            return refused('executor_binding_mismatch');
        }
        const verification = verifyAebEvaluation(evaluation, {
            mode: 'historical',
            config: options.aeb.config,
            adapters: options.aeb.adapters,
            artifacts: input.artifacts,
            expected_action: action,
        });
        if (!verification.valid) {
            return refused(verification.reasons[0] ?? 'evaluation_not_verified');
        }
        const expectedRequestDigest = consequenceBoundaryRequestDigest({
            provider,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action,
            evaluation_digest: evaluationDigest,
            provider_idempotency_key: consequenceBoundaryProviderIdempotencyKey({
                provider,
                caid: evaluation.caid,
                action_digest: digestAeb(action),
                authorization_instance: evaluation.consumption_nonce,
            }),
        });
        const expectedProviderIdempotencyKey = consequenceBoundaryProviderIdempotencyKey({
            provider,
            caid: evaluation.caid,
            action_digest: digestAeb(action),
            authorization_instance: evaluation.consumption_nonce,
        });
        if (attemptBinding.tenant_id !== provider.tenant_id
            || attemptBinding.provider_id !== provider.provider_id
            || attemptBinding.provider_account_id !== provider.provider_account_id
            || attemptBinding.environment !== provider.environment
            || attemptBinding.provider_idempotency_key !== expectedProviderIdempotencyKey
            || attemptBinding.request_digest !== expectedRequestDigest) {
            return refused('reconciliation_binding_mismatch');
        }
        const outcome = normalizeEffectOutcome(input.outcome);
        if (!outcome || outcome.state === 'INDETERMINATE') {
            return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
        }
        let recovered = null;
        try {
            recovered = await options.attempts.recover({
                attempt: attemptBinding,
                recovery_authorization: input.recovery_authorization,
            });
        }
        catch {
            recovered = null;
        }
        if (!validAttemptReference(recovered)) {
            return refused('attempt_recovery_refused');
        }
        const recoveredReference = cloneFrozen(recovered);
        const recoveredBinding = publicAttempt(recoveredReference);
        if (canonicalizeAeb(recoveredBinding) !== canonicalizeAeb(attemptBinding)) {
            return refused('attempt_recovery_binding_mismatch');
        }
        const reservationKey = aebReservationKey(evaluation);
        const consumed = await reconcileAebExecutionDurable(options.aeb.store, reservationKey, 'COMMITTED');
        if (consumed.state !== 'CONSUMED') {
            return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
        }
        const providerEvidence = cloneFrozen({
            ...attemptBinding,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action_digest: digestAeb(action),
            evidence_id: outcome.evidence.evidence_id,
            observed_at: outcome.evidence.observed_at,
            outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
            evidence_digest: outcome.evidence.evidence_digest,
        });
        const terminal = await options.attempts.store.reconcile({
            ...recoveredReference,
            expected_state: 'INDETERMINATE',
            next_state: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED',
            evidence: providerEvidence,
        }).catch(() => false);
        if (!terminal) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
        }
        if (outcome.state === 'EXECUTED') {
            return Object.freeze({
                state: 'EXECUTED',
                invoked: true,
                retry_allowed: false,
                result: outcome.result,
                evidence: outcome.evidence,
                attempt: attemptBinding,
            });
        }
        return Object.freeze({
            state: 'FAILED',
            invoked: true,
            retry_allowed: false,
            reason: outcome.reason,
            evidence: outcome.evidence,
            attempt: attemptBinding,
        });
    }
    return Object.freeze({
        version: CONSEQUENCE_BOUNDARY_VERSION,
        executor_id: options.executor_id,
        provider,
        run,
        reconcile,
    });
}
export default Object.freeze({
    CONSEQUENCE_BOUNDARY_VERSION,
    CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN,
    consequenceBoundaryProviderIdempotencyKey,
    consequenceBoundaryRequestDigest,
    createConsequenceBoundary,
});
//# sourceMappingURL=consequence-boundary.js.map