// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. The direct path verifies a relying-party-
 * pinned gateway handoff; it does not re-verify the native permit or artifact.
 * The boundary durably fences every native replay unit and every exact action
 * while an attempt for it is in flight, records dispatch custody, and invokes
 * one provider adapter. It does not acquire approvals, mint authority, or
 * require an EMILIA receipt.
 */
import crypto from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import { aebReservationKey, authorizeAebExecutionDurable, canonicalizeAeb, digestAeb, reconcileAebExecutionDurable, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { verifyAebNativeAuthorizationHandoff, } from '@emilia-protocol/verify/aeb';
export const CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-CONSEQUENCE-BOUNDARY-v1';
export const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = 'EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1';
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const AUTHORIZATION_INSTANCE = /^[A-Za-z0-9_.:-]{1,256}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
// canonicalizeStrictJson refuses more than 100000 nodes, so a walk that
// exceeds this budget is refused rather than completed.
const PROXY_SCAN_NODE_BUDGET = 100_001;
/**
 * True when a Proxy appears anywhere in a caller value. Detection does not
 * run traps; the walk reads descriptors of ordinary objects only. A Proxy can
 * answer descriptor reads faithfully while its other traps misbehave, so the
 * boundary refuses it instead of reasoning about which reads are safe.
 */
function containsProxy(value) {
    const seen = new Set();
    const stack = [value];
    let nodes = 0;
    while (stack.length > 0) {
        const current = stack.pop();
        if (current === null || (typeof current !== 'object' && typeof current !== 'function'))
            continue;
        if (nodeTypes.isProxy(current))
            return true;
        if (seen.has(current))
            continue;
        seen.add(current);
        nodes += 1;
        if (nodes > PROXY_SCAN_NODE_BUDGET)
            return true;
        try {
            const descriptors = Object.getOwnPropertyDescriptors(current);
            for (const key of Reflect.ownKeys(descriptors)) {
                const descriptor = descriptors[key];
                if (Object.hasOwn(descriptor, 'value'))
                    stack.push(descriptor.value);
            }
        }
        catch {
            return true;
        }
    }
    return false;
}
function dataRecord(value) {
    if (!isObject(value) || nodeTypes.isProxy(value))
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
            // Assignment would route an own "__proto__" member through the
            // prototype setter and hide it from exact-key checks. defineProperty
            // keeps it as an ordinary own member, so closed shapes refuse it.
            Object.defineProperty(record, key, {
                value: descriptor.value,
                enumerable: true,
                writable: true,
                configurable: true,
            });
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
function secureConsequenceEnvelope(value) {
    return isObject(value)
        && (value.guaranteeClass === 'durable-local-atomic'
            || value.guaranteeClass === 'test-only-process-local')
        && isObject(value.envelope)
        && typeof value.envelope_digest === 'string'
        && typeof value.reserve === 'function'
        && typeof value.beginProviderEntry === 'function'
        && typeof value.releaseNotEntered === 'function'
        && typeof value.settle === 'function'
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
function normalizeEffectOutcome(value, snapshotResult = false) {
    const record = dataRecord(value);
    if (!record || !identifier(record.state))
        return null;
    if (record.state === 'INDETERMINATE') {
        return exactKeys(record, ['state', 'reason']) && identifier(record.reason)
            ? { state: 'INDETERMINATE', reason: record.reason }
            : null;
    }
    if (record.state === 'EXECUTED') {
        if (!exactKeys(record, ['state', 'evidence', 'result'])
            || !validEvidence(record.evidence))
            return null;
        if (!snapshotResult) {
            return {
                state: 'EXECUTED',
                evidence: cloneFrozen(record.evidence),
                result: record.result,
            };
        }
        try {
            return {
                state: 'EXECUTED',
                evidence: cloneFrozen(record.evidence),
                result: cloneFrozen(record.result),
            };
        }
        catch {
            return null;
        }
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
const NATIVE_ATTEMPT_BINDING_KEYS = [
    'tenant_id',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'request_digest',
    'provider_idempotency_key',
    'operation_id',
    'action_digest',
    'handoff_digest',
    'native_replay_unit',
    'trust_snapshot_id',
    'trust_snapshot_digest',
    'authorization_program_digest',
    'local_authorization_program_digest',
    'local_decision_digest',
    'local_decided_at',
    'provider_outcome_verification_program_digest',
];
function validNativeAttemptBinding(value) {
    const record = dataRecord(value);
    return record !== null
        && exactKeys(record, NATIVE_ATTEMPT_BINDING_KEYS)
        && identifier(record.tenant_id)
        && identifier(record.provider_id)
        && identifier(record.provider_account_id)
        && identifier(record.environment)
        && identifier(record.attempt_id)
        && digest(record.request_digest)
        && identifier(record.provider_idempotency_key)
        && identifier(record.operation_id)
        && digest(record.action_digest)
        && digest(record.handoff_digest)
        && digest(record.native_replay_unit)
        && identifier(record.trust_snapshot_id)
        && digest(record.trust_snapshot_digest)
        && digest(record.authorization_program_digest)
        && digest(record.local_authorization_program_digest)
        && digest(record.local_decision_digest)
        && canonicalInstant(record.local_decided_at)
        && digest(record.provider_outcome_verification_program_digest);
}
function validNativeAttemptReference(value) {
    const record = dataRecord(value);
    if (!record || !exactKeys(record, [...NATIVE_ATTEMPT_BINDING_KEYS, 'owner'])
        || !opaqueOwner(record.owner))
        return false;
    const { owner: _owner, ...binding } = record;
    return validNativeAttemptBinding(binding);
}
function publicNativeAttempt(attempt) {
    const { owner: _owner, ...binding } = attempt;
    return cloneFrozen(binding);
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
function secureAebConsumptionStore(value) {
    return isObject(value)
        && value.durable === true
        && value.ownershipFenced === true
        && value.permanentConsumption === true
        && value.atomicReplayFenced === true
        && typeof value.reserve === 'function'
        && typeof value.commit === 'function'
        && typeof value.release === 'function';
}
function secureNativeConsumptionStore(value) {
    return secureAebConsumptionStore(value)
        && isObject(value)
        && typeof value.state === 'function';
}
function secureNativeAttemptStore(value) {
    return secureAttemptStore(value)
        && isObject(value)
        && typeof value.state === 'function';
}
function nativeTrustSnapshotDigest(pins) {
    return digestAeb({
        domain: NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN,
        pins,
    });
}
export function nativeConsequenceBoundaryReservationKey(input) {
    if (!identifier(input?.relying_party_id) || !identifier(input?.operation_id)
        || !digest(input?.action_digest)) {
        throw new TypeError('native_consequence_reservation_binding_invalid');
    }
    return `aeb-native-operation:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:RESERVATION`,
        relying_party_id: input.relying_party_id,
        operation_id: input.operation_id,
        action_digest: input.action_digest,
    })}`;
}
export function nativeConsequenceBoundaryProviderIdempotencyKey(input) {
    if (!isObject(input) || !isObject(input.provider)
        || !identifier(input.provider.tenant_id)
        || !identifier(input.provider.provider_id)
        || !identifier(input.provider.provider_account_id)
        || !identifier(input.provider.environment)
        || !digest(input.action_digest) || !digest(input.native_replay_unit)) {
        throw new TypeError('native_provider_idempotency_binding_invalid');
    }
    const derived = digestAeb({
        domain: NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN,
        provider: input.provider,
        action_digest: input.action_digest,
        native_replay_unit: input.native_replay_unit,
    });
    return `epnb1:${derived.slice('sha256:'.length)}`;
}
export function nativeConsequenceBoundaryRequestDigest(input) {
    return digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:REQUEST`,
        provider: input.provider,
        operation_id: input.operation_id,
        action: input.action,
        action_digest: input.action_digest,
        handoff_digest: input.handoff_digest,
        native_replay_unit: input.native_replay_unit,
        trust_snapshot_id: input.trust_snapshot_id,
        trust_snapshot_digest: input.trust_snapshot_digest,
        authorization_program_digest: input.authorization_program_digest,
        local_authorization: input.local_authorization,
        provider_outcome_verification_program_digest: input.provider_outcome_verification_program_digest,
        provider_idempotency_key: input.provider_idempotency_key,
    });
}
function providerCoordinates(value) {
    const record = dataRecord(value);
    if (!record
        || !exactKeys(record, ['tenant_id', 'provider_id', 'provider_account_id', 'environment'])
        || !identifier(record.tenant_id)
        || !identifier(record.provider_id)
        || !identifier(record.provider_account_id)
        || !identifier(record.environment))
        return null;
    return {
        tenant_id: record.tenant_id,
        provider_id: record.provider_id,
        provider_account_id: record.provider_account_id,
        environment: record.environment,
    };
}
/**
 * Durable identity of one exact action at one effecting target: the relying
 * party, the provider coordinates the boundary invokes, and the canonical
 * action digest. While an attempt for this identity is RESERVED, INVOKING, or
 * INDETERMINATE, a new attempt is refused as `native_action_in_flight` even
 * when it carries a fresh native authorization and a fresh operation ID.
 * Intentional repeats must differ in the canonical action itself, for example
 * through a caller-chosen instance field that the action digest covers.
 */
export function nativeConsequenceBoundaryActionFenceKey(input) {
    const record = dataRecord(input);
    const provider = record ? providerCoordinates(record.provider) : null;
    if (!record || !provider || !identifier(record.relying_party_id)
        || !digest(record.action_digest)) {
        throw new TypeError('native_action_fence_binding_invalid');
    }
    return `aeb-native-action:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE`,
        relying_party_id: record.relying_party_id,
        provider,
        action_digest: record.action_digest,
    })}`;
}
/**
 * Consumption-store key of the reservation that holds the action fence for
 * one operation. It is derived from the operation reservation key, so a
 * reconciliation can only ever close the fence holder of its own operation,
 * never the holder of a later attempt for the same action.
 */
export function nativeConsequenceBoundaryActionFenceHolderKey(input) {
    const operationKey = nativeConsequenceBoundaryReservationKey(input);
    return `aeb-native-action-holder:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE-HOLDER`,
        operation_key: operationKey,
    })}`;
}
function nativeActionExecutedMarkerKey(actionFenceKey) {
    return `aeb-native-action-executed:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-EXECUTED`,
        action_fence_key: actionFenceKey,
    })}`;
}
function deriveNativeConsumptionKeys(input) {
    try {
        const operation = nativeConsequenceBoundaryReservationKey(input);
        const holder = nativeConsequenceBoundaryActionFenceHolderKey(input);
        const actionFence = nativeConsequenceBoundaryActionFenceKey(input);
        return {
            operation,
            holder,
            action_fence: actionFence,
            executed_marker: nativeActionExecutedMarkerKey(actionFence),
        };
    }
    catch {
        return null;
    }
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
        || (options.consequence_envelope !== undefined
            && !secureConsequenceEnvelope(options.consequence_envelope))
        || (options.consequence_envelope?.guaranteeClass === 'test-only-process-local'
            && options.allow_test_consequence_envelope !== true)
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
        let envelopeReservation = null;
        if (options.consequence_envelope) {
            let capacity;
            try {
                capacity = await options.consequence_envelope.reserve({
                    operation_id: evaluation.operation_id,
                    state_domain_id: options.consequence_envelope.envelope.state_domain_id,
                    expected_epoch: options.consequence_envelope.envelope.epoch,
                    action,
                });
            }
            catch {
                capacity = { status: 'REFUSED', reason: 'consequence_envelope_unavailable' };
            }
            if (capacity.status !== 'RESERVED') {
                await options.aeb.store.release(reservationKey).catch(() => false);
                return refused(capacity.reason);
            }
            envelopeReservation = capacity.reservation;
        }
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
            if (envelopeReservation) {
                await options.consequence_envelope.releaseNotEntered(envelopeReservation).catch(() => null);
            }
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
            if (envelopeReservation) {
                await options.consequence_envelope.releaseNotEntered(envelopeReservation).catch(() => null);
            }
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused('attempt_store_unavailable');
        }
        if (!reserved.reserved) {
            if (envelopeReservation) {
                await options.consequence_envelope.releaseNotEntered(envelopeReservation).catch(() => null);
            }
            await options.aeb.store.release(reservationKey).catch(() => false);
            return refused(reserved.reason || 'attempt_conflict');
        }
        const attempt = {
            ...attemptBinding,
            owner: reserved.owner,
        };
        if (envelopeReservation) {
            const capacityEntry = await options.consequence_envelope
                .beginProviderEntry(envelopeReservation)
                .catch(() => ({ status: 'REFUSED', reason: 'consequence_envelope_unavailable' }));
            if (capacityEntry.status !== 'ENTERED') {
                const attemptReleased = await options.attempts.store.transition({
                    ...attempt,
                    expected_state: 'RESERVED',
                    next_state: 'RELEASED',
                }).catch(() => false);
                await options.consequence_envelope.releaseNotEntered(envelopeReservation).catch(() => null);
                await options.aeb.store.release(reservationKey).catch(() => false);
                return attemptReleased
                    ? refused(capacityEntry.reason)
                    : indeterminate('attempt_release_unconfirmed', false, publicAttempt(attempt));
            }
        }
        try {
            const started = await options.attempts.store.transition({
                ...attempt,
                expected_state: 'RESERVED',
                next_state: 'INVOKING',
            });
            if (!started) {
                if (envelopeReservation) {
                    await options.consequence_envelope.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
                    return indeterminate('attempt_start_conflict', false, publicAttempt(attempt));
                }
                await options.aeb.store.release(reservationKey).catch(() => false);
                return refused('attempt_start_conflict');
            }
        }
        catch {
            if (envelopeReservation) {
                await options.consequence_envelope.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
                return indeterminate('attempt_store_unavailable', false, publicAttempt(attempt));
            }
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
            if (envelopeReservation) {
                await options.consequence_envelope.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
            }
            return indeterminate('provider_outcome_indeterminate', true, publicAttempt(attempt));
        }
        const frozen = await options.attempts.store.transition({
            ...attempt,
            expected_state: 'INVOKING',
            next_state: 'INDETERMINATE',
        }).catch(() => false);
        if (!frozen) {
            if (envelopeReservation) {
                await options.consequence_envelope.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
            }
            return indeterminate('attempt_freeze_failed', true, publicAttempt(attempt));
        }
        if (envelopeReservation) {
            const held = await options.consequence_envelope
                .settle(envelopeReservation, 'INDETERMINATE')
                .catch(() => ({ status: 'REFUSED', reason: 'consequence_envelope_unavailable' }));
            if (held.status !== 'INDETERMINATE') {
                return indeterminate('consequence_envelope_indeterminate_unconfirmed', true, publicAttempt(attempt));
            }
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
        if (envelopeReservation) {
            const capacityTerminal = await options.consequence_envelope
                .settle(envelopeReservation, outcome.state === 'EXECUTED' ? 'COMMITTED' : 'PROVEN_NOT_COMMITTED')
                .catch(() => ({ status: 'REFUSED', reason: 'consequence_envelope_unavailable' }));
            const expectedCapacityState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
            if (capacityTerminal.status !== expectedCapacityState) {
                return indeterminate('consequence_envelope_terminal_unconfirmed', true, publicAttempt(attempt));
            }
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
        if (options.consequence_envelope) {
            const capacityTerminal = await options.consequence_envelope.reconcile({
                operation_id: evaluation.operation_id,
                action_digest: digestAeb(action),
                outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'PROVEN_NOT_COMMITTED',
                recovery_authorization: input.recovery_authorization,
            }).catch(() => ({ status: 'REFUSED', reason: 'consequence_envelope_unavailable' }));
            const expectedCapacityState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
            if (capacityTerminal.status !== expectedCapacityState) {
                return indeterminate('consequence_envelope_reconciliation_unconfirmed', true, attemptBinding);
            }
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
/**
 * Build the direct native path. The native system has already made the policy
 * decision; Gate verifies the pinned gateway handoff, not the native permit or
 * artifact. It applies its own operational authorization and atomically fences
 * the operation and native replay unit.
 */
export function createNativeConsequenceBoundary(options) {
    let provider;
    let pins;
    let configured = false;
    try {
        provider = cloneFrozen(options?.provider);
        pins = cloneFrozen(options?.native_authorization?.pins);
        configured = isObject(options)
            && identifier(options.executor_id)
            && isObject(provider)
            && identifier(provider.tenant_id)
            && identifier(provider.provider_id)
            && identifier(provider.provider_account_id)
            && identifier(provider.environment)
            && isObject(pins)
            // Gate derives its durable keys from the pinned relying party. The
            // verifier accepts a wider identifier grammar, so a relying party ID
            // Gate cannot key is refused here rather than failing at run time.
            && identifier(pins.relying_party_id)
            && isObject(options.native_authorization)
            && identifier(options.native_authorization.trust_snapshot_id)
            && secureNativeConsumptionStore(options.native_authorization.store)
            && typeof options.native_authorization.resolve_status === 'function'
            && typeof options.native_authorization.resolve_historical_pins === 'function'
            && pins.executor_id === options.executor_id
            && canonicalizeAeb(pins.provider) === canonicalizeAeb(provider)
            && isObject(options.attempts)
            && secureNativeAttemptStore(options.attempts.store)
            && (options.attempts.create_id === undefined
                || typeof options.attempts.create_id === 'function')
            && typeof options.attempts.recover === 'function'
            && digest(options.local_authorization_program_digest)
            && typeof options.local_authorize === 'function'
            && typeof options.invoke === 'function'
            && isObject(options.provider_outcomes)
            && digest(options.provider_outcomes.verification_program_digest)
            && typeof options.provider_outcomes.verify === 'function'
            && (options.now === undefined || typeof options.now === 'function');
    }
    catch {
        configured = false;
    }
    if (!configured) {
        throw new TypeError('native_consequence_boundary_configuration_invalid');
    }
    provider = provider;
    pins = pins;
    const store = options.native_authorization.store;
    const attemptStore = options.attempts.store;
    const executorId = options.executor_id;
    const relyingPartyId = pins.relying_party_id;
    const now = options.now?.bind(options) ?? (() => new Date().toISOString());
    const createAttemptId = options.attempts.create_id?.bind(options.attempts)
        ?? (() => `attempt:${crypto.randomUUID()}`);
    // Snapshot every security-critical callback with its original receiver. The
    // caller may retain and later mutate the configuration object; such a
    // mutation must not replace code while the attempt still records the
    // digests and trust snapshot pinned at construction.
    const resolveNativeStatus = options.native_authorization.resolve_status
        .bind(options.native_authorization);
    const resolveHistoricalPins = options.native_authorization.resolve_historical_pins
        .bind(options.native_authorization);
    const recoverAttempt = options.attempts.recover.bind(options.attempts);
    const localAuthorize = options.local_authorize.bind(options);
    const invoke = options.invoke.bind(options);
    const verifyOutcome = options.provider_outcomes.verify.bind(options.provider_outcomes);
    const readConsumptionState = store.state.bind(store);
    const reserveConsumption = store.reserve.bind(store);
    const commitConsumption = store.commit.bind(store);
    const releaseConsumption = store.release.bind(store);
    const releaseTerminalConsumption = store.terminalRelease === true
        && typeof store.releaseTerminal === 'function'
        ? store.releaseTerminal.bind(store)
        : null;
    // A store that fences commit/release to the reserving process exposes an
    // authorized claim so reconciliation after a restart can take ownership.
    const claimConsumption = store.recoveryClaimSupported === true
        && typeof store.claimReservation === 'function'
        ? store.claimReservation.bind(store)
        : null;
    const readAttemptState = attemptStore.state.bind(attemptStore);
    const reserveAttempt = attemptStore.reserve.bind(attemptStore);
    const transitionAttemptState = attemptStore.transition.bind(attemptStore);
    const reconcileAttempt = attemptStore.reconcile.bind(attemptStore);
    const trustSnapshotId = options.native_authorization.trust_snapshot_id;
    const trustSnapshotDigest = nativeTrustSnapshotDigest(pins);
    const localAuthorizationProgramDigest = options.local_authorization_program_digest;
    const providerOutcomeVerificationProgramDigest = options.provider_outcomes.verification_program_digest;
    const authorizationProgramDigest = digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:AUTHORIZATION-PROGRAM`,
        executor_id: executorId,
        provider,
        trust_snapshot_id: trustSnapshotId,
        trust_snapshot_digest: trustSnapshotDigest,
        local_authorization_program_digest: localAuthorizationProgramDigest,
        provider_outcome_verification_program_digest: providerOutcomeVerificationProgramDigest,
    });
    function deriveAuthorizationProgramDigest(input) {
        return digestAeb({
            domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:AUTHORIZATION-PROGRAM`,
            executor_id: executorId,
            provider,
            ...input,
        });
    }
    function deriveLocalDecision(input) {
        const decision = {
            decision: 'PERMIT',
            decided_at: input.decided_at,
            program_digest: input.program_digest,
            decision_digest: digestAeb({
                domain: NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN,
                decision: 'PERMIT',
                decided_at: input.decided_at,
                program_digest: input.program_digest,
                executor_id: executorId,
                provider,
                action_digest: input.action_digest,
                handoff_digest: input.handoff_digest,
                native_replay_unit: input.native_replay_unit,
            }),
        };
        return cloneFrozen(decision);
    }
    async function consumptionState(key) {
        try {
            const state = await readConsumptionState(key);
            return state === 'AVAILABLE' || state === 'RESERVED'
                || state === 'CONSUMED' || state === 'RELEASED_NOT_ENTERED'
                ? state
                : null;
        }
        catch {
            return null;
        }
    }
    async function closeConsumption(key, target) {
        const before = await consumptionState(key);
        if (before === target)
            return true;
        if (before !== 'RESERVED')
            return false;
        try {
            if (target === 'CONSUMED')
                await commitConsumption(key);
            else if (releaseTerminalConsumption) {
                await releaseTerminalConsumption(key);
            }
            else {
                return false;
            }
        }
        catch {
            // A lost acknowledgement is resolved by the durable state read below.
        }
        return await consumptionState(key) === target;
    }
    /** Delete an open reservation and every fence it holds; AVAILABLE after. */
    async function releaseReservation(key) {
        const before = await consumptionState(key);
        if (before === 'AVAILABLE')
            return true;
        if (before !== 'RESERVED')
            return false;
        try {
            await releaseConsumption(key);
        }
        catch { /* confirm through state */ }
        return await consumptionState(key) === 'AVAILABLE';
    }
    /**
     * Take ownership of a RESERVED row through the store's authorized recovery
     * path. Only reconciliation calls this, after it has authenticated the
     * attempt, its historical trust snapshot, and the provider outcome.
     */
    async function claimForRecovery(key, recoveryAuthorization) {
        if (!claimConsumption || await consumptionState(key) !== 'RESERVED')
            return false;
        try {
            return await claimConsumption(key, recoveryAuthorization) === true;
        }
        catch {
            return false;
        }
    }
    async function closeConsumptionForRecovery(key, target, recoveryAuthorization) {
        if (await closeConsumption(key, target))
            return true;
        if (!await claimForRecovery(key, recoveryAuthorization))
            return false;
        return closeConsumption(key, target);
    }
    async function releaseReservationForRecovery(key, recoveryAuthorization) {
        if (await releaseReservation(key))
            return true;
        if (!await claimForRecovery(key, recoveryAuthorization))
            return false;
        return releaseReservation(key);
    }
    /** Pre-entry release: the fence holder first, then the operation. */
    async function releaseNotEntered(keys) {
        const fenceReleased = await releaseReservation(keys.holder);
        const authorizationReleased = await releaseReservation(keys.operation);
        return fenceReleased && authorizationReleased;
    }
    async function actionFenceRefusal(keys) {
        return await consumptionState(keys.executed_marker) === 'CONSUMED'
            ? 'native_action_already_executed'
            : 'native_action_in_flight';
    }
    async function markActionExecuted(keys) {
        // Diagnostic only: it lets a later refusal say "already executed" rather
        // than "in flight". The fence itself is the committed holder reservation.
        try {
            const marker = await reserveConsumption(keys.executed_marker, []);
            if (marker === true || marker === 'RESERVED')
                await commitConsumption(keys.executed_marker);
        }
        catch {
            // The committed fence keeps the action closed without the marker.
        }
    }
    async function attemptState(reference) {
        try {
            const snapshot = dataRecord(await readAttemptState(reference));
            if (!snapshot
                || typeof snapshot.state !== 'string'
                || !['RESERVED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'RELEASED']
                    .includes(snapshot.state))
                return null;
            const state = snapshot.state;
            if (snapshot.evidence === undefined)
                return { state };
            return { state, evidence: cloneFrozen(snapshot.evidence) };
        }
        catch {
            return null;
        }
    }
    async function transitionAttempt(reference, expected, next) {
        const before = await attemptState(reference);
        if (before?.state === next)
            return true;
        if (before?.state !== expected)
            return false;
        try {
            await transitionAttemptState({
                ...reference,
                expected_state: expected,
                next_state: next,
            });
        }
        catch {
            // A lost acknowledgement is resolved by the durable state read below.
        }
        return (await attemptState(reference))?.state === next;
    }
    function terminalRecordMatches(snapshot, next, evidence) {
        try {
            return snapshot?.state === next
                && snapshot.evidence !== undefined
                && canonicalizeAeb(snapshot.evidence) === canonicalizeAeb(evidence);
        }
        catch {
            return false;
        }
    }
    async function closeAttempt(reference, next, evidence) {
        let current = await attemptState(reference);
        if (terminalRecordMatches(current, next, evidence))
            return true;
        if (current?.state !== 'INDETERMINATE')
            return false;
        try {
            await reconcileAttempt({
                ...reference,
                expected_state: 'INDETERMINATE',
                next_state: next,
                evidence,
            });
        }
        catch {
            // A lost acknowledgement is resolved by the durable state read below.
        }
        current = await attemptState(reference);
        return terminalRecordMatches(current, next, evidence);
    }
    async function verifyProviderOutcome(attempt, outcome) {
        try {
            return await verifyOutcome(cloneFrozen({
                provider,
                operation_id: attempt.operation_id,
                action_digest: attempt.action_digest,
                native_replay_unit: attempt.native_replay_unit,
                verification_program_digest: attempt.provider_outcome_verification_program_digest,
                attempt,
                outcome,
            })) === true;
        }
        catch {
            return false;
        }
    }
    function providerEvidence(attemptBinding, outcome) {
        return cloneFrozen({
            ...attemptBinding,
            evidence_id: outcome.evidence.evidence_id,
            observed_at: outcome.evidence.observed_at,
            outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
            evidence_digest: outcome.evidence.evidence_digest,
        });
    }
    /**
     * Close the action fence once the provider outcome is authenticated.
     * EXECUTED keeps it closed for this exact action; an authenticated FAILED
     * releases it so a fresh native authorization may retry the same action.
     */
    async function closeActionFence(keys, executed, recoveryAuthorization) {
        if (executed) {
            // A holder left RESERVED still fences the action, so an unconfirmed
            // commit here cannot reopen it.
            if (recoveryAuthorization === undefined)
                await closeConsumption(keys.holder, 'CONSUMED');
            else
                await closeConsumptionForRecovery(keys.holder, 'CONSUMED', recoveryAuthorization);
            await markActionExecuted(keys);
            return true;
        }
        return recoveryAuthorization === undefined
            ? releaseReservation(keys.holder)
            : releaseReservationForRecovery(keys.holder, recoveryAuthorization);
    }
    function terminalResult(outcome, attemptBinding) {
        if (outcome.state === 'EXECUTED') {
            return Object.freeze({
                state: 'EXECUTED', invoked: true, retry_allowed: false,
                result: outcome.result, evidence: outcome.evidence, attempt: attemptBinding,
            });
        }
        return Object.freeze({
            state: 'FAILED', invoked: true, retry_allowed: false,
            reason: outcome.reason, evidence: outcome.evidence, attempt: attemptBinding,
        });
    }
    async function run(input) {
        let action;
        let handoff;
        let operationId;
        let decisionNow;
        try {
            const record = dataRecord(input);
            if (!record || !exactKeys(record, ['operation_id', 'handoff', 'action'])
                || containsProxy(record)) {
                throw new Error('native_execution_input_invalid');
            }
            action = cloneFrozen(record.action);
            handoff = cloneFrozen(record.handoff);
            operationId = record.operation_id;
            decisionNow = now();
            if (!identifier(operationId) || !canonicalInstant(decisionNow)) {
                throw new Error('native_execution_input_invalid');
            }
        }
        catch {
            return refused('native_execution_input_invalid');
        }
        const preflight = verifyAebNativeAuthorizationHandoff(handoff, {
            mode: 'historical',
            pins,
            expected_action: action,
            now: decisionNow,
        });
        if (!preflight.valid || !preflight.handoff || !preflight.action_digest
            || !preflight.native_replay_unit || !preflight.replay_key) {
            return refused(preflight.reasons[0] ?? 'native_handoff_not_verified');
        }
        let status;
        try {
            status = cloneFrozen(await resolveNativeStatus(preflight.handoff));
        }
        catch {
            return refused('native_status_resolution_failed');
        }
        const verification = verifyAebNativeAuthorizationHandoff(handoff, {
            mode: 'execution',
            pins,
            expected_action: action,
            status,
            now: decisionNow,
        });
        if (!verification.valid || !verification.execution_authorizing
            || !verification.handoff || !verification.action_digest
            || !verification.native_replay_unit || !verification.replay_key) {
            return refused(verification.reasons[0] ?? 'native_handoff_not_verified');
        }
        // Derive every durable key before any callback or store write, so a
        // binding Gate cannot key is a refusal with no side effect.
        const derivedKeys = deriveNativeConsumptionKeys({
            relying_party_id: relyingPartyId,
            provider,
            operation_id: operationId,
            action_digest: verification.action_digest,
        });
        if (!derivedKeys || verification.handoff.relying_party_id !== relyingPartyId) {
            return refused('native_consequence_binding_invalid');
        }
        const keys = derivedKeys;
        let providerIdempotencyKey;
        try {
            providerIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
                provider,
                action_digest: verification.action_digest,
                native_replay_unit: verification.native_replay_unit,
            });
        }
        catch {
            return refused('native_consequence_binding_invalid');
        }
        let localAuthorization = false;
        try {
            localAuthorization = await localAuthorize(cloneFrozen({
                action,
                handoff: verification.handoff,
                verification,
                provider,
                local_authorization_program_digest: localAuthorizationProgramDigest,
            })) === true;
        }
        catch {
            localAuthorization = false;
        }
        if (!localAuthorization)
            return refused('local_authorization_denied');
        let localDecidedAt;
        try {
            localDecidedAt = now();
            if (!canonicalInstant(localDecidedAt))
                throw new Error('clock_invalid');
        }
        catch {
            return refused('native_local_decision_time_invalid');
        }
        const localDecision = deriveLocalDecision({
            decided_at: localDecidedAt,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_unit,
            program_digest: localAuthorizationProgramDigest,
        });
        // 1. The operation reservation atomically claims the operation ID and the
        //    native replay key derived from (namespace, issuer, authorization ID).
        try {
            const reservation = await reserveConsumption(keys.operation, [verification.replay_key]);
            if (reservation !== true && reservation !== 'RESERVED') {
                return refused(reservation === 'NATIVE_REPLAY_CONFLICT'
                    ? 'native_replay_conflict'
                    : 'consumption_conflict');
            }
        }
        catch {
            const released = await releaseReservation(keys.operation);
            return released
                ? refused('consumption_store_unavailable')
                : indeterminate('consumption_reservation_state_unconfirmed', false);
        }
        // 2. The holder reservation claims the exact-action fence. Another
        //    attempt for the same action that is RESERVED, INVOKING, or
        //    INDETERMINATE (or EXECUTED) already holds it.
        let fenceReservation;
        try {
            fenceReservation = await reserveConsumption(keys.holder, [keys.action_fence]);
        }
        catch {
            const released = await releaseNotEntered(keys);
            return released
                ? refused('consumption_store_unavailable')
                : indeterminate('consumption_reservation_state_unconfirmed', false);
        }
        if (fenceReservation !== true && fenceReservation !== 'RESERVED') {
            // Never release a holder this call did not reserve.
            const released = await releaseReservation(keys.operation);
            return released
                ? refused(await actionFenceRefusal(keys))
                : indeterminate('native_pre_entry_release_unconfirmed', false);
        }
        const requestDigest = nativeConsequenceBoundaryRequestDigest({
            provider,
            operation_id: operationId,
            action,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_unit,
            trust_snapshot_id: trustSnapshotId,
            trust_snapshot_digest: trustSnapshotDigest,
            authorization_program_digest: authorizationProgramDigest,
            local_authorization: localDecision,
            provider_outcome_verification_program_digest: providerOutcomeVerificationProgramDigest,
            provider_idempotency_key: providerIdempotencyKey,
        });
        let attemptId;
        try {
            attemptId = await createAttemptId({
                operation_id: operationId,
                request_digest: requestDigest,
            });
            if (!identifier(attemptId))
                throw new Error('attempt_id_invalid');
        }
        catch {
            const released = await releaseNotEntered(keys);
            return released
                ? refused('attempt_allocation_failed')
                : indeterminate('native_pre_entry_release_unconfirmed', false);
        }
        const attemptBinding = cloneFrozen({
            ...provider,
            attempt_id: attemptId,
            request_digest: requestDigest,
            provider_idempotency_key: providerIdempotencyKey,
            operation_id: operationId,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_unit,
            trust_snapshot_id: trustSnapshotId,
            trust_snapshot_digest: trustSnapshotDigest,
            authorization_program_digest: authorizationProgramDigest,
            local_authorization_program_digest: localAuthorizationProgramDigest,
            local_decision_digest: localDecision.decision_digest,
            local_decided_at: localDecision.decided_at,
            provider_outcome_verification_program_digest: providerOutcomeVerificationProgramDigest,
        });
        let owner;
        try {
            const reserved = dataRecord(await reserveAttempt(attemptBinding));
            if (reserved?.reserved !== true || !opaqueOwner(reserved.owner)) {
                const released = await releaseNotEntered(keys);
                return released
                    ? refused(identifier(reserved?.reason) ? reserved.reason : 'attempt_conflict')
                    : indeterminate('native_pre_entry_release_unconfirmed', false);
            }
            owner = reserved.owner;
        }
        catch {
            const released = await releaseNotEntered(keys);
            return released
                ? refused('attempt_store_unavailable')
                : indeterminate('native_pre_entry_release_unconfirmed', false);
        }
        const attempt = {
            ...attemptBinding,
            owner,
        };
        // Reservations are released only after the attempt itself is durably
        // RELEASED. An attempt that is still RESERVED or INVOKING keeps both the
        // native authorization and the action fence, so no later attempt can
        // reuse its operation key while it could still be reconciled.
        async function refuseBeforeEntry(expected, reason) {
            const attemptReleased = await transitionAttempt(attempt, expected, 'RELEASED');
            const reservationsReleased = attemptReleased && await releaseNotEntered(keys);
            return attemptReleased && reservationsReleased
                ? refused(reason)
                : indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
        }
        let entryVerification;
        try {
            const entryStatus = cloneFrozen(await resolveNativeStatus(verification.handoff));
            const entryNow = now();
            if (!canonicalInstant(entryNow))
                throw new Error('clock_invalid');
            entryVerification = verifyAebNativeAuthorizationHandoff(verification.handoff, {
                mode: 'execution',
                pins,
                expected_action: action,
                status: entryStatus,
                now: entryNow,
            });
        }
        catch {
            entryVerification = {
                ...verification,
                valid: false,
                execution_authorizing: false,
                reasons: ['native_status_resolution_failed'],
            };
        }
        if (!entryVerification.valid || !entryVerification.execution_authorizing) {
            return refuseBeforeEntry('RESERVED', entryVerification.reasons[0] ?? 'native_handoff_not_verified_at_provider_entry');
        }
        const started = await transitionAttempt(attempt, 'RESERVED', 'INVOKING');
        if (!started) {
            return indeterminate('attempt_start_unconfirmed', false, publicNativeAttempt(attempt));
        }
        // The custody transition itself can block. Resolve status once more after
        // it completes so no delayed store call can carry stale authority into the
        // provider callback.
        let providerEntryVerification;
        try {
            const providerEntryStatus = cloneFrozen(await resolveNativeStatus(verification.handoff));
            const providerEntryNow = now();
            if (!canonicalInstant(providerEntryNow))
                throw new Error('clock_invalid');
            providerEntryVerification = verifyAebNativeAuthorizationHandoff(verification.handoff, {
                mode: 'execution',
                pins,
                expected_action: action,
                status: providerEntryStatus,
                now: providerEntryNow,
            });
        }
        catch {
            providerEntryVerification = {
                ...verification,
                valid: false,
                execution_authorizing: false,
                reasons: ['native_status_resolution_failed'],
            };
        }
        if (!providerEntryVerification.valid
            || !providerEntryVerification.execution_authorizing) {
            return refuseBeforeEntry('INVOKING', providerEntryVerification.reasons[0]
                ?? 'native_handoff_not_verified_at_provider_entry');
        }
        let rawOutcome;
        try {
            rawOutcome = await invoke(cloneFrozen({
                action,
                operation_id: operationId,
                action_digest: verification.action_digest,
                handoff_digest: verification.record_digest,
                native_replay_unit: verification.native_replay_unit,
                authorization_program_digest: authorizationProgramDigest,
                local_authorization: localDecision,
                trust_snapshot_id: trustSnapshotId,
                trust_snapshot_digest: trustSnapshotDigest,
                provider_outcome_verification_program_digest: providerOutcomeVerificationProgramDigest,
                provider_idempotency_key: providerIdempotencyKey,
                attempt: attemptBinding,
            }));
        }
        catch {
            await transitionAttempt(attempt, 'INVOKING', 'INDETERMINATE');
            return indeterminate('provider_outcome_indeterminate', true, publicNativeAttempt(attempt));
        }
        const frozen = await transitionAttempt(attempt, 'INVOKING', 'INDETERMINATE');
        if (!frozen)
            return indeterminate('attempt_freeze_failed', true, publicNativeAttempt(attempt));
        const outcome = normalizeEffectOutcome(rawOutcome, true);
        if (!outcome)
            return indeterminate('provider_outcome_invalid', true, publicNativeAttempt(attempt));
        if (outcome.state === 'INDETERMINATE') {
            return indeterminate(outcome.reason, true, publicNativeAttempt(attempt));
        }
        if (!await verifyProviderOutcome(attemptBinding, outcome)) {
            return indeterminate('provider_outcome_authentication_failed', true, publicNativeAttempt(attempt));
        }
        // Any terminal provider result follows provider entry and therefore burns
        // the one-time native authorization, including authenticated NOT_COMMITTED.
        if (!await closeConsumption(keys.operation, 'CONSUMED')) {
            return indeterminate('authorization_consumption_unconfirmed', true, publicNativeAttempt(attempt));
        }
        // The fence closes before the terminal record, so an unconfirmed release
        // leaves the attempt INDETERMINATE and any authenticated reconciliation
        // can finish it. The holder is scoped to this operation, so a repeated
        // close can never reach a later attempt's fence.
        if (!await closeActionFence(keys, outcome.state === 'EXECUTED')) {
            return indeterminate('native_action_fence_release_unconfirmed', true, publicNativeAttempt(attempt));
        }
        const evidence = providerEvidence(attemptBinding, outcome);
        const terminal = await closeAttempt(attempt, outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED', evidence);
        if (!terminal) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, publicNativeAttempt(attempt));
        }
        return terminalResult(outcome, attemptBinding);
    }
    const RECONCILE_KEYS = [
        'operation_id', 'handoff', 'action', 'attempt', 'outcome', 'recovery_authorization',
    ];
    async function reconcile(input) {
        let action;
        let handoff;
        let attemptBinding;
        let operationId;
        let decisionNow;
        let rawOutcome;
        let recoveryAuthorization;
        try {
            // One read of the caller's object: getters, Proxy traps, and an own
            // "__proto__" member are refused here rather than read later.
            const record = dataRecord(input);
            if (!record
                || containsProxy(record)
                || !Object.keys(record).every((key) => RECONCILE_KEYS.includes(key))
                || !['operation_id', 'handoff', 'action', 'attempt', 'outcome']
                    .every((key) => Object.hasOwn(record, key))) {
                throw new Error('input_invalid');
            }
            action = cloneFrozen(record.action);
            handoff = cloneFrozen(record.handoff);
            attemptBinding = cloneFrozen(record.attempt);
            operationId = record.operation_id;
            rawOutcome = record.outcome;
            recoveryAuthorization = record.recovery_authorization;
            decisionNow = now();
            if (!identifier(operationId) || !canonicalInstant(decisionNow)
                || !validNativeAttemptBinding(attemptBinding))
                throw new Error('input_invalid');
        }
        catch {
            return refused('native_reconciliation_input_invalid');
        }
        if (attemptBinding.tenant_id !== provider.tenant_id
            || attemptBinding.provider_id !== provider.provider_id
            || attemptBinding.provider_account_id !== provider.provider_account_id
            || attemptBinding.environment !== provider.environment
            || attemptBinding.operation_id !== operationId) {
            return refused('reconciliation_binding_mismatch');
        }
        // Authenticate custody before the caller-controlled attempt can select a
        // historical trust snapshot or provider-outcome verifier version.
        let recovered = null;
        try {
            recovered = await recoverAttempt({
                attempt: attemptBinding,
                recovery_authorization: recoveryAuthorization,
            });
        }
        catch {
            recovered = null;
        }
        if (!validNativeAttemptReference(recovered))
            return refused('attempt_recovery_refused');
        let recoveredReference;
        try {
            recoveredReference = cloneFrozen(recovered);
            if (canonicalizeAeb(publicNativeAttempt(recoveredReference))
                !== canonicalizeAeb(attemptBinding)) {
                return refused('attempt_recovery_binding_mismatch');
            }
        }
        catch {
            return refused('attempt_recovery_refused');
        }
        let historicalPins = null;
        try {
            historicalPins = await resolveHistoricalPins({
                trust_snapshot_id: attemptBinding.trust_snapshot_id,
                trust_snapshot_digest: attemptBinding.trust_snapshot_digest,
            });
            if (historicalPins !== null)
                historicalPins = cloneFrozen(historicalPins);
        }
        catch {
            historicalPins = null;
        }
        if (!historicalPins)
            return refused('native_historical_trust_snapshot_unavailable');
        if (nativeTrustSnapshotDigest(historicalPins) !== attemptBinding.trust_snapshot_digest) {
            return refused('native_historical_trust_snapshot_mismatch');
        }
        const verification = verifyAebNativeAuthorizationHandoff(handoff, {
            mode: 'historical',
            pins: historicalPins,
            expected_action: action,
            now: decisionNow,
        });
        if (!verification.valid || !verification.handoff || !verification.action_digest
            || !verification.native_replay_unit) {
            return refused(verification.reasons[0] ?? 'native_handoff_not_verified');
        }
        const derivedKeys = deriveNativeConsumptionKeys({
            relying_party_id: verification.handoff.relying_party_id,
            provider,
            operation_id: operationId,
            action_digest: verification.action_digest,
        });
        if (!derivedKeys)
            return refused('native_consequence_binding_invalid');
        const keys = derivedKeys;
        let expectedProviderIdempotencyKey;
        try {
            expectedProviderIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
                provider,
                action_digest: verification.action_digest,
                native_replay_unit: verification.native_replay_unit,
            });
        }
        catch {
            return refused('native_consequence_binding_invalid');
        }
        const expectedAuthorizationProgramDigest = deriveAuthorizationProgramDigest({
            trust_snapshot_id: attemptBinding.trust_snapshot_id,
            trust_snapshot_digest: attemptBinding.trust_snapshot_digest,
            local_authorization_program_digest: attemptBinding.local_authorization_program_digest,
            provider_outcome_verification_program_digest: attemptBinding.provider_outcome_verification_program_digest,
        });
        const expectedLocalDecision = deriveLocalDecision({
            decided_at: attemptBinding.local_decided_at,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_unit,
            program_digest: attemptBinding.local_authorization_program_digest,
        });
        const expectedRequestDigest = nativeConsequenceBoundaryRequestDigest({
            provider,
            operation_id: operationId,
            action,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_unit,
            trust_snapshot_id: attemptBinding.trust_snapshot_id,
            trust_snapshot_digest: attemptBinding.trust_snapshot_digest,
            authorization_program_digest: expectedAuthorizationProgramDigest,
            local_authorization: expectedLocalDecision,
            provider_outcome_verification_program_digest: attemptBinding.provider_outcome_verification_program_digest,
            provider_idempotency_key: expectedProviderIdempotencyKey,
        });
        if (attemptBinding.tenant_id !== provider.tenant_id
            || attemptBinding.provider_id !== provider.provider_id
            || attemptBinding.provider_account_id !== provider.provider_account_id
            || attemptBinding.environment !== provider.environment
            || attemptBinding.operation_id !== operationId
            || attemptBinding.action_digest !== verification.action_digest
            || attemptBinding.handoff_digest !== verification.record_digest
            || attemptBinding.native_replay_unit !== verification.native_replay_unit
            || attemptBinding.authorization_program_digest
                !== expectedAuthorizationProgramDigest
            || attemptBinding.local_decision_digest !== expectedLocalDecision.decision_digest
            || attemptBinding.provider_idempotency_key !== expectedProviderIdempotencyKey
            || attemptBinding.request_digest !== expectedRequestDigest) {
            return refused('reconciliation_binding_mismatch');
        }
        const outcome = normalizeEffectOutcome(rawOutcome, true);
        if (!outcome || outcome.state === 'INDETERMINATE') {
            return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
        }
        const evidence = providerEvidence(attemptBinding, outcome);
        const terminalState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
        const recoveredState = await attemptState(recoveredReference);
        if (recoveredState === null) {
            return indeterminate('attempt_state_unavailable', true, attemptBinding);
        }
        // RESERVED never entered the provider. RELEASED without terminal evidence
        // is a pre-entry release: its reservations were handed back, and the same
        // operation key may now belong to a later attempt. Neither is closable.
        if (recoveredState.state === 'RESERVED'
            || (recoveredState.state === 'RELEASED' && recoveredState.evidence === undefined)) {
            return refused('attempt_never_entered_provider');
        }
        if ((recoveredState.state === 'COMMITTED' || recoveredState.state === 'RELEASED')
            && !terminalRecordMatches(recoveredState, terminalState, evidence)) {
            // A terminal record is never rewritten, and a conflicting outcome must
            // not touch the reservations that record already closed.
            return refused('reconciliation_outcome_conflict');
        }
        if (recoveredState.state === 'INVOKING'
            && !await transitionAttempt(recoveredReference, 'INVOKING', 'INDETERMINATE')) {
            return indeterminate('attempt_freeze_unconfirmed', true, attemptBinding);
        }
        if (!await verifyProviderOutcome(attemptBinding, outcome)) {
            return indeterminate('provider_outcome_authentication_failed', true, attemptBinding);
        }
        // Any terminal provider result follows provider entry and therefore burns
        // the one-time native authorization, including authenticated NOT_COMMITTED.
        // After a restart the reservation may be owned by a dead process; the
        // store's authorized recovery claim takes it over before the close.
        const custodyClosed = await closeConsumptionForRecovery(keys.operation, 'CONSUMED', recoveryAuthorization);
        if (!custodyClosed) {
            return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
        }
        if (!await closeActionFence(keys, outcome.state === 'EXECUTED', recoveryAuthorization)) {
            return indeterminate('native_action_fence_release_unconfirmed', true, attemptBinding);
        }
        const terminal = await closeAttempt(recoveredReference, terminalState, evidence);
        if (!terminal) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
        }
        return terminalResult(outcome, attemptBinding);
    }
    return Object.freeze({
        version: NATIVE_CONSEQUENCE_BOUNDARY_VERSION,
        executor_id: executorId,
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
    NATIVE_CONSEQUENCE_BOUNDARY_VERSION,
    NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN,
    NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN,
    NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN,
    nativeConsequenceBoundaryReservationKey,
    nativeConsequenceBoundaryActionFenceKey,
    nativeConsequenceBoundaryActionFenceHolderKey,
    nativeConsequenceBoundaryProviderIdempotencyKey,
    nativeConsequenceBoundaryRequestDigest,
    createNativeConsequenceBoundary,
});
//# sourceMappingURL=consequence-boundary.js.map