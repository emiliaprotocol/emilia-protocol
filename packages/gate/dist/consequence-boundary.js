// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. The direct path verifies a relying-party-
 * pinned gateway handoff; it does not re-verify the native permit or artifact.
 * Both boundaries durably fence every native replay unit, and every exact
 * action at one provider target while an attempt for it is in flight, record
 * dispatch custody, and invoke one provider adapter. They do not acquire
 * approvals, mint authority, or require an EMILIA receipt.
 *
 * Reservation ownership: every reservation a native attempt can release or
 * close is keyed by its attempt ID (the diagnostic executed marker is only
 * ever committed), so a release, close, or recovery claim can only reach rows
 * that attempt created. On the composed boundary the action-fence holder is
 * keyed the same way; the evaluation reservation is keyed by the evaluation,
 * and an attempt commits it only while its own holder is still held, which
 * marks it as that reservation's owner. The durable attempt record is written
 * before any attempt-keyed reservation, so an attempt that stops before
 * provider entry can be found and recovered through reconcile().
 *
 * Release ordering: an attempt's reservations are released, closed, or
 * committed only after its durable record has confirmably reached a terminal
 * state or RELEASED with this attempt's explicit not-entered marker. A
 * RELEASED record without that marker or provider evidence proves nothing and
 * releases nothing. Pre-entry recovery and terminal reconciliation are
 * separate reconcile() modes, and a pre-entry recovery that loses its
 * RESERVED -> RELEASED transition to the live run releases nothing.
 */
import crypto from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import { aebReservationKey, authorizeAebExecutionDurable, canonicalizeAeb, digestAeb, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { digestAebNativeAuthorizationAction, verifyAebNativeAuthorizationHandoff, verifyAebNativeAuthorizationPins, } from '@emilia-protocol/verify/aeb';
export const CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-CONSEQUENCE-BOUNDARY-v1';
export const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = 'EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN = 'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1';
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const AUTHORIZATION_INSTANCE = /^[A-Za-z0-9_.:-]{1,256}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
/** Value of `ConsequenceBoundaryNotEnteredMarker.kind`. */
export const CONSEQUENCE_BOUNDARY_NOT_ENTERED = 'not_entered';
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
        && value.notEnteredMarker === true
        && typeof value.state === 'function';
}
function nativeTrustSnapshotDigest(pins) {
    return digestAeb({
        domain: NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN,
        pins,
    });
}
/**
 * Operation identity of one (relying party, operation ID, exact action). The
 * native boundary holds it as a fence inside the attempt's operation
 * reservation, so a second attempt with the same operation ID and action is
 * refused as `consumption_conflict` while the first holds it, and forever once
 * the first reached the provider. It is also the operation key a recovery
 * claim scope names for every reservation of one attempt.
 */
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
function relyingPartyText(value) {
    return typeof value === 'string'
        && Buffer.byteLength(value, 'utf8') >= 1
        && Buffer.byteLength(value, 'utf8') <= 512
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function actionFenceKeyUnchecked(relyingPartyId, provider, actionDigest) {
    return `aeb-native-action:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE`,
        relying_party_id: relyingPartyId,
        provider,
        action_digest: actionDigest,
    })}`;
}
/**
 * Durable identity of one exact action at one effecting target: the relying
 * party, the provider coordinates the boundary invokes, and the canonical
 * action digest (digestAebNativeAuthorizationAction). While an attempt for
 * this identity is RESERVED, INVOKING, or INDETERMINATE, a new attempt is
 * refused as `native_action_in_flight` even when it carries a fresh native
 * authorization and a fresh operation ID; after EXECUTED it is refused as
 * `native_action_already_executed`. Both boundaries derive the same key, so
 * they fence each other when they share a store and a relying party ID.
 *
 * Identity is byte-level. Gate does not canonicalize amounts, case,
 * whitespace, or Unicode, and does not know which fields are material: two
 * encodings of one logical action are two actions, and provider coordinates
 * are compared exactly as configured. Callers and profiles must canonicalize
 * the action and configure one spelling per provider account. Intentional
 * repeats must differ in the canonical action itself, for example through a
 * caller-chosen instance field that the action digest covers.
 */
export function nativeConsequenceBoundaryActionFenceKey(input) {
    const record = dataRecord(input);
    const provider = record ? providerCoordinates(record.provider) : null;
    if (!record || !provider || !identifier(record.relying_party_id)
        || !digest(record.action_digest)) {
        throw new TypeError('native_action_fence_binding_invalid');
    }
    return actionFenceKeyUnchecked(record.relying_party_id, provider, record.action_digest);
}
/**
 * Consumption-store keys of one native attempt. Every row key includes the
 * attempt ID, and the authority and holder keys are derived from the
 * attempt's operation key, so a release, close, or recovery claim for one
 * attempt can never reach a row another attempt wrote, even when both carry
 * the same caller-chosen operation ID.
 */
export function nativeConsequenceBoundaryAttemptReservationKeys(input) {
    const record = dataRecord(input);
    if (!record || !identifier(record.attempt_id)) {
        throw new TypeError('native_attempt_reservation_binding_invalid');
    }
    const operationFence = nativeConsequenceBoundaryReservationKey({
        relying_party_id: record.relying_party_id,
        operation_id: record.operation_id,
        action_digest: record.action_digest,
    });
    const actionFence = nativeConsequenceBoundaryActionFenceKey({
        relying_party_id: record.relying_party_id,
        provider: record.provider,
        action_digest: record.action_digest,
    });
    const operation = nativeAttemptOperationKey(operationFence, record.attempt_id);
    return {
        operation_fence: operationFence,
        action_fence: actionFence,
        operation,
        authority: nativeAttemptAuthorityKey(operation),
        holder: nativeAttemptHolderKey(operation),
    };
}
function nativeAttemptOperationKey(operationFence, attemptId) {
    return `aeb-native-attempt-operation:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ATTEMPT-OPERATION`,
        operation_fence: operationFence,
        attempt_id: attemptId,
    })}`;
}
function nativeAttemptAuthorityKey(operationKey) {
    return `aeb-native-attempt-authority:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ATTEMPT-AUTHORITY`,
        operation_key: operationKey,
    })}`;
}
function nativeAttemptHolderKey(operationKey) {
    return `aeb-native-action-holder:${digestAeb({
        domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE-HOLDER`,
        operation_key: operationKey,
    })}`;
}
const NATIVE_OPERATION_FENCE_KEY = /^aeb-native-operation:sha256:[a-f0-9]{64}$/;
const COMPOSED_RESERVATION_KEY = /^aeb:sha256:[a-f0-9]{64}$/;
const RECOVERY_CLAIM_SCOPE_KEYS = [
    'boundary', 'attemptId', 'operationId', 'recoveryOperationKey', 'reservation',
];
/**
 * The exact consumption-store row a recovery claim scope names, derived the
 * way the boundaries derive it: from the scope's boundary kind, its recovery
 * operation key (the native operation fence, or the composed evaluation
 * reservation key), its attempt ID, and which reservation it names. A
 * `native` scope derives only native rows and a `composed` scope only
 * composed rows. Null for a scope no boundary produces. A store that is given
 * a scope refuses a claim on any other row, so a credential bound to one
 * attempt identity (consequenceBoundaryRecoveryAttemptIdentity()) cannot
 * claim another attempt's row, on either boundary.
 */
export function consequenceBoundaryRecoveryClaimKey(scope) {
    const record = dataRecord(scope);
    if (!record || !exactKeys(record, RECOVERY_CLAIM_SCOPE_KEYS)
        || !identifier(record.attemptId) || typeof record.operationId !== 'string'
        || typeof record.recoveryOperationKey !== 'string')
        return null;
    const attemptId = record.attemptId;
    const recoveryOperationKey = record.recoveryOperationKey;
    if (record.boundary === 'native' && NATIVE_OPERATION_FENCE_KEY.test(recoveryOperationKey)) {
        const operation = nativeAttemptOperationKey(recoveryOperationKey, attemptId);
        if (record.reservation === 'operation')
            return operation;
        if (record.reservation === 'native-authority')
            return nativeAttemptAuthorityKey(operation);
        if (record.reservation === 'action-fence-holder')
            return nativeAttemptHolderKey(operation);
        return null;
    }
    if (record.boundary === 'composed' && COMPOSED_RESERVATION_KEY.test(recoveryOperationKey)) {
        if (record.reservation === 'operation')
            return recoveryOperationKey;
        if (record.reservation === 'action-fence-holder') {
            return consequenceBoundaryActionFenceHolderKey({
                reservation_key: recoveryOperationKey,
                attempt_id: attemptId,
            });
        }
    }
    return null;
}
/**
 * The attempt identity a recovery credential binds to: the boundary kind and
 * the attempt ID, as `native:<attemptId>` or `composed:<attemptId>`. Every
 * row of one attempt carries the same identity, and a native and a composed
 * attempt never share one even when their attempt IDs are equal. Null for a
 * scope that consequenceBoundaryRecoveryClaimKey() refuses.
 */
export function consequenceBoundaryRecoveryAttemptIdentity(scope) {
    if (consequenceBoundaryRecoveryClaimKey(scope) === null)
        return null;
    const record = dataRecord(scope);
    return `${record.boundary}:${record.attemptId}`;
}
/**
 * For a scope whose row is shared by every attempt of one evaluation (the
 * composed evaluation reservation), the row that marks this attempt as its
 * current owner: the attempt's action-fence holder. Null for a row keyed by
 * the attempt itself, which needs no marker.
 */
export function consequenceBoundaryRecoveryClaimMarkerKey(scope) {
    const record = dataRecord(scope);
    if (!record || record.boundary !== 'composed' || record.reservation !== 'operation'
        || typeof record.recoveryOperationKey !== 'string'
        || !COMPOSED_RESERVATION_KEY.test(record.recoveryOperationKey))
        return null;
    return consequenceBoundaryRecoveryClaimKey({ ...record, reservation: 'action-fence-holder' });
}
/**
 * Key of the reservation that holds the action fence for one native attempt.
 * It is derived from that attempt's operation key, which includes the attempt
 * ID, so reconciliation can only ever close the holder of its own attempt.
 */
export function nativeConsequenceBoundaryActionFenceHolderKey(input) {
    return nativeConsequenceBoundaryAttemptReservationKeys(input).holder;
}
/**
 * Key of the reservation that holds the action fence for one attempt on the
 * composed (AEB evaluation) boundary: derived from the evaluation's
 * consumption reservation key and the attempt ID.
 */
export function consequenceBoundaryActionFenceHolderKey(input) {
    if (!isObject(input) || typeof input.reservation_key !== 'string'
        || !input.reservation_key.startsWith('aeb:') || !identifier(input.attempt_id)) {
        throw new TypeError('action_fence_holder_binding_invalid');
    }
    return `aeb-action-holder:${digestAeb({
        domain: `${CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE-HOLDER`,
        reservation_key: input.reservation_key,
        attempt_id: input.attempt_id,
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
        const keys = nativeConsequenceBoundaryAttemptReservationKeys(input);
        return { ...keys, executed_marker: nativeActionExecutedMarkerKey(keys.action_fence) };
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
const ATTEMPT_STATES = [
    'RESERVED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'RELEASED',
];
/**
 * How many durable reads a run makes to resolve an unconfirmed move to
 * INVOKING before it closes the attempt as not entered without one.
 */
const START_CONFIRM_READS = 3;
function notEnteredMarker(attemptId) {
    return Object.freeze({ kind: CONSEQUENCE_BOUNDARY_NOT_ENTERED, attempt_id: attemptId });
}
/**
 * What the stored evidence of a COMMITTED or RELEASED record proves, from
 * the evidence alone: this attempt's not-entered marker, provider evidence
 * (to be compared with the terminal outcome), or nothing at all.
 */
function recordEvidenceKind(snapshot, attemptId) {
    if (snapshot.evidence === undefined)
        return 'unproven';
    const record = dataRecord(snapshot.evidence);
    if (!record)
        return 'unproven';
    if (Object.hasOwn(record, 'kind')) {
        return snapshot.state === 'RELEASED'
            && exactKeys(record, ['kind', 'attempt_id'])
            && record.kind === CONSEQUENCE_BOUNDARY_NOT_ENTERED
            && record.attempt_id === attemptId
            ? 'not_entered'
            : 'unproven';
    }
    return 'provider';
}
/** RELEASED with this attempt's durable not-entered marker. */
function isNotEntered(snapshot, attemptId) {
    return snapshot?.state === 'RELEASED' && recordEvidenceKind(snapshot, attemptId) === 'not_entered';
}
/** COMMITTED or RELEASED with no evidence that proves how it got there. */
function isUnprovenRecord(snapshot, attemptId) {
    return (snapshot?.state === 'RELEASED' || snapshot?.state === 'COMMITTED')
        && recordEvidenceKind(snapshot, attemptId) === 'unproven';
}
/**
 * A provider-outcome verifier's answer counts only when it affirms the exact
 * purpose, attempt, and provider idempotency key it was asked about.
 */
function affirmsProviderOutcome(answer, purpose, attempt) {
    const record = dataRecord(answer);
    return record !== null
        && exactKeys(record, ['verified', 'purpose', 'attempt_id', 'provider_idempotency_key'])
        && record.verified === true
        && record.purpose === purpose
        && record.attempt_id === attempt.attempt_id
        && record.provider_idempotency_key === attempt.provider_idempotency_key;
}
/**
 * Await a store or callback call and never throw: a throw, a rejection, or a
 * synchronous answer that is not a promise all come back as a value.
 */
async function guarded(call, fallback) {
    try {
        return await call();
    }
    catch {
        return fallback;
    }
}
function reconcileMode(value) {
    if (value === undefined || value === 'terminal')
        return 'terminal';
    return value === 'pre_entry' ? 'pre_entry' : null;
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
        || (options.provider_outcomes !== undefined
            && (!isObject(options.provider_outcomes)
                || typeof options.provider_outcomes.verify !== 'function'))
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
    const attemptStore = options.attempts.store;
    const envelopeBoundary = options.consequence_envelope ?? null;
    // Action-fence custody. A store that fails the secure-store check is
    // refused by authorizeAebExecutionDurable() before any fence write.
    const custody = secureAebConsumptionStore(options.aeb.store)
        ? consumptionCustody(options.aeb.store)
        : null;
    // A durable attempt-state read confirms every attempt transition, but only
    // for a store that declares it persists and returns the not-entered marker.
    // Gate 0.26.0 never read a composed attempt store, so a store written for
    // it is used as before: transitions count only on an acknowledgement that
    // is exactly `true`.
    const readComposedAttemptState = attemptStore.notEnteredMarker === true
        && typeof attemptStore.state === 'function'
        ? attemptStore.state.bind(attemptStore)
        : null;
    const verifyComposedOutcome = options.provider_outcomes
        ? options.provider_outcomes.verify.bind(options.provider_outcomes)
        : null;
    /**
     * Ask the configured provider-outcome verifier about one terminal outcome.
     * Only an affirmation of this exact purpose, attempt, and provider
     * idempotency key counts.
     */
    async function composedOutcomeVerified(attemptBinding, evaluation, evaluationDigest, actionDigest, outcome, purpose) {
        if (!verifyComposedOutcome)
            return false;
        const answer = await guarded(() => verifyComposedOutcome(cloneFrozen({
            provider,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action_digest: actionDigest,
            evaluation_digest: evaluationDigest,
            provider_idempotency_key: attemptBinding.provider_idempotency_key,
            attempt: attemptBinding,
            outcome,
            purpose,
        })), null);
        return affirmsProviderOutcome(answer, purpose, attemptBinding);
    }
    async function composedAttemptState(reference) {
        if (!readComposedAttemptState)
            return null;
        try {
            const snapshot = dataRecord(await readComposedAttemptState(reference));
            if (!snapshot || typeof snapshot.state !== 'string'
                || !ATTEMPT_STATES.includes(snapshot.state))
                return null;
            const state = snapshot.state;
            return snapshot.evidence === undefined
                ? { state }
                : { state, evidence: cloneFrozen(snapshot.evidence) };
        }
        catch {
            return null;
        }
    }
    /**
     * One attempt-store transition. With a durable read the read decides; the
     * store's answer never counts on its own. Without one, only an answer that
     * is exactly `true` counts. Every move to RELEASED carries this attempt's
     * not-entered marker, and with a durable read it is confirmed only when the
     * stored record carries that marker.
     */
    async function composedTransition(reference, expected, next) {
        const marker = notEnteredMarker(reference.attempt_id);
        const answer = await guarded(() => attemptStore.transition({
            ...reference,
            expected_state: expected,
            next_state: next,
            ...(next === 'RELEASED' ? { evidence: marker } : {}),
        }), undefined);
        if (!readComposedAttemptState) {
            return {
                confirmed: answer === true,
                snapshot: answer === true
                    ? { state: next, ...(next === 'RELEASED' ? { evidence: marker } : {}) }
                    : null,
            };
        }
        const snapshot = await composedAttemptState(reference);
        return {
            confirmed: snapshot !== null && snapshot.state === next
                && (next !== 'RELEASED' || isNotEntered(snapshot, reference.attempt_id)),
            snapshot,
        };
    }
    /** Durable read with a few retries; null when it never succeeds. */
    async function composedAttemptStateRetried(reference) {
        let snapshot = null;
        for (let read = 0; snapshot === null && read < START_CONFIRM_READS; read += 1) {
            snapshot = await composedAttemptState(reference);
        }
        return snapshot;
    }
    /**
     * Close an attempt whose move to INVOKING was not confirmed, from a run
     * that has not called the provider and never will. The store's
     * compare-and-swap applies at most one of the two moves. Returns the state
     * it was closed from, 'READ' when only a later durable read shows the
     * not-entered marker, or null when nothing is confirmed.
     */
    async function closeUnconfirmedStart(reference) {
        if ((await composedTransition(reference, 'RESERVED', 'RELEASED')).confirmed)
            return 'RESERVED';
        if ((await composedTransition(reference, 'INVOKING', 'RELEASED')).confirmed)
            return 'INVOKING';
        if (!readComposedAttemptState)
            return null;
        return isNotEntered(await composedAttemptStateRetried(reference), reference.attempt_id)
            ? 'READ'
            : null;
    }
    /** Only called with a durable read, whose store returns stored evidence. */
    function composedTerminalMatches(snapshot, next, evidence) {
        if (snapshot?.state !== next || snapshot.evidence === undefined)
            return false;
        try {
            return canonicalizeAeb(snapshot.evidence) === canonicalizeAeb(evidence);
        }
        catch {
            return false;
        }
    }
    /** INDETERMINATE -> COMMITTED or RELEASED with evidence, confirmed. */
    async function composedTerminal(reference, next, evidence) {
        const answer = await guarded(() => attemptStore.reconcile({
            ...reference,
            expected_state: 'INDETERMINATE',
            next_state: next,
            evidence,
        }), undefined);
        if (!readComposedAttemptState)
            return answer === true;
        return composedTerminalMatches(await composedAttemptState(reference), next, evidence);
    }
    /**
     * Close the evaluation reservation R(E) and this attempt's fence holder
     * after the attempt's terminal record is confirmed. R(E) is keyed by the
     * evaluation, not the attempt; the holder, keyed by R(E) and this attempt,
     * is its attempt marker. The holder is reserved after R(E), is released
     * before R(E) on every pre-entry path, and is closed only after R(E) is
     * committed, so while it is RESERVED no other attempt can hold R(E). Without
     * that marker R(E) is left untouched.
     */
    async function settleComposedReservations(reservationKey, holderKey, executedMarker, executed, recovery) {
        const store = custody;
        const commitEvaluation = () => recovery
            ? store.closeForRecovery(reservationKey, 'CONSUMED', recovery.authorization, recovery.scope('operation'))
            : store.closeConfirmed(reservationKey, 'CONSUMED');
        if (store.hasStateRead) {
            const holder = await store.state(holderKey);
            if (holder === 'RESERVED') {
                if (!await commitEvaluation())
                    return 'authorization_consumption_unconfirmed';
            }
            else if (await store.state(reservationKey) !== 'CONSUMED') {
                return 'evaluation_reservation_not_owned';
            }
            return await closeComposedActionFence(holderKey, executedMarker, executed, recovery && {
                authorization: recovery.authorization,
                scope: recovery.scope('action-fence-holder'),
            })
                ? null
                : 'native_action_fence_release_unconfirmed';
        }
        // Without a durable read the holder's own acknowledged close is the
        // marker: it proves this attempt still held the holder, so R(E) was still
        // this attempt's. EXECUTED commits the holder, FAILED releases it.
        const holderScope = recovery?.scope('action-fence-holder');
        const holderClosed = executed
            ? recovery
                ? await store.closeForRecovery(holderKey, 'CONSUMED', recovery.authorization, holderScope)
                : await store.closeConfirmed(holderKey, 'CONSUMED')
            : recovery
                ? await store.releaseForRecovery(holderKey, recovery.authorization, holderScope)
                : await store.releaseConfirmed(holderKey);
        if (executed)
            await store.markActionExecuted(executedMarker);
        if (!holderClosed) {
            return executed ? 'authorization_consumption_unconfirmed' : 'native_action_fence_release_unconfirmed';
        }
        return await commitEvaluation() ? null : 'authorization_consumption_unconfirmed';
    }
    async function closeComposedActionFence(holderKey, executedMarker, executed, recovery) {
        if (executed) {
            // A holder left RESERVED still fences the action, so an unconfirmed
            // commit cannot reopen it.
            if (!recovery)
                await custody.closeConfirmed(holderKey, 'CONSUMED');
            else
                await custody.closeForRecovery(holderKey, 'CONSUMED', recovery.authorization, recovery.scope);
            await custody.markActionExecuted(executedMarker);
            return true;
        }
        return !recovery
            ? custody.releaseConfirmed(holderKey)
            : custody.releaseForRecovery(holderKey, recovery.authorization, recovery.scope);
    }
    async function run(input) {
        const progress = { entered: false };
        try {
            return await runAttempt(input, progress);
        }
        catch {
            // Last resort: every store and callback call below is guarded, so this
            // is reached only by a defect. Whatever was reserved stays held.
            return progress.attempt
                ? indeterminate('boundary_internal_error', progress.entered, progress.attempt)
                : refused('boundary_internal_error');
        }
    }
    async function runAttempt(input, progress) {
        let action;
        let evaluation;
        let evaluationDigest;
        let decisionNow;
        let artifacts;
        let currentStatuses;
        let executionConditions;
        let additionalReplayKeys;
        try {
            // One read of the caller's object: getters and Proxies anywhere in it
            // are refused here rather than run later.
            const record = dataRecord(input);
            if (!record || containsProxy(record))
                throw new Error('execution_input_invalid');
            action = cloneFrozen(record.action);
            evaluation = cloneFrozen(record.evaluation);
            evaluationDigest = digestAeb(evaluation);
            artifacts = record.artifacts;
            currentStatuses = record.current_statuses;
            executionConditions = record.execution_conditions;
            if (record.additional_replay_keys !== undefined) {
                const keys = cloneFrozen(record.additional_replay_keys);
                if (!Array.isArray(keys) || !keys.every((key) => typeof key === 'string')) {
                    throw new Error('execution_input_invalid');
                }
                additionalReplayKeys = keys;
            }
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
        let verification;
        try {
            verification = verifyAebEvaluation(evaluation, {
                mode: 'execution',
                config: options.aeb.config,
                adapters: options.aeb.adapters,
                artifacts: artifacts,
                expected_action: action,
                current_statuses: currentStatuses,
                now: decisionNow,
            });
        }
        catch {
            return refused('evaluation_not_verified');
        }
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
        let authorization;
        try {
            authorization = await authorizeAebExecutionDurable(evaluation, {
                verification,
                local_authorization: true,
                store: options.aeb.store,
                execution_conditions: executionConditions,
                additional_replay_keys: additionalReplayKeys,
            });
        }
        catch {
            return refused('execution_input_invalid');
        }
        if (!authorization.invoke_allowed || !authorization.reservation_key) {
            return authorization.state === 'RECONCILIATION_REQUIRED'
                ? indeterminate(authorization.reason, false)
                : refused(authorization.reason);
        }
        const reservationKey = authorization.reservation_key;
        const actionDigest = digestAeb(action);
        const releaseEvaluation = async () => custody
            ? custody.releaseConfirmed(reservationKey)
            : await guarded(() => options.aeb.store.release(reservationKey), false) === true;
        // A refusal before the attempt record exists is clean only when the
        // evaluation reservation was confirmably handed back. Otherwise R(E) may
        // still be RESERVED with no attempt record to recover it from, so the
        // result is INDETERMINATE.
        const refuseBeforeAttempt = async (reason) => (await releaseEvaluation()
            ? refused(reason)
            : indeterminate('evaluation_release_unconfirmed', false));
        // Same-action fence, shared with the native boundary: relying party,
        // provider coordinates as configured, and the canonical action digest.
        // Derived before any further write so an unkeyable binding is a refusal.
        let actionFence;
        try {
            const relyingPartyId = options.aeb.config.relying_party_id;
            if (!relyingPartyText(relyingPartyId) || !custody)
                throw new Error('fence_unkeyable');
            actionFence = actionFenceKeyUnchecked(relyingPartyId, provider, digestAebNativeAuthorizationAction(action));
        }
        catch {
            return refuseBeforeAttempt('action_fence_binding_invalid');
        }
        const executedMarker = nativeActionExecutedMarkerKey(actionFence);
        let envelopeReservation = null;
        if (envelopeBoundary) {
            let capacity;
            try {
                capacity = await envelopeBoundary.reserve({
                    operation_id: evaluation.operation_id,
                    state_domain_id: envelopeBoundary.envelope.state_domain_id,
                    expected_epoch: envelopeBoundary.envelope.epoch,
                    action,
                });
            }
            catch {
                capacity = { status: 'REFUSED', reason: 'consequence_envelope_unavailable' };
            }
            if (capacity?.status !== 'RESERVED') {
                return refuseBeforeAttempt(identifier(capacity?.reason) ? capacity.reason : 'consequence_envelope_unavailable');
            }
            envelopeReservation = capacity.reservation;
        }
        const releaseEnvelopeNotEntered = async () => {
            if (envelopeReservation) {
                await guarded(() => envelopeBoundary.releaseNotEntered(envelopeReservation), null);
            }
        };
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
        let holderKey;
        try {
            attemptId = await createAttemptId({
                operation_id: evaluation.operation_id,
                request_digest: requestDigest,
            });
            if (!identifier(attemptId))
                throw new Error('attempt_id_invalid');
            holderKey = consequenceBoundaryActionFenceHolderKey({
                reservation_key: reservationKey,
                attempt_id: attemptId,
            });
        }
        catch {
            await releaseEnvelopeNotEntered();
            return refuseBeforeAttempt('attempt_allocation_failed');
        }
        const attemptBinding = cloneFrozen({
            ...provider,
            attempt_id: attemptId,
            request_digest: requestDigest,
            provider_idempotency_key: providerIdempotencyKey,
        });
        // No owner handle exists until reserve() answers, so an attempt record a
        // failed reserve may still have written can never reach INVOKING; the
        // evaluation reservation it would guard can be handed back.
        let reservedAnswer;
        try {
            reservedAnswer = dataRecord(await attemptStore.reserve(attemptBinding));
        }
        catch {
            await releaseEnvelopeNotEntered();
            return refuseBeforeAttempt('attempt_store_unavailable');
        }
        if (reservedAnswer?.reserved !== true || !opaqueOwner(reservedAnswer.owner)) {
            await releaseEnvelopeNotEntered();
            return refuseBeforeAttempt(identifier(reservedAnswer?.reason) ? reservedAnswer.reason : 'attempt_conflict');
        }
        const attempt = {
            ...attemptBinding,
            owner: reservedAnswer.owner,
        };
        const publicBinding = publicAttempt(attempt);
        progress.attempt = publicBinding;
        /**
         * Pre-entry stop. Nothing is handed back until the attempt record is
         * durably not entered (RESERVED -> RELEASED, confirmed). Then the holder
         * goes first, the capacity reservation next, and the evaluation
         * reservation last, so a held holder always proves this attempt still
         * owns R(E).
         */
        async function stopBeforeEntry(reason, holderMayBeHeld, envelopeEntered, alreadyReleased = false) {
            if (!alreadyReleased) {
                const released = await composedTransition(attempt, 'RESERVED', 'RELEASED');
                if (!released.confirmed) {
                    if (envelopeReservation && envelopeEntered) {
                        await guarded(() => envelopeBoundary.settle(envelopeReservation, 'INDETERMINATE'), null);
                    }
                    return indeterminate('attempt_release_unconfirmed', false, publicBinding);
                }
            }
            if (holderMayBeHeld && !await custody.releaseConfirmed(holderKey)) {
                return indeterminate('native_pre_entry_release_unconfirmed', false, publicBinding);
            }
            if (envelopeReservation) {
                // The record proves the provider callback never ran, so capacity that
                // already began provider entry is settled as proven not committed.
                if (envelopeEntered) {
                    await guarded(() => envelopeBoundary.settle(envelopeReservation, 'PROVEN_NOT_COMMITTED'), null);
                }
                else {
                    await releaseEnvelopeNotEntered();
                }
            }
            if (!await releaseEvaluation()) {
                return indeterminate('evaluation_release_unconfirmed', false, publicBinding);
            }
            return refused(reason);
        }
        // The holder reservation is keyed by this attempt and fences the exact
        // action at this provider. It is written after the attempt record, so an
        // attempt that stops before entry can be found and its holder released by
        // reconcile().
        let holderReserved = false;
        try {
            const fenced = await custody.reserve(holderKey, [actionFence]);
            holderReserved = fenced === true || fenced === 'RESERVED';
        }
        catch {
            return stopBeforeEntry('consumption_store_unavailable', true, false);
        }
        if (!holderReserved) {
            return stopBeforeEntry(await custody.actionFenceRefusal(executedMarker), false, false);
        }
        let envelopeEntered = false;
        if (envelopeReservation) {
            const capacityEntry = await guarded(() => envelopeBoundary.beginProviderEntry(envelopeReservation), { status: 'REFUSED', reason: 'consequence_envelope_unavailable' });
            if (capacityEntry?.status !== 'ENTERED') {
                return stopBeforeEntry(identifier(capacityEntry?.reason)
                    ? capacityEntry.reason
                    : 'consequence_envelope_unavailable', true, false);
            }
            envelopeEntered = true;
        }
        // Provider entry. An answer other than exactly `true` is resolved by the
        // durable record, never by assumption: INVOKING means this owner's write
        // landed and it proceeds; RESERVED means it did not, so the attempt is
        // closed as not entered first; RELEASED with the not-entered marker means
        // a pre-entry recovery linearized first; anything else holds every
        // reservation. An unreadable record is read again, and if it stays
        // unreadable this run, which has not called the provider and never will,
        // closes the attempt as not entered from either state without a read.
        let start = await composedTransition(attempt, 'RESERVED', 'INVOKING');
        if (!start.confirmed && readComposedAttemptState && start.snapshot === null) {
            const reread = await composedAttemptStateRetried(attempt);
            start = { confirmed: reread?.state === 'INVOKING', snapshot: reread };
        }
        if (!start.confirmed) {
            if (readComposedAttemptState && start.snapshot?.state === 'RESERVED') {
                return stopBeforeEntry('attempt_start_conflict', true, envelopeEntered);
            }
            if (readComposedAttemptState && isNotEntered(start.snapshot, attemptId)) {
                return stopBeforeEntry('attempt_released_by_recovery', true, envelopeEntered, true);
            }
            if (!readComposedAttemptState || start.snapshot === null) {
                const closedFrom = await closeUnconfirmedStart(attempt);
                if (closedFrom !== null) {
                    return stopBeforeEntry(closedFrom === 'RESERVED' ? 'attempt_start_conflict' : 'attempt_start_unconfirmed', true, envelopeEntered, true);
                }
            }
            if (envelopeReservation) {
                await guarded(() => envelopeBoundary.settle(envelopeReservation, 'INDETERMINATE'), null);
            }
            return indeterminate('attempt_start_unconfirmed', false, publicBinding);
        }
        progress.entered = true;
        let rawOutcome;
        let invokeThrew = false;
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
            invokeThrew = true;
        }
        const frozen = await composedTransition(attempt, 'INVOKING', 'INDETERMINATE');
        if (invokeThrew || !frozen.confirmed) {
            if (envelopeReservation) {
                await guarded(() => envelopeBoundary.settle(envelopeReservation, 'INDETERMINATE'), null);
            }
            return indeterminate(invokeThrew ? 'provider_outcome_indeterminate' : 'attempt_freeze_failed', true, publicBinding);
        }
        if (envelopeReservation) {
            const held = await guarded(() => envelopeBoundary.settle(envelopeReservation, 'INDETERMINATE'), { status: 'REFUSED', reason: 'consequence_envelope_unavailable' });
            if (held?.status !== 'INDETERMINATE') {
                return indeterminate('consequence_envelope_indeterminate_unconfirmed', true, publicBinding);
            }
        }
        // With a verifier the result is snapshotted, as on the native path, so
        // what was verified is what is returned.
        const outcome = normalizeEffectOutcome(rawOutcome, verifyComposedOutcome !== null);
        if (!outcome) {
            return indeterminate('provider_outcome_invalid', true, publicBinding);
        }
        if (outcome.state === 'INDETERMINATE') {
            return indeterminate(identifier(outcome.reason) ? outcome.reason : 'provider_outcome_indeterminate', true, publicBinding);
        }
        if (!validEvidence(outcome.evidence)) {
            return indeterminate('provider_evidence_invalid', true, publicBinding);
        }
        if (verifyComposedOutcome && !await composedOutcomeVerified(attemptBinding, evaluation, evaluationDigest, actionDigest, outcome, 'provider_outcome')) {
            return indeterminate('provider_outcome_authentication_failed', true, publicBinding);
        }
        // The terminal record comes first; only then is the one-time
        // authorization burned (even after FAILED: a later attempt requires a new
        // action instance and a fresh authorization) and the fence closed.
        // EXECUTED keeps the fence closed; an authenticated FAILED hands it back
        // so a fresh authorization may retry the same action.
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
        if (!await composedTerminal(attempt, terminalState, providerEvidence)) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, publicBinding);
        }
        const settledReservations = await settleComposedReservations(reservationKey, holderKey, executedMarker, outcome.state === 'EXECUTED');
        if (settledReservations !== null) {
            return indeterminate(settledReservations, true, publicBinding);
        }
        if (envelopeReservation) {
            const capacityTerminal = await guarded(() => envelopeBoundary.settle(envelopeReservation, outcome.state === 'EXECUTED' ? 'COMMITTED' : 'PROVEN_NOT_COMMITTED'), { status: 'REFUSED', reason: 'consequence_envelope_unavailable' });
            const expectedCapacityState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
            if (capacityTerminal?.status !== expectedCapacityState) {
                return indeterminate('consequence_envelope_terminal_unconfirmed', true, publicBinding);
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
        try {
            return await reconcileWithMode(input);
        }
        catch {
            return refused('boundary_internal_error');
        }
    }
    async function reconcileWithMode(input) {
        let action;
        let evaluation;
        let attemptBinding;
        let evaluationDigest;
        let artifacts;
        let rawOutcome;
        let recoveryAuthorization;
        let mode;
        try {
            const record = dataRecord(input);
            if (!record || containsProxy(record))
                throw new Error('input_invalid');
            action = cloneFrozen(record.action);
            evaluation = cloneFrozen(record.evaluation);
            evaluationDigest = digestAeb(evaluation);
            attemptBinding = cloneFrozen(record.attempt);
            artifacts = record.artifacts;
            rawOutcome = record.outcome;
            recoveryAuthorization = record.recovery_authorization;
            mode = reconcileMode(record.mode);
            if (!validAttemptBinding(attemptBinding) || mode === null)
                throw new Error('attempt_invalid');
        }
        catch {
            return refused('reconciliation_input_invalid');
        }
        if (evaluation.executor_id !== options.executor_id) {
            return refused('executor_binding_mismatch');
        }
        let verification;
        try {
            verification = verifyAebEvaluation(evaluation, {
                mode: 'historical',
                config: options.aeb.config,
                adapters: options.aeb.adapters,
                artifacts: artifacts,
                expected_action: action,
            });
        }
        catch {
            return refused('evaluation_not_verified');
        }
        if (!verification.valid) {
            return refused(verification.reasons[0] ?? 'evaluation_not_verified');
        }
        const expectedProviderIdempotencyKey = consequenceBoundaryProviderIdempotencyKey({
            provider,
            caid: evaluation.caid,
            action_digest: digestAeb(action),
            authorization_instance: evaluation.consumption_nonce,
        });
        const expectedRequestDigest = consequenceBoundaryRequestDigest({
            provider,
            operation_id: evaluation.operation_id,
            caid: evaluation.caid,
            action,
            evaluation_digest: evaluationDigest,
            provider_idempotency_key: expectedProviderIdempotencyKey,
        });
        if (attemptBinding.tenant_id !== provider.tenant_id
            || attemptBinding.provider_id !== provider.provider_id
            || attemptBinding.provider_account_id !== provider.provider_account_id
            || attemptBinding.environment !== provider.environment
            || attemptBinding.provider_idempotency_key !== expectedProviderIdempotencyKey
            || attemptBinding.request_digest !== expectedRequestDigest) {
            return refused('reconciliation_binding_mismatch');
        }
        // Snapshotted when a verifier will see it, so what was verified is what
        // is returned.
        const outcome = normalizeEffectOutcome(rawOutcome, verifyComposedOutcome !== null);
        let recovered = null;
        try {
            recovered = await options.attempts.recover({
                attempt: attemptBinding,
                recovery_authorization: recoveryAuthorization,
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
        let holderKey;
        let executedMarker;
        try {
            const relyingPartyId = options.aeb.config.relying_party_id;
            if (!relyingPartyText(relyingPartyId) || !custody)
                throw new Error('fence_unkeyable');
            holderKey = consequenceBoundaryActionFenceHolderKey({
                reservation_key: reservationKey,
                attempt_id: attemptBinding.attempt_id,
            });
            executedMarker = nativeActionExecutedMarkerKey(actionFenceKeyUnchecked(relyingPartyId, provider, digestAebNativeAuthorizationAction(action)));
        }
        catch {
            return refused('action_fence_binding_invalid');
        }
        const scope = (reservation) => ({
            boundary: 'composed',
            attemptId: attemptBinding.attempt_id,
            operationId: evaluation.operation_id,
            recoveryOperationKey: reservationKey,
            reservation,
        });
        const actionDigest = digestAeb(action);
        if (mode === 'pre_entry') {
            // Pre-entry recovery. It never falls through to terminal
            // reconciliation, never treats the caller's lookup as a provider
            // outcome, and never touches the evaluation reservation, which a live
            // run hands back itself. The linearization point is this call's own
            // RESERVED -> RELEASED transition with the not-entered marker (or an
            // earlier one, recorded with that marker): after it the original run
            // can no longer move the attempt to INVOKING.
            if (!outcome)
                return indeterminate('provider_outcome_indeterminate', false, attemptBinding);
            if (outcome.state === 'EXECUTED')
                return refused('reconciliation_outcome_conflict');
            let before = null;
            if (readComposedAttemptState) {
                before = await composedAttemptState(recoveredReference);
                if (before === null)
                    return indeterminate('attempt_state_unavailable', false, attemptBinding);
                if (isUnprovenRecord(before, attemptBinding.attempt_id)) {
                    return indeterminate('attempt_record_unproven', false, attemptBinding);
                }
                if (before.state === 'COMMITTED'
                    || (before.state === 'RELEASED' && !isNotEntered(before, attemptBinding.attempt_id))) {
                    return refused('reconciliation_outcome_conflict');
                }
                if (before.state === 'INVOKING' || before.state === 'INDETERMINATE') {
                    return indeterminate('recovery_lost_to_live_attempt', true, attemptBinding);
                }
            }
            // A configured verifier must affirm the lookup as a pre-entry lookup.
            // It is never used as a terminal outcome.
            if (verifyComposedOutcome && outcome.state === 'FAILED' && !await composedOutcomeVerified(attemptBinding, evaluation, evaluationDigest, actionDigest, outcome, 'pre_entry_lookup')) {
                return indeterminate('provider_outcome_authentication_failed', false, attemptBinding);
            }
            if (before) {
                // `before` is RESERVED or RELEASED with the not-entered marker here.
                if (before.state === 'RESERVED') {
                    const released = await composedTransition(recoveredReference, 'RESERVED', 'RELEASED');
                    if (!released.confirmed) {
                        const after = released.snapshot;
                        if (after === null)
                            return indeterminate('attempt_state_unavailable', false, attemptBinding);
                        if (isUnprovenRecord(after, attemptBinding.attempt_id)) {
                            return indeterminate('attempt_record_unproven', false, attemptBinding);
                        }
                        return after.state === 'RESERVED'
                            ? indeterminate('attempt_release_unconfirmed', false, attemptBinding)
                            : indeterminate('recovery_lost_to_live_attempt', true, attemptBinding);
                    }
                }
            }
            else {
                // Without a durable read only this call's own acknowledged
                // RESERVED -> RELEASED proves the stop.
                const released = await composedTransition(recoveredReference, 'RESERVED', 'RELEASED');
                if (!released.confirmed) {
                    return indeterminate('attempt_release_unconfirmed', false, attemptBinding);
                }
            }
            return await custody.releaseForRecovery(holderKey, recoveryAuthorization, scope('action-fence-holder'))
                ? refused('attempt_never_entered_provider')
                : indeterminate('native_pre_entry_release_unconfirmed', false, attemptBinding);
        }
        // Terminal reconciliation: only for an attempt that reached INVOKING, and
        // only with a terminal provider outcome that the configured verifier
        // affirms for this attempt before anything changes.
        const snapshot = readComposedAttemptState
            ? await composedAttemptState(recoveredReference)
            : null;
        if (readComposedAttemptState) {
            if (snapshot === null)
                return indeterminate('attempt_state_unavailable', true, attemptBinding);
            if (snapshot.state === 'RESERVED' || isNotEntered(snapshot, attemptBinding.attempt_id)) {
                return indeterminate('pre_entry_recovery_required', false, attemptBinding);
            }
            if (isUnprovenRecord(snapshot, attemptBinding.attempt_id)) {
                return indeterminate('attempt_record_unproven', true, attemptBinding);
            }
        }
        if (!outcome || outcome.state === 'INDETERMINATE') {
            return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
        }
        if (!verifyComposedOutcome)
            return refused('provider_outcome_verifier_required');
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
        if (snapshot && (snapshot.state === 'COMMITTED' || snapshot.state === 'RELEASED')
            && !composedTerminalMatches(snapshot, terminalState, providerEvidence)) {
            // A terminal record is never rewritten, and a conflicting outcome must
            // not touch the reservations that record already closed.
            return refused('reconciliation_outcome_conflict');
        }
        // Verified before the record is frozen, so a refused outcome leaves an
        // INVOKING record as it was and the live run can still finish it.
        if (!await composedOutcomeVerified(attemptBinding, evaluation, evaluationDigest, actionDigest, outcome, 'provider_outcome')) {
            return indeterminate('provider_outcome_authentication_failed', true, attemptBinding);
        }
        if (snapshot) {
            if (snapshot.state === 'INVOKING'
                && !(await composedTransition(recoveredReference, 'INVOKING', 'INDETERMINATE')).confirmed) {
                return indeterminate('attempt_freeze_unconfirmed', true, attemptBinding);
            }
            if (snapshot.state !== 'COMMITTED' && snapshot.state !== 'RELEASED'
                && !await composedTerminal(recoveredReference, terminalState, providerEvidence)) {
                return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
            }
        }
        else if (!await composedTerminal(recoveredReference, terminalState, providerEvidence)) {
            // A 0.26.0-style attempt store: freeze an INVOKING record, then retry
            // the terminal write. A RESERVED record fails both, so nothing is
            // released for an attempt that never reached INVOKING.
            if (!(await composedTransition(recoveredReference, 'INVOKING', 'INDETERMINATE')).confirmed
                || !await composedTerminal(recoveredReference, terminalState, providerEvidence)) {
                return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
            }
        }
        // After a restart an ownership-fenced store (the shipped PostgreSQL store)
        // refuses the commit until the authorized recovery claim takes the row.
        const settledReservations = await settleComposedReservations(reservationKey, holderKey, executedMarker, outcome.state === 'EXECUTED', { authorization: recoveryAuthorization, scope });
        if (settledReservations !== null) {
            return indeterminate(settledReservations, true, attemptBinding);
        }
        if (envelopeBoundary) {
            const capacityTerminal = await guarded(() => envelopeBoundary.reconcile({
                operation_id: evaluation.operation_id,
                action_digest: digestAeb(action),
                outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'PROVEN_NOT_COMMITTED',
                recovery_authorization: recoveryAuthorization,
            }), { status: 'REFUSED', reason: 'consequence_envelope_unavailable' });
            const expectedCapacityState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
            if (capacityTerminal?.status !== expectedCapacityState) {
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
/** How many times one recovery claims a row that concurrent recoveries keep taking. */
const RECOVERY_CLAIM_ATTEMPTS = 3;
/**
 * Consumption-store operations with every method pinned at construction.
 * A write is confirmed by a durable state read when the store has one, and
 * otherwise only by an explicit `true` acknowledgement. A lost acknowledgement
 * is resolved by the read, never by assuming the write happened.
 */
function consumptionCustody(store) {
    const readState = typeof store.state === 'function' ? store.state.bind(store) : null;
    const reserve = store.reserve.bind(store);
    const commit = store.commit.bind(store);
    const release = store.release.bind(store);
    const releaseTerminal = store.terminalRelease === true
        && typeof store.releaseTerminal === 'function'
        ? store.releaseTerminal.bind(store)
        : null;
    // A store that fences commit/release to the reserving process exposes an
    // authorized claim so reconciliation after a restart can take ownership.
    const claim = store.recoveryClaimSupported === true
        && typeof store.claimReservation === 'function'
        ? store.claimReservation.bind(store)
        : null;
    async function state(key) {
        if (!readState)
            return null;
        try {
            const value = await readState(key);
            return value === 'AVAILABLE' || value === 'RESERVED'
                || value === 'CONSUMED' || value === 'RELEASED_NOT_ENTERED'
                ? value
                : null;
        }
        catch {
            return null;
        }
    }
    /** Hand one open reservation back so its key and fences are AVAILABLE. */
    async function releaseConfirmed(key) {
        if (readState) {
            const before = await state(key);
            if (before === 'AVAILABLE')
                return true;
            if (before !== 'RESERVED')
                return false;
            try {
                await release(key);
            }
            catch { /* confirm through state */ }
            return await state(key) === 'AVAILABLE';
        }
        try {
            return await release(key) === true;
        }
        catch {
            return false;
        }
    }
    async function closeConfirmed(key, target) {
        if (target === 'RELEASED_NOT_ENTERED' && !releaseTerminal)
            return false;
        if (readState) {
            const before = await state(key);
            if (before === target)
                return true;
            if (before !== 'RESERVED')
                return false;
            try {
                if (target === 'CONSUMED')
                    await commit(key);
                else
                    await releaseTerminal(key);
            }
            catch {
                // A lost acknowledgement is resolved by the durable state read below.
            }
            return await state(key) === target;
        }
        try {
            return target === 'CONSUMED'
                ? await commit(key) === true
                : await releaseTerminal(key) === true;
        }
        catch {
            return false;
        }
    }
    /**
     * Take ownership of a RESERVED row through the store's authorized recovery
     * path. Only reconciliation calls this, after it has authenticated custody
     * of the attempt, and only for keys derived from that attempt.
     */
    async function claimFor(key, authorization, scope) {
        if (!claim)
            return false;
        if (readState && await state(key) !== 'RESERVED')
            return false;
        try {
            return await claim(key, authorization, cloneFrozen(scope)) === true;
        }
        catch {
            return false;
        }
    }
    // After a refused claim the row is read again: a concurrent owner (the live
    // run handing back its own rows, or another recovery) may already have
    // moved it to the target, which counts as done. A claim that another
    // recovery overtook before this call's write is claimed again, a bounded
    // number of times.
    async function closeForRecovery(key, target, authorization, scope) {
        if (await closeConfirmed(key, target))
            return true;
        for (let claimed = 0; claimed < RECOVERY_CLAIM_ATTEMPTS; claimed += 1) {
            if (!await claimFor(key, authorization, scope))
                return await state(key) === target;
            if (await closeConfirmed(key, target))
                return true;
        }
        return false;
    }
    async function releaseForRecovery(key, authorization, scope) {
        if (await releaseConfirmed(key))
            return true;
        for (let claimed = 0; claimed < RECOVERY_CLAIM_ATTEMPTS; claimed += 1) {
            if (!await claimFor(key, authorization, scope))
                return await state(key) === 'AVAILABLE';
            if (await releaseConfirmed(key))
                return true;
        }
        return false;
    }
    async function markActionExecuted(markerKey) {
        // Diagnostic only: it lets a later refusal say "already executed" rather
        // than "in flight". The fence itself is the committed holder reservation.
        try {
            const marker = await reserve(markerKey, []);
            if (marker === true || marker === 'RESERVED')
                await commit(markerKey);
        }
        catch {
            // The committed or still-reserved holder keeps the action closed.
        }
    }
    async function actionFenceRefusal(markerKey) {
        return await state(markerKey) === 'CONSUMED'
            ? 'native_action_already_executed'
            : 'native_action_in_flight';
    }
    return Object.freeze({
        hasStateRead: readState !== null,
        hasTerminalRelease: releaseTerminal !== null,
        reserve,
        state,
        releaseConfirmed,
        closeConfirmed,
        closeForRecovery,
        releaseForRecovery,
        markActionExecuted,
        actionFenceRefusal,
    });
}
/**
 * Build the direct native path. The native system has already made the policy
 * decision; Gate verifies the pinned gateway handoff, not the native permit or
 * artifact. It applies its own operational authorization and atomically fences
 * the operation, the native replay unit, and the exact action at this
 * provider, each in a reservation keyed by the attempt.
 */
export function createNativeConsequenceBoundary(options) {
    let provider;
    let pins;
    let configured = false;
    let pinRefusal = null;
    try {
        provider = cloneFrozen(options?.provider);
        pins = cloneFrozen(options?.native_authorization?.pins);
        // A pin set the verifier would refuse (aliased issuers without one shared
        // namespace, mixed namespace declarations, duplicates) is refused here,
        // before any attempt can run under it.
        const pinCheck = verifyAebNativeAuthorizationPins(pins);
        if (!pinCheck.valid)
            pinRefusal = pinCheck.reasons[0] ?? 'native_pins_invalid';
        configured = pinRefusal === null
            && isObject(options)
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
        throw new TypeError(pinRefusal
            ? `native_consequence_boundary_configuration_invalid: ${pinRefusal}`
            : 'native_consequence_boundary_configuration_invalid');
    }
    provider = provider;
    pins = pins;
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
    const custody = consumptionCustody(options.native_authorization.store);
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
    async function attemptState(reference) {
        try {
            const snapshot = dataRecord(await readAttemptState(reference));
            if (!snapshot
                || typeof snapshot.state !== 'string'
                || !ATTEMPT_STATES.includes(snapshot.state))
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
    /** One attempt-store write whose answer never counts on its own. */
    async function writeTransition(reference, expected, next) {
        await guarded(() => transitionAttemptState({
            ...reference,
            expected_state: expected,
            next_state: next,
            ...(next === 'RELEASED' ? { evidence: notEnteredMarker(reference.attempt_id) } : {}),
        }), undefined);
    }
    /**
     * One attempt-store transition, decided by the durable read that follows
     * it. The store's answer never counts on its own: a lost acknowledgement, a
     * `false`, or a truthy non-`true` value are all resolved by the read. A move
     * to RELEASED carries this attempt's not-entered marker. Returns the record
     * as read afterwards (the unchanged record when it was not in `expected`),
     * or null when it cannot be read.
     */
    async function transitionAttempt(reference, expected, next) {
        const before = await attemptState(reference);
        if (before === null || before.state !== expected)
            return before;
        await writeTransition(reference, expected, next);
        return attemptState(reference);
    }
    /** Durable read with a few retries; null when it never succeeds. */
    async function attemptStateRetried(reference) {
        let snapshot = null;
        for (let read = 0; snapshot === null && read < START_CONFIRM_READS; read += 1) {
            snapshot = await attemptState(reference);
        }
        return snapshot;
    }
    /** RELEASED with this attempt's durable not-entered marker. */
    function notEntered(snapshot, reference) {
        return isNotEntered(snapshot, reference.attempt_id);
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
    /**
     * Only an affirmation of this exact purpose, attempt ID, and provider
     * idempotency key counts; a plain `true` does not.
     */
    async function verifyProviderOutcome(attempt, outcome, purpose = 'provider_outcome') {
        const answer = await guarded(() => verifyOutcome(cloneFrozen({
            provider,
            operation_id: attempt.operation_id,
            action_digest: attempt.action_digest,
            native_replay_unit: attempt.native_replay_unit,
            verification_program_digest: attempt.provider_outcome_verification_program_digest,
            attempt,
            outcome,
            provider_idempotency_key: attempt.provider_idempotency_key,
            purpose,
        })), null);
        return affirmsProviderOutcome(answer, purpose, attempt);
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
    function claimScope(keys, attempt, reservation) {
        return {
            boundary: 'native',
            attemptId: attempt.attempt_id,
            operationId: attempt.operation_id,
            recoveryOperationKey: keys.operation_fence,
            reservation,
        };
    }
    /**
     * Close the action fence once the provider outcome is authenticated.
     * EXECUTED keeps it closed for this exact action; an authenticated FAILED
     * releases it so a fresh native authorization may retry the same action.
     */
    async function closeActionFence(keys, executed, recovery) {
        if (executed) {
            // A holder left RESERVED still fences the action, so an unconfirmed
            // commit here cannot reopen it.
            if (!recovery)
                await custody.closeConfirmed(keys.holder, 'CONSUMED');
            else {
                await custody.closeForRecovery(keys.holder, 'CONSUMED', recovery.authorization, claimScope(keys, recovery.attempt, 'action-fence-holder'));
            }
            await custody.markActionExecuted(keys.executed_marker);
            return true;
        }
        return !recovery
            ? custody.releaseConfirmed(keys.holder)
            : custody.releaseForRecovery(keys.holder, recovery.authorization, claimScope(keys, recovery.attempt, 'action-fence-holder'));
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
        const progress = { entered: false };
        try {
            return await runAttempt(input, progress);
        }
        catch {
            // Last resort: every store and callback call below is guarded, so this
            // is reached only by a defect. Whatever was reserved stays held.
            return progress.attempt
                ? indeterminate('boundary_internal_error', progress.entered, progress.attempt)
                : refused('boundary_internal_error');
        }
    }
    async function runAttempt(input, progress) {
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
            || !preflight.native_replay_identity || !preflight.replay_identity_key) {
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
            || !verification.native_replay_identity || !verification.replay_identity_key
            || !verification.replay_key || !Array.isArray(verification.legacy_replay_keys)
            || !verification.legacy_replay_keys.includes(verification.replay_key)) {
            return refused(verification.reasons[0] ?? 'native_handoff_not_verified');
        }
        if (verification.handoff.relying_party_id !== relyingPartyId) {
            return refused('native_consequence_binding_invalid');
        }
        let providerIdempotencyKey;
        try {
            providerIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
                provider,
                action_digest: verification.action_digest,
                native_replay_unit: verification.native_replay_identity,
            });
            // Every key but the attempt-bound rows is derivable now; a binding Gate
            // cannot key is a refusal with no callback and no store write.
            nativeConsequenceBoundaryReservationKey({
                relying_party_id: relyingPartyId,
                operation_id: operationId,
                action_digest: verification.action_digest,
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
            native_replay_unit: verification.native_replay_identity,
            program_digest: localAuthorizationProgramDigest,
        });
        const requestDigest = nativeConsequenceBoundaryRequestDigest({
            provider,
            operation_id: operationId,
            action,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_identity,
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
            return refused('attempt_allocation_failed');
        }
        const derivedKeys = deriveNativeConsumptionKeys({
            relying_party_id: relyingPartyId,
            provider,
            operation_id: operationId,
            action_digest: verification.action_digest,
            attempt_id: attemptId,
        });
        if (!derivedKeys)
            return refused('native_consequence_binding_invalid');
        const keys = derivedKeys;
        const attemptBinding = cloneFrozen({
            ...provider,
            attempt_id: attemptId,
            request_digest: requestDigest,
            provider_idempotency_key: providerIdempotencyKey,
            operation_id: operationId,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_identity,
            trust_snapshot_id: trustSnapshotId,
            trust_snapshot_digest: trustSnapshotDigest,
            authorization_program_digest: authorizationProgramDigest,
            local_authorization_program_digest: localAuthorizationProgramDigest,
            local_decision_digest: localDecision.decision_digest,
            local_decided_at: localDecision.decided_at,
            provider_outcome_verification_program_digest: providerOutcomeVerificationProgramDigest,
        });
        // 1. The durable attempt record comes before any reservation, so every
        //    reservation below belongs to an attempt that reconcile() can find
        //    and prove never reached provider entry.
        let owner;
        try {
            const reserved = dataRecord(await reserveAttempt(attemptBinding));
            if (reserved?.reserved !== true || !opaqueOwner(reserved.owner)) {
                return refused(identifier(reserved?.reason) ? reserved.reason : 'attempt_conflict');
            }
            owner = reserved.owner;
        }
        catch {
            return refused('attempt_store_unavailable');
        }
        const attempt = {
            ...attemptBinding,
            owner,
        };
        progress.attempt = publicNativeAttempt(attempt);
        // Attempt-bound rows this call wrote or may have written (a reserve that
        // threw can still have landed). No other attempt can own these keys.
        const held = [];
        // Reservations are handed back only after the attempt itself is durably
        // RELEASED with its not-entered marker (by this call, or by a pre-entry
        // recovery that linearized first), so an attempt that is still RESERVED
        // or INVOKING keeps its fences until reconcile() proves it never entered
        // the provider.
        async function stopBeforeEntry(expected, reason) {
            const attemptReleased = notEntered(await transitionAttempt(attempt, expected, 'RELEASED'), attempt);
            if (held.length === 0)
                return refused(reason);
            if (!attemptReleased) {
                return indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
            }
            let released = true;
            for (const key of [...held].reverse()) {
                released = await custody.releaseConfirmed(key) && released;
            }
            return released
                ? refused(reason)
                : indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
        }
        // 2. Three attempt-bound reservations, in refusal-precedence order: the
        //    operation identity, the native replay key derived from (namespace,
        //    authorization ID), and the exact-action fence at this provider.
        const reservations = [
            [keys.operation, [keys.operation_fence], async () => 'consumption_conflict'],
            // The authority reservation fences the label-free replay identity key and
            // the verify 4.1.0 key of every pinned (system, profile, issuer) label
            // that shares this grant's authority namespace, the presented label's
            // `replay_key` among them. The identity key is what makes a relabelled
            // grant one spend; the 4.1.0 keys keep a grant consumed by Gate 0.26.0
            // under any of those labels, and a grant burned before a namespace
            // rotation, fenced across the upgrade.
            [
                keys.authority,
                [verification.replay_identity_key, ...verification.legacy_replay_keys],
                async () => 'native_replay_conflict',
            ],
            [keys.holder, [keys.action_fence], () => custody.actionFenceRefusal(keys.executed_marker)],
        ];
        for (const [key, fences, conflictReason] of reservations) {
            let reservation;
            try {
                reservation = await custody.reserve(key, fences);
            }
            catch {
                held.push(key);
                return stopBeforeEntry('RESERVED', 'consumption_store_unavailable');
            }
            if (reservation !== true && reservation !== 'RESERVED') {
                return stopBeforeEntry('RESERVED', await conflictReason());
            }
            held.push(key);
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
            return stopBeforeEntry('RESERVED', entryVerification.reasons[0] ?? 'native_handoff_not_verified_at_provider_entry');
        }
        // Provider entry. The durable record decides: INVOKING means this owner's
        // write landed (a lost acknowledgement included) and it proceeds as the
        // owner; RESERVED means it did not, so the attempt is first closed as not
        // entered and then released; RELEASED with the not-entered marker means a
        // pre-entry recovery linearized first, so this run hands back the rows it
        // still holds. An unreadable record is read again; if it stays
        // unreadable, this run, which has not called the provider and never will,
        // closes the attempt as not entered from either state without a read (the
        // store's compare-and-swap applies at most one), and hands its rows back
        // only once a read shows the marker. Otherwise everything stays held.
        let started = await transitionAttempt(attempt, 'RESERVED', 'INVOKING');
        if (started === null)
            started = await attemptStateRetried(attempt);
        let startReason = 'attempt_start_conflict';
        if (started === null) {
            await writeTransition(attempt, 'RESERVED', 'RELEASED');
            await writeTransition(attempt, 'INVOKING', 'RELEASED');
            started = await attemptStateRetried(attempt);
            startReason = 'attempt_start_unconfirmed';
        }
        if (started?.state !== 'INVOKING') {
            if (started?.state === 'RESERVED') {
                return stopBeforeEntry('RESERVED', startReason);
            }
            if (notEntered(started, attempt)) {
                return stopBeforeEntry('RESERVED', startReason === 'attempt_start_unconfirmed'
                    ? 'attempt_start_unconfirmed'
                    : 'attempt_released_by_recovery');
            }
            return indeterminate('attempt_start_unconfirmed', false, publicNativeAttempt(attempt));
        }
        progress.entered = true;
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
            return stopBeforeEntry('INVOKING', providerEntryVerification.reasons[0]
                ?? 'native_handoff_not_verified_at_provider_entry');
        }
        let rawOutcome;
        try {
            rawOutcome = await invoke(cloneFrozen({
                action,
                operation_id: operationId,
                action_digest: verification.action_digest,
                handoff_digest: verification.record_digest,
                native_replay_unit: verification.native_replay_identity,
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
        if (frozen?.state !== 'INDETERMINATE') {
            return indeterminate('attempt_freeze_failed', true, publicNativeAttempt(attempt));
        }
        const outcome = normalizeEffectOutcome(rawOutcome, true);
        if (!outcome)
            return indeterminate('provider_outcome_invalid', true, publicNativeAttempt(attempt));
        if (outcome.state === 'INDETERMINATE') {
            return indeterminate(outcome.reason, true, publicNativeAttempt(attempt));
        }
        if (!await verifyProviderOutcome(attemptBinding, outcome)) {
            return indeterminate('provider_outcome_authentication_failed', true, publicNativeAttempt(attempt));
        }
        return closeEnteredAttempt(attempt, attemptBinding, keys, outcome);
    }
    /**
     * Finish an attempt that entered the provider, once its authenticated
     * terminal outcome is known. The terminal record comes first and must be
     * confirmed by a durable read; only then are the one-time native
     * authorization and the operation identity burned (any terminal result
     * follows provider entry, including an authenticated NOT_COMMITTED) and the
     * action fence closed. Every step is idempotent, so a later authenticated
     * reconciliation finishes whatever an interrupted call left open.
     */
    async function closeEnteredAttempt(reference, attemptBinding, keys, outcome, recovery) {
        if (!await closeAttempt(reference, outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED', providerEvidence(attemptBinding, outcome))) {
            return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
        }
        const consume = (key, reservation) => recovery
            ? custody.closeForRecovery(key, 'CONSUMED', recovery.authorization, claimScope(keys, attemptBinding, reservation))
            : custody.closeConfirmed(key, 'CONSUMED');
        if (!await consume(keys.authority, 'native-authority')
            || !await consume(keys.operation, 'operation')) {
            return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
        }
        // The holder is keyed by this attempt, so a repeated close can never
        // reach a later attempt's fence.
        if (!await closeActionFence(keys, outcome.state === 'EXECUTED', recovery
            ? { authorization: recovery.authorization, attempt: attemptBinding }
            : undefined)) {
            return indeterminate('native_action_fence_release_unconfirmed', true, attemptBinding);
        }
        return terminalResult(outcome, attemptBinding);
    }
    const RECONCILE_KEYS = [
        'operation_id', 'handoff', 'action', 'attempt', 'outcome', 'recovery_authorization', 'mode',
    ];
    async function reconcile(input) {
        try {
            return await reconcileWithMode(input);
        }
        catch {
            return refused('boundary_internal_error');
        }
    }
    async function reconcileWithMode(input) {
        let action;
        let handoff;
        let attemptBinding;
        let operationId;
        let decisionNow;
        let rawOutcome;
        let recoveryAuthorization;
        let mode;
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
            mode = reconcileMode(record.mode);
            decisionNow = now();
            if (!identifier(operationId) || !canonicalInstant(decisionNow) || mode === null
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
            || !verification.native_replay_identity) {
            return refused(verification.reasons[0] ?? 'native_handoff_not_verified');
        }
        const derivedKeys = deriveNativeConsumptionKeys({
            relying_party_id: verification.handoff.relying_party_id,
            provider,
            operation_id: operationId,
            action_digest: verification.action_digest,
            attempt_id: attemptBinding.attempt_id,
        });
        if (!derivedKeys)
            return refused('native_consequence_binding_invalid');
        const keys = derivedKeys;
        let expectedProviderIdempotencyKey;
        try {
            expectedProviderIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
                provider,
                action_digest: verification.action_digest,
                native_replay_unit: verification.native_replay_identity,
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
            native_replay_unit: verification.native_replay_identity,
            program_digest: attemptBinding.local_authorization_program_digest,
        });
        const expectedRequestDigest = nativeConsequenceBoundaryRequestDigest({
            provider,
            operation_id: operationId,
            action,
            action_digest: verification.action_digest,
            handoff_digest: verification.record_digest,
            native_replay_unit: verification.native_replay_identity,
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
            || attemptBinding.native_replay_unit !== verification.native_replay_identity
            || attemptBinding.authorization_program_digest
                !== expectedAuthorizationProgramDigest
            || attemptBinding.local_decision_digest !== expectedLocalDecision.decision_digest
            || attemptBinding.provider_idempotency_key !== expectedProviderIdempotencyKey
            || attemptBinding.request_digest !== expectedRequestDigest) {
            return refused('reconciliation_binding_mismatch');
        }
        const outcome = normalizeEffectOutcome(rawOutcome, true);
        const recoveredState = await attemptState(recoveredReference);
        if (recoveredState === null) {
            return indeterminate('attempt_state_unavailable', true, attemptBinding);
        }
        if (mode === 'pre_entry') {
            // Pre-entry recovery. Gate calls the provider only after moving the
            // attempt to INVOKING, and writes the not-entered marker only for a
            // stop before the provider callback. The linearization point is this
            // call's own RESERVED -> RELEASED transition with that marker, confirmed
            // by a durable read (or an earlier not-entered transition, recorded with
            // the marker): after it the original run cannot reach INVOKING. The
            // caller's lookup must agree (FAILED "not found" that the verifier
            // affirms as a pre_entry_lookup, or INDETERMINATE when the provider has
            // no lookup), but it is never used as a terminal outcome: if the
            // attempt reached INVOKING first, nothing is released.
            if (!outcome)
                return indeterminate('provider_outcome_indeterminate', false, attemptBinding);
            if (outcome.state === 'EXECUTED')
                return refused('reconciliation_outcome_conflict');
            if (isUnprovenRecord(recoveredState, attemptBinding.attempt_id)) {
                return indeterminate('attempt_record_unproven', false, attemptBinding);
            }
            if (recoveredState.state === 'COMMITTED'
                || (recoveredState.state === 'RELEASED' && !notEntered(recoveredState, attemptBinding))) {
                return refused('reconciliation_outcome_conflict');
            }
            if (recoveredState.state === 'INVOKING' || recoveredState.state === 'INDETERMINATE') {
                return indeterminate('recovery_lost_to_live_attempt', true, attemptBinding);
            }
            if (outcome.state === 'FAILED'
                && !await verifyProviderOutcome(attemptBinding, outcome, 'pre_entry_lookup')) {
                return indeterminate('provider_outcome_authentication_failed', false, attemptBinding);
            }
            if (recoveredState.state === 'RESERVED') {
                const released = await transitionAttempt(recoveredReference, 'RESERVED', 'RELEASED');
                if (!notEntered(released, attemptBinding)) {
                    if (released === null)
                        return indeterminate('attempt_state_unavailable', false, attemptBinding);
                    if (isUnprovenRecord(released, attemptBinding.attempt_id)) {
                        return indeterminate('attempt_record_unproven', false, attemptBinding);
                    }
                    return released.state === 'RESERVED'
                        ? indeterminate('attempt_release_unconfirmed', false, attemptBinding)
                        : indeterminate('recovery_lost_to_live_attempt', true, attemptBinding);
                }
            }
            let released = true;
            for (const [key, reservation] of [
                [keys.holder, 'action-fence-holder'],
                [keys.authority, 'native-authority'],
                [keys.operation, 'operation'],
            ]) {
                released = await custody.releaseForRecovery(key, recoveryAuthorization, claimScope(keys, attemptBinding, reservation)) && released;
            }
            return released
                ? refused('attempt_never_entered_provider')
                : indeterminate('native_pre_entry_release_unconfirmed', false, attemptBinding);
        }
        // Terminal reconciliation: only for an attempt that reached INVOKING,
        // and only with the provider's terminal outcome for it, affirmed by the
        // verifier for purpose provider_outcome before anything changes.
        if (recoveredState.state === 'RESERVED' || notEntered(recoveredState, attemptBinding)) {
            return indeterminate('pre_entry_recovery_required', false, attemptBinding);
        }
        if (isUnprovenRecord(recoveredState, attemptBinding.attempt_id)) {
            return indeterminate('attempt_record_unproven', true, attemptBinding);
        }
        if (!outcome || outcome.state === 'INDETERMINATE') {
            return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
        }
        const terminalState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
        if ((recoveredState.state === 'COMMITTED' || recoveredState.state === 'RELEASED')
            && !terminalRecordMatches(recoveredState, terminalState, providerEvidence(attemptBinding, outcome))) {
            // A terminal record is never rewritten, and a conflicting outcome must
            // not touch the reservations that record already closed.
            return refused('reconciliation_outcome_conflict');
        }
        // Verified before the record is frozen, so a refused outcome leaves an
        // INVOKING record as it was: the live run can still finish it, and a
        // later reconcile with verified evidence can still close it.
        if (!await verifyProviderOutcome(attemptBinding, outcome)) {
            return indeterminate('provider_outcome_authentication_failed', true, attemptBinding);
        }
        if (recoveredState.state === 'INVOKING'
            && (await transitionAttempt(recoveredReference, 'INVOKING', 'INDETERMINATE'))?.state
                !== 'INDETERMINATE') {
            return indeterminate('attempt_freeze_unconfirmed', true, attemptBinding);
        }
        // After a restart the reservations may be owned by a dead process; the
        // store's authorized recovery claim takes them over, one credential
        // scoped to this attempt for all three.
        return closeEnteredAttempt(recoveredReference, attemptBinding, keys, outcome, { authorization: recoveryAuthorization });
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
    consequenceBoundaryActionFenceHolderKey,
    consequenceBoundaryRecoveryClaimKey,
    consequenceBoundaryRecoveryClaimMarkerKey,
    consequenceBoundaryRecoveryAttemptIdentity,
    CONSEQUENCE_BOUNDARY_NOT_ENTERED,
    nativeConsequenceBoundaryReservationKey,
    nativeConsequenceBoundaryActionFenceKey,
    nativeConsequenceBoundaryAttemptReservationKeys,
    nativeConsequenceBoundaryActionFenceHolderKey,
    nativeConsequenceBoundaryProviderIdempotencyKey,
    nativeConsequenceBoundaryRequestDigest,
    createNativeConsequenceBoundary,
});
//# sourceMappingURL=consequence-boundary.js.map