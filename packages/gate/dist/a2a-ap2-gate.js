// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Experimental A2A/AP2 consequence-admission profile.
 *
 * A2A carries the authorization interruption and AE-CHALLENGE. AP2 remains
 * native evidence verified by a relying-party-pinned AP2 adapter. AEB joins
 * every required evidence leg to one executor-derived CAID. Gate claims the
 * issued challenge and atomically reserves the evaluation, native replay
 * identities, and A2A task before the credential-owning actuator may enter the
 * provider.
 *
 * The request supplies only the A2A task, signed AEB evaluation, and native
 * artifacts. Expected action, status, local policy, time, and execution
 * envelope are executor-owned dependencies and cannot be selected by a
 * presenter.
 */
import { aebReservationKey, authorizeAebExecutionDurable, digestAeb, reconcileAebExecutionDurable, verifyAebEvaluation, } from '@emilia-protocol/verify/aeb-adapter-contract';
import { AP2_NATIVE_AEB_ADAPTER_ID } from '@emilia-protocol/verify/ap2-native-adapter';
import { A2A_AP2_NATIVE_PRESENTATION_METHOD, verifyA2AAuthorizationChallengeTask, } from '@emilia-protocol/verify/a2a-evidence-challenge';
export const A2A_AP2_GATE_PROFILE_VERSION = 'EP-A2A-AP2-GATE-EXPERIMENTAL-v1';
function isObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactTaskReference(value) {
    if (!isObject(value) || typeof value.id !== 'string' || value.id.length === 0
        || typeof value.contextId !== 'string' || value.contextId.length === 0)
        return null;
    return { task_id: value.id, context_id: value.contextId };
}
function nativeScope(record) {
    const refs = isObject(record) && Array.isArray(record.legs)
        ? record.legs
            .filter((leg) => isObject(leg) && leg.adapter_id === AP2_NATIVE_AEB_ADAPTER_ID
            && typeof leg.artifact_ref === 'string')
            .map((leg) => leg.artifact_ref)
        : [];
    return Object.freeze({
        protocol: 'AP2',
        artifact_refs: Object.freeze([...new Set(refs)].sort()),
        emilia_originated: false,
    });
}
function recordArtifactRefs(record) {
    const refs = new Set();
    for (const leg of record.legs) {
        if (typeof leg.artifact_ref === 'string')
            refs.add(leg.artifact_ref);
    }
    return [...refs].sort();
}
function base(record, reason, reservationKey) {
    return {
        profile: A2A_AP2_GATE_PROFILE_VERSION,
        invoked: false,
        retry_allowed: false,
        reason,
        native_authorization: nativeScope(record),
        ...(reservationKey ? { aeb_reservation_key: reservationKey } : {}),
    };
}
function refuse(record, reason) {
    return Object.freeze({ ...base(record, reason), state: 'REFUSE', invoked: false });
}
function indeterminate(record, reason, invoked = false, reservationKey) {
    return Object.freeze({
        ...base(record, reason, reservationKey),
        state: 'INDETERMINATE',
        invoked,
        retry_allowed: false,
    });
}
function currentStatusDisposition(statuses, requiredRefs, now) {
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs))
        return { state: 'INDETERMINATE', reason: 'verification_time_invalid' };
    for (const ref of requiredRefs) {
        const status = statuses?.[ref];
        if (!isObject(status))
            return { state: 'INDETERMINATE', reason: 'current_status_missing' };
        if (status.revoked === true)
            return { state: 'REFUSE', reason: 'evidence_revoked' };
        if (status.consumed === true)
            return { state: 'REFUSE', reason: 'evidence_already_consumed' };
        if (status.unavailable === true)
            return { state: 'INDETERMINATE', reason: 'current_status_unavailable' };
        if (status.revocation_checked !== true)
            return { state: 'INDETERMINATE', reason: 'revocation_not_checked' };
        const checkedAt = Date.parse(status.checked_at);
        const expiresAt = Date.parse(status.expires_at);
        if (!Number.isFinite(checkedAt) || !Number.isFinite(expiresAt)
            || checkedAt > nowMs || expiresAt <= nowMs) {
            return { state: 'INDETERMINATE', reason: 'current_status_stale' };
        }
    }
    return { state: 'CURRENT', reason: 'current_status_verified' };
}
function challengeProfileValid(challenge, relyingPartyId) {
    return challenge.audience === relyingPartyId
        && Array.isArray(challenge.present_as)
        && challenge.present_as.includes(A2A_AP2_NATIVE_PRESENTATION_METHOD)
        && Array.isArray(challenge.required_evidence)
        && challenge.required_evidence.some((requirement) => isObject(requirement)
            && requirement.type === 'ap2-native-authorization');
}
function actuatorReason(result) {
    return result.ok ? 'provider_effect_committed' : result.reason;
}
function secureChallengeStore(value) {
    return isObject(value) && value.durable === true && value.atomicRegistration === true
        && value.bodyBound === true && value.permanentConsumption === true
        && typeof value.consume === 'function';
}
export class A2AAp2Gate {
    #options;
    constructor(options) {
        if (!isObject(options) || !isObject(options.aeb_config)
            || !isObject(options.adapters) || !isObject(options.aeb_store)
            || typeof options.aeb_store.reserve !== 'function'
            || typeof options.aeb_store.commit !== 'function'
            || typeof options.aeb_store.release !== 'function'
            || !secureChallengeStore(options.challenge_store)
            || !isObject(options.actuator) || typeof options.actuator.execute !== 'function'
            || typeof options.now !== 'function' || typeof options.resolve_action !== 'function'
            || typeof options.resolve_current_statuses !== 'function'
            || typeof options.authorize_local !== 'function'
            || typeof options.resolve_execution !== 'function') {
            throw new TypeError('A2A/AP2 Gate requires executor-owned resolution, durable custody, and a consequence actuator');
        }
        this.#options = Object.freeze({ ...options, adapters: Object.freeze({ ...options.adapters }) });
        Object.freeze(this);
    }
    async execute(input) {
        const taskRef = exactTaskReference(input?.task);
        if (!taskRef)
            return refuse(input?.evaluation, 'malformed_a2a_task_reference');
        if (!isObject(input?.evaluation))
            return refuse(input?.evaluation, 'aeb_evaluation_required');
        const record = input.evaluation;
        const scope = nativeScope(record);
        if (scope.artifact_refs.length === 0)
            return refuse(record, 'native_ap2_evidence_required');
        let resolved;
        let now;
        try {
            resolved = await this.#options.resolve_action(taskRef);
            now = this.#options.now();
            digestAeb(resolved?.expected_action);
        }
        catch {
            return indeterminate(record, 'executor_action_resolution_failed');
        }
        if (!isObject(resolved) || typeof resolved.expected_caid !== 'string') {
            return indeterminate(record, 'executor_action_resolution_failed');
        }
        const challengeCheck = verifyA2AAuthorizationChallengeTask(input.task, resolved.expected_action, now);
        if (!challengeCheck.valid || !isObject(challengeCheck.challenge)) {
            return refuse(record, challengeCheck.reasons[0] ?? 'a2a_authorization_challenge_invalid');
        }
        if (!challengeProfileValid(challengeCheck.challenge, this.#options.aeb_config.relying_party_id)) {
            return refuse(record, 'a2a_authorization_challenge_profile_mismatch');
        }
        const actionDigest = digestAeb(resolved.expected_action);
        if (record.operation_id !== taskRef.task_id)
            return refuse(record, 'a2a_task_aeb_operation_mismatch');
        if (record.consumption_nonce !== challengeCheck.challenge.nonce) {
            return refuse(record, 'a2a_challenge_aeb_nonce_mismatch');
        }
        const ap2Legs = record.legs.filter((leg) => leg.adapter_id === AP2_NATIVE_AEB_ADAPTER_ID);
        if (record.caid !== resolved.expected_caid
            || ap2Legs.length === 0
            || ap2Legs.some((leg) => leg.action_digest !== actionDigest)) {
            return refuse(record, 'aeb_exact_action_mismatch');
        }
        if (scope.artifact_refs.some((ref) => !Object.hasOwn(input.artifacts ?? {}, ref))) {
            return refuse(record, 'native_ap2_artifact_missing');
        }
        const context = {
            ...taskRef,
            evaluation: record,
            artifacts: Object.freeze({ ...(input.artifacts ?? {}) }),
        };
        let statuses;
        let localAuthorization;
        let execution;
        try {
            statuses = await this.#options.resolve_current_statuses(context);
            localAuthorization = await this.#options.authorize_local({ ...context, ...resolved });
            execution = await this.#options.resolve_execution({ ...context, ...resolved });
        }
        catch {
            return indeterminate(record, 'executor_policy_resolution_failed');
        }
        if (!isObject(statuses))
            return indeterminate(record, 'current_status_resolution_failed');
        const status = currentStatusDisposition(statuses, recordArtifactRefs(record), now);
        if (status.state === 'REFUSE')
            return refuse(record, status.reason);
        if (status.state === 'INDETERMINATE')
            return indeterminate(record, status.reason);
        if (localAuthorization !== true)
            return refuse(record, 'local_authorization_denied');
        if (!isObject(execution) || execution.attemptId !== taskRef.task_id
            || execution.actionDigest !== actionDigest) {
            return refuse(record, 'a2a_task_actuator_binding_mismatch');
        }
        const verification = verifyAebEvaluation(record, {
            config: this.#options.aeb_config,
            adapters: this.#options.adapters,
            mode: 'execution',
            expected_action: resolved.expected_action,
            artifacts: input.artifacts,
            current_statuses: statuses,
            now,
        });
        if (!verification.valid || !verification.execution_authorizing) {
            return record.verdict === 'INDETERMINATE'
                ? indeterminate(record, 'aeb_execution_verification_indeterminate')
                : refuse(record, 'aeb_execution_verification_failed');
        }
        let challengeClaimed = false;
        try {
            challengeClaimed = await this.#options.challenge_store.consume(challengeCheck.challenge);
        }
        catch {
            return indeterminate(record, 'challenge_store_unavailable');
        }
        if (!challengeClaimed)
            return refuse(record, 'challenge_unregistered_or_replayed');
        const additionalReplayKeys = [
            `a2a-task:${digestAeb({
                relying_party_id: this.#options.aeb_config.relying_party_id,
                task_id: taskRef.task_id,
                context_id: taskRef.context_id,
            })}`,
            `ae-challenge:${digestAeb({
                relying_party_id: this.#options.aeb_config.relying_party_id,
                challenge_id: challengeCheck.challenge.challenge_id,
                nonce: challengeCheck.challenge.nonce,
                action_digest: challengeCheck.challenge.action_digest,
            })}`,
        ];
        const authorization = await authorizeAebExecutionDurable(record, {
            verification,
            local_authorization: localAuthorization,
            store: this.#options.aeb_store,
            additional_replay_keys: additionalReplayKeys,
        });
        if (authorization.state === 'RECONCILIATION_REQUIRED') {
            return indeterminate(record, authorization.reason);
        }
        if (authorization.state !== 'AUTHORIZED' || !authorization.reservation_key) {
            return refuse(record, authorization.reason);
        }
        const reservationKey = authorization.reservation_key;
        const effect = await this.#options.actuator.execute(execution);
        if (!effect.ok) {
            if (effect.invoked) {
                return indeterminate(record, actuatorReason(effect), true, reservationKey);
            }
            const released = await reconcileAebExecutionDurable(this.#options.aeb_store, reservationKey, 'NOT_COMMITTED');
            if (released.state !== 'AVAILABLE') {
                return indeterminate(record, released.reason, false, reservationKey);
            }
            return Object.freeze({
                ...base(record, effect.reason),
                state: 'REFUSE',
                invoked: false,
            });
        }
        const committed = await reconcileAebExecutionDurable(this.#options.aeb_store, reservationKey, 'COMMITTED');
        if (committed.state !== 'CONSUMED') {
            return indeterminate(record, committed.reason, true, reservationKey);
        }
        return Object.freeze({
            ...base(record, 'provider_effect_committed', reservationKey),
            state: 'ADMIT',
            invoked: true,
            retry_allowed: false,
            result: effect.result,
        });
    }
}
export function a2aAp2ReservationKey(record) {
    return aebReservationKey(record);
}
//# sourceMappingURL=a2a-ap2-gate.js.map