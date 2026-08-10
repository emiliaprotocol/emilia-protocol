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
import {
  aebReservationKey,
  authorizeAebExecutionDurable,
  digestAeb,
  reconcileAebExecutionDurable,
  verifyAebEvaluation,
  type AebAdapter,
  type AebDurableConsumptionStore,
  type AebEvaluationRecord,
  type AebPinnedConfig,
  type AebStatusInput,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import { AP2_NATIVE_AEB_ADAPTER_ID } from '@emilia-protocol/verify/ap2-native-adapter';
import {
  A2A_AP2_NATIVE_PRESENTATION_METHOD,
  verifyA2AAuthorizationChallengeTask,
} from '@emilia-protocol/verify/a2a-evidence-challenge';

import {
  type ConsequenceActuator,
  type ConsequenceActuatorExecutionInput,
  type ConsequenceActuatorExecutionResult,
} from './consequence-actuator.js';

type Obj = Record<string, any>;

export const A2A_AP2_GATE_PROFILE_VERSION = 'EP-A2A-AP2-GATE-EXPERIMENTAL-v1';

export interface A2AAp2ChallengeStore {
  readonly durable: true;
  readonly atomicRegistration: true;
  readonly bodyBound: true;
  readonly permanentConsumption: true;
  /** Atomically consumes an exact, previously registered challenge body. */
  consume(challenge: unknown): Promise<boolean>;
}

export interface A2AAp2ResolvedAction {
  expected_action: unknown;
  expected_caid: string;
}

export interface A2AAp2ResolutionContext {
  task_id: string;
  context_id: string;
  evaluation: AebEvaluationRecord;
  artifacts: Readonly<Record<string, unknown>>;
}

export interface A2AAp2GateOptions<TResult> {
  aeb_config: AebPinnedConfig;
  adapters: Record<string, AebAdapter>;
  aeb_store: AebDurableConsumptionStore;
  challenge_store: A2AAp2ChallengeStore;
  actuator: ConsequenceActuator<TResult>;
  now(): string;
  resolve_action(input: Readonly<{ task_id: string; context_id: string }>):
    Promise<A2AAp2ResolvedAction> | A2AAp2ResolvedAction;
  resolve_current_statuses(input: Readonly<A2AAp2ResolutionContext>):
    Promise<Record<string, AebStatusInput>> | Record<string, AebStatusInput>;
  authorize_local(input: Readonly<A2AAp2ResolutionContext & A2AAp2ResolvedAction>):
    Promise<boolean> | boolean;
  resolve_execution(input: Readonly<A2AAp2ResolutionContext & A2AAp2ResolvedAction>):
    Promise<ConsequenceActuatorExecutionInput> | ConsequenceActuatorExecutionInput;
}

export interface A2AAp2GateExecutionInput {
  task: unknown;
  evaluation: unknown;
  /** Native artifacts keyed by the exact artifact_ref in the signed AEB record. */
  artifacts: Record<string, unknown>;
}

export interface A2AAp2NativeAuthorizationScope {
  protocol: 'AP2';
  artifact_refs: readonly string[];
  emilia_originated: false;
}

interface DecisionBase {
  profile: typeof A2A_AP2_GATE_PROFILE_VERSION;
  invoked: boolean;
  retry_allowed: boolean;
  reason: string;
  native_authorization: A2AAp2NativeAuthorizationScope;
  aeb_reservation_key?: string;
}

export type A2AAp2GateDecision<TResult> =
  | (DecisionBase & { state: 'ADMIT'; invoked: true; retry_allowed: false; result: TResult })
  | (DecisionBase & { state: 'REFUSE'; invoked: false })
  | (DecisionBase & { state: 'INDETERMINATE'; retry_allowed: false });

function isObject(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactTaskReference(value: unknown): { task_id: string; context_id: string } | null {
  if (!isObject(value) || typeof value.id !== 'string' || value.id.length === 0
      || typeof value.contextId !== 'string' || value.contextId.length === 0) return null;
  return { task_id: value.id, context_id: value.contextId };
}

function nativeScope(record: unknown): A2AAp2NativeAuthorizationScope {
  const refs = isObject(record) && Array.isArray(record.legs)
    ? record.legs
      .filter((leg: unknown) => isObject(leg) && leg.adapter_id === AP2_NATIVE_AEB_ADAPTER_ID
        && typeof leg.artifact_ref === 'string')
      .map((leg: Obj) => leg.artifact_ref)
    : [];
  return Object.freeze({
    protocol: 'AP2' as const,
    artifact_refs: Object.freeze([...new Set(refs)].sort()),
    emilia_originated: false as const,
  });
}

function recordArtifactRefs(record: AebEvaluationRecord): string[] {
  const refs = new Set<string>();
  for (const leg of record.legs) {
    if (typeof leg.artifact_ref === 'string') refs.add(leg.artifact_ref);
  }
  return [...refs].sort();
}

function base(record: unknown, reason: string, reservationKey?: string): DecisionBase {
  return {
    profile: A2A_AP2_GATE_PROFILE_VERSION,
    invoked: false,
    retry_allowed: false,
    reason,
    native_authorization: nativeScope(record),
    ...(reservationKey ? { aeb_reservation_key: reservationKey } : {}),
  };
}

function refuse(record: unknown, reason: string): A2AAp2GateDecision<never> {
  return Object.freeze({ ...base(record, reason), state: 'REFUSE' as const, invoked: false as const });
}

function indeterminate(
  record: unknown,
  reason: string,
  invoked = false,
  reservationKey?: string,
): A2AAp2GateDecision<never> {
  return Object.freeze({
    ...base(record, reason, reservationKey),
    state: 'INDETERMINATE' as const,
    invoked,
    retry_allowed: false as const,
  });
}

function currentStatusDisposition(
  statuses: Record<string, AebStatusInput>,
  requiredRefs: readonly string[],
  now: string,
): { state: 'CURRENT' | 'REFUSE' | 'INDETERMINATE'; reason: string } {
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) return { state: 'INDETERMINATE', reason: 'verification_time_invalid' };
  for (const ref of requiredRefs) {
    const status = statuses?.[ref];
    if (!isObject(status)) return { state: 'INDETERMINATE', reason: 'current_status_missing' };
    if (status.revoked === true) return { state: 'REFUSE', reason: 'evidence_revoked' };
    if (status.consumed === true) return { state: 'REFUSE', reason: 'evidence_already_consumed' };
    if (status.unavailable === true) return { state: 'INDETERMINATE', reason: 'current_status_unavailable' };
    if (status.revocation_checked !== true) return { state: 'INDETERMINATE', reason: 'revocation_not_checked' };
    const checkedAt = Date.parse(status.checked_at);
    const expiresAt = Date.parse(status.expires_at);
    if (!Number.isFinite(checkedAt) || !Number.isFinite(expiresAt)
        || checkedAt > nowMs || expiresAt <= nowMs) {
      return { state: 'INDETERMINATE', reason: 'current_status_stale' };
    }
  }
  return { state: 'CURRENT', reason: 'current_status_verified' };
}

function challengeProfileValid(challenge: Obj, relyingPartyId: string): boolean {
  return challenge.audience === relyingPartyId
    && Array.isArray(challenge.present_as)
    && challenge.present_as.includes(A2A_AP2_NATIVE_PRESENTATION_METHOD)
    && Array.isArray(challenge.required_evidence)
    && challenge.required_evidence.some((requirement: unknown) => isObject(requirement)
      && requirement.type === 'ap2-native-authorization');
}

function actuatorReason<TResult>(result: ConsequenceActuatorExecutionResult<TResult>): string {
  return result.ok ? 'provider_effect_committed' : result.reason;
}

function secureChallengeStore(value: unknown): value is A2AAp2ChallengeStore {
  return isObject(value) && value.durable === true && value.atomicRegistration === true
    && value.bodyBound === true && value.permanentConsumption === true
    && typeof value.consume === 'function';
}

export class A2AAp2Gate<TResult = unknown> {
  readonly #options: A2AAp2GateOptions<TResult>;

  constructor(options: A2AAp2GateOptions<TResult>) {
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

  async execute(input: A2AAp2GateExecutionInput): Promise<A2AAp2GateDecision<TResult>> {
    const taskRef = exactTaskReference(input?.task);
    if (!taskRef) return refuse(input?.evaluation, 'malformed_a2a_task_reference');
    if (!isObject(input?.evaluation)) return refuse(input?.evaluation, 'aeb_evaluation_required');
    const record = input.evaluation as AebEvaluationRecord;
    const scope = nativeScope(record);
    if (scope.artifact_refs.length === 0) return refuse(record, 'native_ap2_evidence_required');

    let resolved: A2AAp2ResolvedAction;
    let now: string;
    try {
      resolved = await this.#options.resolve_action(taskRef);
      now = this.#options.now();
      digestAeb(resolved?.expected_action);
    } catch {
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
    if (record.operation_id !== taskRef.task_id) return refuse(record, 'a2a_task_aeb_operation_mismatch');
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

    const context: A2AAp2ResolutionContext = {
      ...taskRef,
      evaluation: record,
      artifacts: Object.freeze({ ...(input.artifacts ?? {}) }),
    };
    let statuses: Record<string, AebStatusInput>;
    let localAuthorization: boolean;
    let execution: ConsequenceActuatorExecutionInput;
    try {
      statuses = await this.#options.resolve_current_statuses(context);
      localAuthorization = await this.#options.authorize_local({ ...context, ...resolved });
      execution = await this.#options.resolve_execution({ ...context, ...resolved });
    } catch {
      return indeterminate(record, 'executor_policy_resolution_failed');
    }
    if (!isObject(statuses)) return indeterminate(record, 'current_status_resolution_failed');
    const status = currentStatusDisposition(statuses, recordArtifactRefs(record), now);
    if (status.state === 'REFUSE') return refuse(record, status.reason);
    if (status.state === 'INDETERMINATE') return indeterminate(record, status.reason);
    if (localAuthorization !== true) return refuse(record, 'local_authorization_denied');
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
    } catch {
      return indeterminate(record, 'challenge_store_unavailable');
    }
    if (!challengeClaimed) return refuse(record, 'challenge_unregistered_or_replayed');

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
      const released = await reconcileAebExecutionDurable(
        this.#options.aeb_store,
        reservationKey,
        'NOT_COMMITTED',
      );
      if (released.state !== 'AVAILABLE') {
        return indeterminate(record, released.reason, false, reservationKey);
      }
      return Object.freeze({
        ...base(record, effect.reason),
        state: 'REFUSE' as const,
        invoked: false as const,
      });
    }

    const committed = await reconcileAebExecutionDurable(
      this.#options.aeb_store,
      reservationKey,
      'COMMITTED',
    );
    if (committed.state !== 'CONSUMED') {
      return indeterminate(record, committed.reason, true, reservationKey);
    }
    return Object.freeze({
      ...base(record, 'provider_effect_committed', reservationKey),
      state: 'ADMIT' as const,
      invoked: true as const,
      retry_allowed: false as const,
      result: effect.result,
    });
  }
}

export function a2aAp2ReservationKey(record: AebEvaluationRecord): string {
  return aebReservationKey(record);
}
