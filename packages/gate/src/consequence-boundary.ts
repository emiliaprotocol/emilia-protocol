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
 * keyed the same way. The durable attempt record is written before any
 * attempt-keyed reservation, so an attempt that stops before provider entry
 * can be found and recovered through reconcile().
 */

import crypto from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import {
  aebReservationKey,
  authorizeAebExecutionDurable,
  canonicalizeAeb,
  digestAeb,
  reconcileAebExecutionDurable,
  verifyAebEvaluation,
  type AebAdapter,
  type AebConsumptionState,
  type AebDigest,
  type AebDurableConsumptionStore,
  type AebEvaluationRecord,
  type AebPinnedConfig,
  type AebStatusInput,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import type { AebExecutionConditionsResult } from '@emilia-protocol/verify/aeb-execution-conditions';
import {
  digestAebNativeAuthorizationAction,
  verifyAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationPins,
  type AebNativeAuthorizationDigest,
  type AebNativeAuthorizationHandoff,
  type AebNativeAuthorizationHandoffVerification,
  type AebNativeAuthorizationPins,
  type AebNativeAuthorizationStatus,
} from '@emilia-protocol/verify/aeb';
import type { AebRecoveryClaimScope } from './aeb-consumption-store.js';
import type {
  ConsequenceEnvelopeBoundary,
  ConsequenceEnvelopeReservation,
} from './consequence-envelope.js';

export const CONSEQUENCE_BOUNDARY_VERSION = 'EMILIA-CONSEQUENCE-BOUNDARY-v1';
export const CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN =
  'EMILIA-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_VERSION =
  'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_PROVIDER_IDEMPOTENCY_DOMAIN =
  'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-PROVIDER-IDEMPOTENCY-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_TRUST_SNAPSHOT_DOMAIN =
  'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-TRUST-SNAPSHOT-v1';
export const NATIVE_CONSEQUENCE_BOUNDARY_LOCAL_DECISION_DOMAIN =
  'EMILIA-NATIVE-CONSEQUENCE-BOUNDARY-LOCAL-DECISION-v1';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const AUTHORIZATION_INSTANCE = /^[A-Za-z0-9_.:-]{1,256}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

type JsonObject = Record<string, unknown>;

export interface ConsequenceBoundaryProvider {
  tenant_id: string;
  provider_id: string;
  provider_account_id: string;
  environment: string;
}

export interface ConsequenceBoundaryAttemptBinding
  extends ConsequenceBoundaryProvider {
  attempt_id: string;
  request_digest: AebDigest;
  /**
   * Stable for retries and reconciliation of this authorization instance.
   * A provider adapter MUST pass it unchanged to any native idempotency API.
   * The key alone does not assert that the provider offers such semantics.
   */
  provider_idempotency_key: string;
}

declare const CONSEQUENCE_BOUNDARY_OWNER: unique symbol;
export type ConsequenceBoundaryOwnerHandle = string & {
  readonly [CONSEQUENCE_BOUNDARY_OWNER]: true;
};

export interface ConsequenceBoundaryAttemptReference
  extends ConsequenceBoundaryAttemptBinding {
  /** Opaque custody capability. It MUST NOT cross an untrusted API boundary. */
  owner: ConsequenceBoundaryOwnerHandle;
}

export type ConsequenceBoundaryAttemptTransition =
  | { expected_state: 'RESERVED'; next_state: 'INVOKING' }
  | { expected_state: 'RESERVED'; next_state: 'RELEASED' }
  | { expected_state: 'INVOKING'; next_state: 'INDETERMINATE' }
  | { expected_state: 'INVOKING'; next_state: 'RELEASED' };

export interface ConsequenceBoundaryProviderEvidence
  extends ConsequenceBoundaryAttemptBinding {
  operation_id: string;
  caid: string;
  action_digest: AebDigest;
  evidence_id: string;
  observed_at: string;
  outcome: 'COMMITTED' | 'NOT_COMMITTED';
  evidence_digest: AebDigest;
}

/** Durable, owner-fenced dispatch custody. */
export interface ConsequenceBoundaryAttemptStore<
  TProviderEvidence = ConsequenceBoundaryProviderEvidence,
> {
  durable: true;
  ownershipFenced: true;
  compareAndSwap: true;
  atomicEvidenceBinding: true;
  reserve(binding: ConsequenceBoundaryAttemptBinding): Promise<
    | { reserved: true; owner: ConsequenceBoundaryOwnerHandle }
    | { reserved: false; reason: string }
  >;
  transition(
    input: ConsequenceBoundaryAttemptReference
      & ConsequenceBoundaryAttemptTransition,
  ): Promise<boolean>;
  reconcile(input: ConsequenceBoundaryAttemptReference & {
    expected_state: 'INDETERMINATE';
    next_state: 'COMMITTED' | 'RELEASED';
    evidence: TProviderEvidence;
  }): Promise<boolean>;
  /** Required by the direct-native path for idempotent close after lost acks. */
  state?(input: ConsequenceBoundaryAttemptReference): Promise<{
    state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
    evidence?: TProviderEvidence;
  }>;
}

export interface ConsequenceBoundaryEvidence {
  evidence_id: string;
  observed_at: string;
  evidence_digest: AebDigest;
}

export type ConsequenceBoundaryEffectOutcome<TResult> =
  | {
    state: 'EXECUTED';
    /** Authenticated provider evidence for this exact attempt and action. */
    evidence: ConsequenceBoundaryEvidence;
    result: TResult;
  }
  | {
    state: 'FAILED';
    /** Authoritative evidence that the protected effect did not occur. */
    evidence: ConsequenceBoundaryEvidence;
    reason: string;
  }
  | {
    state: 'INDETERMINATE';
    reason: string;
  };

export interface ConsequenceBoundaryEffectContext {
  action: unknown;
  operation_id: string;
  caid: string;
  evaluation_digest: AebDigest;
  authorization_program_digest: AebDigest;
  provider_idempotency_key: string;
  attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
}

export interface ConsequenceBoundaryAuthorizationContext {
  action: unknown;
  evaluation: Readonly<AebEvaluationRecord>;
  evaluation_digest: AebDigest;
  provider: Readonly<ConsequenceBoundaryProvider>;
}

export interface ConsequenceBoundaryOptions<TResult> {
  executor_id: string;
  provider: ConsequenceBoundaryProvider;
  aeb: {
    config: AebPinnedConfig;
    adapters: Record<string, AebAdapter>;
    /**
     * Durable consumption store. Besides the evaluation reservation it holds
     * one action-fence holder per attempt, keyed by the attempt
     * (consequenceBoundaryActionFenceHolderKey), which fences the exact action
     * at this provider under `config.relying_party_id`. A durable `state()`
     * read confirms lost acknowledgements; `terminalRelease` plus
     * `recoveryClaimSupported` (the shipped PostgreSQL store) let
     * reconcile() finish after a restart and close a stopped attempt's
     * evaluation reservation as RELEASED_NOT_ENTERED.
     */
    store: AebDurableConsumptionStore & {
      state?(key: string): AebConsumptionState | Promise<AebConsumptionState>;
      recoveryClaimSupported?: true;
      claimReservation?(
        key: string,
        authorization: unknown,
        scope?: AebRecoveryClaimScope,
      ): Promise<boolean>;
    };
  };
  attempts: {
    /**
     * Durable attempt custody. With `state()`, reconcile() can prove a stop
     * before provider entry (RESERVED, or RELEASED without evidence) and
     * release that attempt's action fence; without it only a terminal
     * provider outcome can close an attempt.
     */
    store: ConsequenceBoundaryAttemptStore;
    create_id?: (input: {
      operation_id: string;
      request_digest: AebDigest;
    }) => string | Promise<string>;
    /** Recover owner-fenced custody under a separate authenticated path. */
    recover(input: {
      attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
      recovery_authorization: unknown;
    }): ConsequenceBoundaryAttemptReference | null
      | Promise<ConsequenceBoundaryAttemptReference | null>;
  };
  local_authorize(
    context: Readonly<ConsequenceBoundaryAuthorizationContext>,
  ): boolean | Promise<boolean>;
  invoke(
    context: Readonly<ConsequenceBoundaryEffectContext>,
  ): ConsequenceBoundaryEffectOutcome<TResult>
    | Promise<ConsequenceBoundaryEffectOutcome<TResult>>;
  /** Optional state-domain-owned capacity reservation before provider entry. */
  consequence_envelope?: ConsequenceEnvelopeBoundary;
  /** Conformance-only escape hatch for a process-local envelope reference. */
  allow_test_consequence_envelope?: true;
  now?: () => string;
}

export interface ConsequenceBoundaryRunInput {
  evaluation: unknown;
  action: unknown;
  artifacts: Record<string, unknown>;
  current_statuses: Record<string, AebStatusInput>;
  execution_conditions?: AebExecutionConditionsResult;
  additional_replay_keys?: readonly string[];
}

export interface ConsequenceBoundaryReconcileInput<TResult> {
  evaluation: unknown;
  action: unknown;
  artifacts: Record<string, unknown>;
  attempt: unknown;
  outcome: ConsequenceBoundaryEffectOutcome<TResult>;
  recovery_authorization: unknown;
}

export interface NativeConsequenceBoundaryProviderEvidence
  extends NativeConsequenceBoundaryAttemptBinding {
  evidence_id: string;
  observed_at: string;
  outcome: 'COMMITTED' | 'NOT_COMMITTED';
  evidence_digest: AebDigest;
}

export interface NativeConsequenceBoundaryLocalDecision {
  decision: 'PERMIT';
  decided_at: string;
  program_digest: AebDigest;
  decision_digest: AebDigest;
}

export interface NativeConsequenceBoundaryAttemptBinding
  extends ConsequenceBoundaryAttemptBinding {
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  handoff_digest: AebNativeAuthorizationDigest;
  native_replay_unit: AebNativeAuthorizationDigest;
  trust_snapshot_id: string;
  trust_snapshot_digest: AebDigest;
  authorization_program_digest: AebDigest;
  local_authorization_program_digest: AebDigest;
  local_decision_digest: AebDigest;
  local_decided_at: string;
  provider_outcome_verification_program_digest: AebDigest;
}

export interface NativeConsequenceBoundaryAttemptReference
  extends NativeConsequenceBoundaryAttemptBinding {
  owner: ConsequenceBoundaryOwnerHandle;
}

export interface NativeConsequenceBoundaryProviderOutcomeVerificationContext<TResult> {
  provider: Readonly<ConsequenceBoundaryProvider>;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  native_replay_unit: AebNativeAuthorizationDigest;
  verification_program_digest: AebDigest;
  attempt: Readonly<NativeConsequenceBoundaryAttemptBinding>;
  outcome: Readonly<Exclude<ConsequenceBoundaryEffectOutcome<TResult>, { state: 'INDETERMINATE' }>>;
}

export interface NativeConsequenceBoundaryAuthorizationContext {
  action: unknown;
  handoff: Readonly<AebNativeAuthorizationHandoff>;
  verification: Readonly<AebNativeAuthorizationHandoffVerification>;
  provider: Readonly<ConsequenceBoundaryProvider>;
  local_authorization_program_digest: AebDigest;
}

export interface NativeConsequenceBoundaryEffectContext {
  action: unknown;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  handoff_digest: AebNativeAuthorizationDigest;
  native_replay_unit: AebNativeAuthorizationDigest;
  authorization_program_digest: AebDigest;
  local_authorization: Readonly<NativeConsequenceBoundaryLocalDecision>;
  trust_snapshot_id: string;
  trust_snapshot_digest: AebDigest;
  provider_outcome_verification_program_digest: AebDigest;
  provider_idempotency_key: string;
  attempt: Readonly<NativeConsequenceBoundaryAttemptBinding>;
}

export interface NativeConsequenceBoundaryOptions<TResult> {
  executor_id: string;
  provider: ConsequenceBoundaryProvider;
  native_authorization: {
    /** `pins.relying_party_id` must also satisfy the Gate identifier grammar. */
    pins: AebNativeAuthorizationPins;
    /** Stable operator identifier for the exact accepted pins below. */
    trust_snapshot_id: string;
    /**
     * Durable consumption store. Each attempt writes three reservations, all
     * keyed by its attempt ID (nativeConsequenceBoundaryAttemptReservationKeys):
     * the operation reservation fences the operation identity, the
     * authority reservation fences the native replay key, and the holder
     * reservation fences the exact action at this provider. `state()` must be
     * a durable read. A store whose commit and release are fenced to the
     * reserving process (the shipped PostgreSQL store) must also declare
     * `recoveryClaimSupported: true` so reconciliation after a restart can
     * claim them. Every claim for one attempt carries the same
     * `recovery_authorization` and a scope naming the attempt, so one
     * credential bound to the attempt (or its operation key) covers all three.
     */
    store: AebDurableConsumptionStore & {
      state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
      recoveryClaimSupported?: true;
      claimReservation?(
        key: string,
        authorization: unknown,
        scope?: AebRecoveryClaimScope,
      ): Promise<boolean>;
    };
    /** Trusted status source. It receives only a preverified pinned handoff. */
    resolve_status(
      handoff: Readonly<AebNativeAuthorizationHandoff>,
    ): AebNativeAuthorizationStatus | Promise<AebNativeAuthorizationStatus>;
    /** Retrieve an archived trust snapshot during authenticated reconciliation. */
    resolve_historical_pins(input: {
      trust_snapshot_id: string;
      trust_snapshot_digest: AebDigest;
    }): AebNativeAuthorizationPins | null
      | Promise<AebNativeAuthorizationPins | null>;
  };
  attempts: {
    store: ConsequenceBoundaryAttemptStore<NativeConsequenceBoundaryProviderEvidence> & {
      state(input: NativeConsequenceBoundaryAttemptReference): Promise<{
        state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
        evidence?: NativeConsequenceBoundaryProviderEvidence;
      }>;
    };
    create_id?: (input: {
      operation_id: string;
      request_digest: AebDigest;
    }) => string | Promise<string>;
    recover(input: {
      attempt: Readonly<ConsequenceBoundaryAttemptBinding>;
      recovery_authorization: unknown;
    }): ConsequenceBoundaryAttemptReference | null
      | Promise<ConsequenceBoundaryAttemptReference | null>;
  };
  /** Digest of the operator-pinned local admission policy/program. */
  local_authorization_program_digest: AebDigest;
  local_authorize(
    context: Readonly<NativeConsequenceBoundaryAuthorizationContext>,
  ): boolean | Promise<boolean>;
  invoke(
    context: Readonly<NativeConsequenceBoundaryEffectContext>,
  ): ConsequenceBoundaryEffectOutcome<TResult>
    | Promise<ConsequenceBoundaryEffectOutcome<TResult>>;
  provider_outcomes: {
    /** Digest of the pinned provider-evidence verification program/profile. */
    verification_program_digest: AebDigest;
    verify(
      context: Readonly<NativeConsequenceBoundaryProviderOutcomeVerificationContext<TResult>>,
    ): boolean | Promise<boolean>;
  };
  now?: () => string;
}

export interface NativeConsequenceBoundaryRunInput {
  operation_id: string;
  handoff: unknown;
  action: unknown;
}

export interface NativeConsequenceBoundaryReconcileInput<TResult> {
  operation_id: string;
  handoff: unknown;
  action: unknown;
  attempt: unknown;
  outcome: ConsequenceBoundaryEffectOutcome<TResult>;
  recovery_authorization: unknown;
}

export type ConsequenceBoundaryResult<TResult> =
  | {
    state: 'REFUSED';
    invoked: false;
    retry_allowed: false;
    reason: string;
  }
  | {
    state: 'EXECUTED';
    invoked: true;
    retry_allowed: false;
    result: TResult;
    evidence: ConsequenceBoundaryEvidence;
    attempt: ConsequenceBoundaryAttemptBinding;
  }
  | {
    state: 'FAILED';
    invoked: true;
    retry_allowed: false;
    reason: string;
    evidence: ConsequenceBoundaryEvidence;
    attempt: ConsequenceBoundaryAttemptBinding;
  }
  | {
    state: 'INDETERMINATE';
    invoked: boolean;
    retry_allowed: false;
    reason: string;
    attempt?: ConsequenceBoundaryAttemptBinding;
  };

function isObject(value: unknown): value is JsonObject {
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
function containsProxy(value: unknown): boolean {
  const seen = new Set<object>();
  const stack: unknown[] = [value];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || (typeof current !== 'object' && typeof current !== 'function')) continue;
    if (nodeTypes.isProxy(current)) return true;
    if (seen.has(current as object)) continue;
    seen.add(current as object);
    nodes += 1;
    if (nodes > PROXY_SCAN_NODE_BUDGET) return true;
    try {
      const descriptors = Object.getOwnPropertyDescriptors(current);
      for (const key of Reflect.ownKeys(descriptors)) {
        const descriptor = descriptors[key as string];
        if (Object.hasOwn(descriptor, 'value')) stack.push(descriptor.value);
      }
    } catch {
      return true;
    }
  }
  return false;
}

function dataRecord(value: unknown): JsonObject | null {
  if (!isObject(value) || nodeTypes.isProxy(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) return null;
    const record: JsonObject = {};
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
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
  } catch {
    return null;
  }
}

function exactKeys(value: JsonObject, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function identifier(value: unknown): value is string {
  return typeof value === 'string'
    && IDENTIFIER.test(value)
    && Buffer.byteLength(value, 'utf8') <= 256;
}

function digest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST.test(value);
}

function canonicalInstant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds)
    && new Date(milliseconds).toISOString() === value;
}

function cloneFrozen<T>(value: T): T {
  const clone = JSON.parse(canonicalizeAeb(value));
  if (clone === null || typeof clone !== 'object') return clone;
  const stack: object[] = [clone];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === 'object') stack.push(child);
    }
    Object.freeze(current);
  }
  return clone;
}

function secureAttemptStore(
  value: unknown,
): value is ConsequenceBoundaryAttemptStore {
  return isObject(value)
    && value.durable === true
    && value.ownershipFenced === true
    && value.compareAndSwap === true
    && value.atomicEvidenceBinding === true
    && typeof value.reserve === 'function'
    && typeof value.transition === 'function'
    && typeof value.reconcile === 'function';
}

function secureConsequenceEnvelope(
  value: unknown,
): value is ConsequenceEnvelopeBoundary {
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

function validEvidence(value: unknown): value is ConsequenceBoundaryEvidence {
  const record = dataRecord(value);
  return record !== null
    && exactKeys(record, ['evidence_id', 'observed_at', 'evidence_digest'])
    && identifier(record.evidence_id)
    && canonicalInstant(record.observed_at)
    && digest(record.evidence_digest);
}

function normalizeEffectOutcome<TResult>(
  value: unknown,
  snapshotResult = false,
): ConsequenceBoundaryEffectOutcome<TResult> | null {
  const record = dataRecord(value);
  if (!record || !identifier(record.state)) return null;
  if (record.state === 'INDETERMINATE') {
    return exactKeys(record, ['state', 'reason']) && identifier(record.reason)
      ? { state: 'INDETERMINATE', reason: record.reason }
      : null;
  }
  if (record.state === 'EXECUTED') {
    if (!exactKeys(record, ['state', 'evidence', 'result'])
        || !validEvidence(record.evidence)) return null;
    if (!snapshotResult) {
      return {
        state: 'EXECUTED',
        evidence: cloneFrozen(record.evidence),
        result: record.result as TResult,
      };
    }
    try {
      return {
        state: 'EXECUTED',
        evidence: cloneFrozen(record.evidence),
        result: cloneFrozen(record.result as TResult),
      };
    } catch {
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

function publicAttempt(
  attempt: ConsequenceBoundaryAttemptReference,
): ConsequenceBoundaryAttemptBinding {
  const { owner: _owner, ...binding } = attempt;
  return cloneFrozen(binding);
}

function validAttemptBinding(value: unknown): value is ConsequenceBoundaryAttemptBinding {
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

function opaqueOwner(value: unknown): value is ConsequenceBoundaryOwnerHandle {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 16
    && Buffer.byteLength(value, 'utf8') <= 1024
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validAttemptReference(
  value: unknown,
): value is ConsequenceBoundaryAttemptReference {
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
  ]) || !opaqueOwner(record.owner)) return false;
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
] as const;

function validNativeAttemptBinding(
  value: unknown,
): value is NativeConsequenceBoundaryAttemptBinding {
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

function validNativeAttemptReference(
  value: unknown,
): value is NativeConsequenceBoundaryAttemptReference {
  const record = dataRecord(value);
  if (!record || !exactKeys(record, [...NATIVE_ATTEMPT_BINDING_KEYS, 'owner'])
      || !opaqueOwner(record.owner)) return false;
  const { owner: _owner, ...binding } = record;
  return validNativeAttemptBinding(binding);
}

function publicNativeAttempt(
  attempt: NativeConsequenceBoundaryAttemptReference,
): NativeConsequenceBoundaryAttemptBinding {
  const { owner: _owner, ...binding } = attempt;
  return cloneFrozen(binding);
}

export function consequenceBoundaryRequestDigest(input: {
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  caid: string;
  action: unknown;
  evaluation_digest: AebDigest;
  provider_idempotency_key: string;
}): AebDigest {
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
export function consequenceBoundaryProviderIdempotencyKey(input: {
  provider: ConsequenceBoundaryProvider;
  caid: string;
  action_digest: AebDigest;
  authorization_instance: string;
}): string {
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

function secureAebConsumptionStore(
  value: unknown,
): value is AebDurableConsumptionStore {
  return isObject(value)
    && value.durable === true
    && value.ownershipFenced === true
    && value.permanentConsumption === true
    && value.atomicReplayFenced === true
    && typeof value.reserve === 'function'
    && typeof value.commit === 'function'
    && typeof value.release === 'function';
}

function secureNativeConsumptionStore(
  value: unknown,
): value is AebDurableConsumptionStore & {
  state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
} {
  return secureAebConsumptionStore(value)
    && isObject(value)
    && typeof value.state === 'function';
}

function secureNativeAttemptStore(
  value: unknown,
): value is NativeConsequenceBoundaryOptions<unknown>['attempts']['store'] {
  return secureAttemptStore(value)
    && isObject(value)
    && typeof value.state === 'function';
}

function nativeTrustSnapshotDigest(
  pins: AebNativeAuthorizationPins,
): AebDigest {
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
export function nativeConsequenceBoundaryReservationKey(input: {
  relying_party_id: string;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
}): string {
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

export function nativeConsequenceBoundaryProviderIdempotencyKey(input: {
  provider: ConsequenceBoundaryProvider;
  action_digest: AebNativeAuthorizationDigest;
  native_replay_unit: AebNativeAuthorizationDigest;
}): string {
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

export function nativeConsequenceBoundaryRequestDigest(input: {
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  action: unknown;
  action_digest: AebNativeAuthorizationDigest;
  handoff_digest: AebNativeAuthorizationDigest;
  native_replay_unit: AebNativeAuthorizationDigest;
  trust_snapshot_id: string;
  trust_snapshot_digest: AebDigest;
  authorization_program_digest: AebDigest;
  local_authorization: NativeConsequenceBoundaryLocalDecision;
  provider_outcome_verification_program_digest: AebDigest;
  provider_idempotency_key: string;
}): AebDigest {
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
    provider_outcome_verification_program_digest:
      input.provider_outcome_verification_program_digest,
    provider_idempotency_key: input.provider_idempotency_key,
  });
}

function providerCoordinates(value: unknown): ConsequenceBoundaryProvider | null {
  const record = dataRecord(value);
  if (!record
      || !exactKeys(record, ['tenant_id', 'provider_id', 'provider_account_id', 'environment'])
      || !identifier(record.tenant_id)
      || !identifier(record.provider_id)
      || !identifier(record.provider_account_id)
      || !identifier(record.environment)) return null;
  return {
    tenant_id: record.tenant_id,
    provider_id: record.provider_id,
    provider_account_id: record.provider_account_id,
    environment: record.environment,
  };
}

function relyingPartyText(value: unknown): value is string {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 1
    && Buffer.byteLength(value, 'utf8') <= 512
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function actionFenceKeyUnchecked(
  relyingPartyId: string,
  provider: ConsequenceBoundaryProvider,
  actionDigest: AebNativeAuthorizationDigest,
): string {
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
export function nativeConsequenceBoundaryActionFenceKey(input: {
  relying_party_id: string;
  provider: ConsequenceBoundaryProvider;
  action_digest: AebNativeAuthorizationDigest;
}): string {
  const record = dataRecord(input);
  const provider = record ? providerCoordinates(record.provider) : null;
  if (!record || !provider || !identifier(record.relying_party_id)
      || !digest(record.action_digest)) {
    throw new TypeError('native_action_fence_binding_invalid');
  }
  return actionFenceKeyUnchecked(record.relying_party_id, provider, record.action_digest);
}

/** Keys of the three reservations one native attempt writes, plus its fences. */
export interface NativeConsequenceBoundaryAttemptReservationKeys {
  /** Operation identity fence (nativeConsequenceBoundaryReservationKey). */
  operation_fence: string;
  /** Exact-action fence (nativeConsequenceBoundaryActionFenceKey). */
  action_fence: string;
  /** Attempt-bound reservation that holds `operation_fence`. */
  operation: string;
  /** Attempt-bound reservation that holds the native replay key. */
  authority: string;
  /** Attempt-bound reservation that holds `action_fence`. */
  holder: string;
}

/**
 * Consumption-store keys of one native attempt. Every row key includes the
 * attempt ID, and the authority and holder keys are derived from the
 * attempt's operation key, so a release, close, or recovery claim for one
 * attempt can never reach a row another attempt wrote, even when both carry
 * the same caller-chosen operation ID.
 */
export function nativeConsequenceBoundaryAttemptReservationKeys(input: {
  relying_party_id: string;
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  attempt_id: string;
}): NativeConsequenceBoundaryAttemptReservationKeys {
  const record = dataRecord(input);
  if (!record || !identifier(record.attempt_id)) {
    throw new TypeError('native_attempt_reservation_binding_invalid');
  }
  const operationFence = nativeConsequenceBoundaryReservationKey({
    relying_party_id: record.relying_party_id as string,
    operation_id: record.operation_id as string,
    action_digest: record.action_digest as AebNativeAuthorizationDigest,
  });
  const actionFence = nativeConsequenceBoundaryActionFenceKey({
    relying_party_id: record.relying_party_id as string,
    provider: record.provider as ConsequenceBoundaryProvider,
    action_digest: record.action_digest as AebNativeAuthorizationDigest,
  });
  const operation = `aeb-native-attempt-operation:${digestAeb({
    domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ATTEMPT-OPERATION`,
    operation_fence: operationFence,
    attempt_id: record.attempt_id,
  })}`;
  return {
    operation_fence: operationFence,
    action_fence: actionFence,
    operation,
    authority: `aeb-native-attempt-authority:${digestAeb({
      domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ATTEMPT-AUTHORITY`,
      operation_key: operation,
    })}`,
    holder: `aeb-native-action-holder:${digestAeb({
      domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE-HOLDER`,
      operation_key: operation,
    })}`,
  };
}

/**
 * Key of the reservation that holds the action fence for one native attempt.
 * It is derived from that attempt's operation key, which includes the attempt
 * ID, so reconciliation can only ever close the holder of its own attempt.
 */
export function nativeConsequenceBoundaryActionFenceHolderKey(input: {
  relying_party_id: string;
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  attempt_id: string;
}): string {
  return nativeConsequenceBoundaryAttemptReservationKeys(input).holder;
}

/**
 * Key of the reservation that holds the action fence for one attempt on the
 * composed (AEB evaluation) boundary: derived from the evaluation's
 * consumption reservation key and the attempt ID.
 */
export function consequenceBoundaryActionFenceHolderKey(input: {
  reservation_key: string;
  attempt_id: string;
}): string {
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

function nativeActionExecutedMarkerKey(actionFenceKey: string): string {
  return `aeb-native-action-executed:${digestAeb({
    domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-EXECUTED`,
    action_fence_key: actionFenceKey,
  })}`;
}

interface NativeConsumptionKeys extends NativeConsequenceBoundaryAttemptReservationKeys {
  /** Diagnostic marker written after an authenticated EXECUTED result. */
  executed_marker: string;
}

function deriveNativeConsumptionKeys(input: {
  relying_party_id: string;
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
  attempt_id: string;
}): NativeConsumptionKeys | null {
  try {
    const keys = nativeConsequenceBoundaryAttemptReservationKeys(input);
    return { ...keys, executed_marker: nativeActionExecutedMarkerKey(keys.action_fence) };
  } catch {
    return null;
  }
}

function refused(reason: string): ConsequenceBoundaryResult<never> {
  return Object.freeze({
    state: 'REFUSED',
    invoked: false,
    retry_allowed: false,
    reason,
  });
}

function indeterminate(
  reason: string,
  invoked: boolean,
  attempt?: ConsequenceBoundaryAttemptBinding,
): ConsequenceBoundaryResult<never> {
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
export function createConsequenceBoundary<TResult>(
  options: ConsequenceBoundaryOptions<TResult>,
) {
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

  const provider: ConsequenceBoundaryProvider = cloneFrozen(options.provider);
  const now = options.now ?? (() => new Date().toISOString());
  const createAttemptId = options.attempts.create_id
    ?? (() => `attempt:${crypto.randomUUID()}`);
  // Action-fence custody. A store that fails the secure-store check is
  // refused by authorizeAebExecutionDurable() before any fence write.
  const custody = secureAebConsumptionStore(options.aeb.store)
    ? consumptionCustody(options.aeb.store as ConsumptionStoreLike)
    : null;
  // Pre-entry recovery needs a durable attempt-state read. Attempt stores
  // written for 0.26.0 may lack one; they keep the provider-outcome-only
  // reconciliation path.
  const readComposedAttemptState = typeof options.attempts.store.state === 'function'
    ? options.attempts.store.state.bind(options.attempts.store)
    : null;

  /** A throwing or non-boolean attempt-store answer is an unconfirmed write. */
  async function releaseComposedAttempt(
    reference: ConsequenceBoundaryAttemptReference,
  ): Promise<boolean> {
    try {
      return await options.attempts.store.transition({
        ...reference,
        expected_state: 'RESERVED',
        next_state: 'RELEASED',
      }) === true;
    } catch {
      return false;
    }
  }

  async function composedAttemptState(
    reference: ConsequenceBoundaryAttemptReference,
  ): Promise<{ state: string; evidence?: unknown } | null> {
    if (!readComposedAttemptState) return null;
    try {
      const snapshot = dataRecord(await readComposedAttemptState(reference));
      if (!snapshot || typeof snapshot.state !== 'string'
          || !['RESERVED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'RELEASED']
            .includes(snapshot.state)) return null;
      return snapshot.evidence === undefined
        ? { state: snapshot.state }
        : { state: snapshot.state, evidence: snapshot.evidence };
    } catch {
      return null;
    }
  }

  async function run(
    input: ConsequenceBoundaryRunInput,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let evaluation: AebEvaluationRecord;
    let evaluationDigest: AebDigest;
    let decisionNow: string;
    try {
      action = cloneFrozen(input?.action);
      evaluation = cloneFrozen(input?.evaluation) as AebEvaluationRecord;
      evaluationDigest = digestAeb(evaluation);
      decisionNow = now();
      if (!canonicalInstant(decisionNow)) throw new Error('clock_invalid');
    } catch {
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
    } catch {
      localAuthorization = false;
    }
    if (!localAuthorization) return refused('local_authorization_denied');

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
    // Same-action fence, shared with the native boundary: relying party,
    // provider coordinates as configured, and the canonical action digest.
    // Derived before any further write so an unkeyable binding is a refusal.
    let actionFence: string;
    try {
      const relyingPartyId = options.aeb.config.relying_party_id;
      if (!relyingPartyText(relyingPartyId) || !custody) throw new Error('fence_unkeyable');
      actionFence = actionFenceKeyUnchecked(
        relyingPartyId,
        provider,
        digestAebNativeAuthorizationAction(action),
      );
    } catch {
      await options.aeb.store.release(reservationKey).catch(() => false);
      return refused('action_fence_binding_invalid');
    }
    const executedMarker = nativeActionExecutedMarkerKey(actionFence);
    let envelopeReservation: ConsequenceEnvelopeReservation | null = null;
    if (options.consequence_envelope) {
      let capacity;
      try {
        capacity = await options.consequence_envelope.reserve({
          operation_id: evaluation.operation_id,
          state_domain_id: options.consequence_envelope.envelope.state_domain_id,
          expected_epoch: options.consequence_envelope.envelope.epoch,
          action,
        });
      } catch {
        capacity = { status: 'REFUSED' as const, reason: 'consequence_envelope_unavailable' };
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

    let attemptId: string;
    let holderKey: string;
    try {
      attemptId = await createAttemptId({
        operation_id: evaluation.operation_id,
        request_digest: requestDigest,
      });
      if (!identifier(attemptId)) throw new Error('attempt_id_invalid');
      holderKey = consequenceBoundaryActionFenceHolderKey({
        reservation_key: reservationKey,
        attempt_id: attemptId,
      });
    } catch {
      if (envelopeReservation) {
        await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
      }
      await options.aeb.store.release(reservationKey).catch(() => false);
      return refused('attempt_allocation_failed');
    }

    const attemptBinding: ConsequenceBoundaryAttemptBinding = cloneFrozen({
      ...provider,
      attempt_id: attemptId,
      request_digest: requestDigest,
      provider_idempotency_key: providerIdempotencyKey,
    });
    let reserved;
    try {
      reserved = await options.attempts.store.reserve(attemptBinding);
    } catch {
      if (envelopeReservation) {
        await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
      }
      await options.aeb.store.release(reservationKey).catch(() => false);
      return refused('attempt_store_unavailable');
    }
    if (!reserved.reserved) {
      if (envelopeReservation) {
        await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
      }
      await options.aeb.store.release(reservationKey).catch(() => false);
      return refused(reserved.reason || 'attempt_conflict');
    }
    const attempt: ConsequenceBoundaryAttemptReference = {
      ...attemptBinding,
      owner: reserved.owner,
    };

    // The holder reservation is keyed by this attempt and fences the exact
    // action at this provider. It is written after the attempt record, so an
    // attempt that stops before entry can be found and its holder released by
    // reconcile(); and it is handed back before the evaluation reservation,
    // so a held holder proves this attempt still owns that reservation.
    let holderReserved = false;
    let holderMayExist = false;
    try {
      const fenced = await custody!.reserve(holderKey, [actionFence]);
      holderReserved = fenced === true || fenced === 'RESERVED';
      if (!holderReserved) {
        const reason = await custody!.actionFenceRefusal(executedMarker);
        await releaseComposedAttempt(attempt);
        if (envelopeReservation) {
          await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
        }
        await options.aeb.store.release(reservationKey).catch(() => false);
        return refused(reason);
      }
    } catch {
      holderMayExist = true;
    }
    if (holderMayExist) {
      const attemptReleased = await releaseComposedAttempt(attempt);
      if (envelopeReservation) {
        await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
      }
      if (!await custody!.releaseConfirmed(holderKey)) {
        return indeterminate('native_pre_entry_release_unconfirmed', false, publicAttempt(attempt));
      }
      await options.aeb.store.release(reservationKey).catch(() => false);
      return attemptReleased
        ? refused('consumption_store_unavailable')
        : indeterminate('attempt_release_unconfirmed', false, publicAttempt(attempt));
    }

    /** Pre-entry hand-back: the holder first, then the evaluation reservation. */
    async function releaseBeforeEntry(): Promise<boolean> {
      if (!await custody!.releaseConfirmed(holderKey)) return false;
      await options.aeb.store.release(reservationKey).catch(() => false);
      return true;
    }

    if (envelopeReservation) {
      const capacityEntry = await options.consequence_envelope!
        .beginProviderEntry(envelopeReservation)
        .catch(() => ({ status: 'REFUSED' as const, reason: 'consequence_envelope_unavailable' }));
      if (capacityEntry.status !== 'ENTERED') {
        const attemptReleased = await options.attempts.store.transition({
          ...attempt,
          expected_state: 'RESERVED',
          next_state: 'RELEASED',
        }).catch(() => false);
        await options.consequence_envelope!.releaseNotEntered(envelopeReservation).catch(() => null);
        if (!await releaseBeforeEntry()) {
          return indeterminate('native_pre_entry_release_unconfirmed', false, publicAttempt(attempt));
        }
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
          await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
          return indeterminate('attempt_start_conflict', false, publicAttempt(attempt));
        }
        return await releaseBeforeEntry()
          ? refused('attempt_start_conflict')
          : indeterminate('native_pre_entry_release_unconfirmed', false, publicAttempt(attempt));
      }
    } catch {
      if (envelopeReservation) {
        await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
        return indeterminate('attempt_store_unavailable', false, publicAttempt(attempt));
      }
      return await releaseBeforeEntry()
        ? refused('attempt_store_unavailable')
        : indeterminate('native_pre_entry_release_unconfirmed', false, publicAttempt(attempt));
    }

    let rawOutcome: unknown;
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
    } catch {
      await options.attempts.store.transition({
        ...attempt,
        expected_state: 'INVOKING',
        next_state: 'INDETERMINATE',
      }).catch(() => false);
      if (envelopeReservation) {
        await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
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
        await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
      }
      return indeterminate('attempt_freeze_failed', true, publicAttempt(attempt));
    }
    if (envelopeReservation) {
      const held = await options.consequence_envelope!
        .settle(envelopeReservation, 'INDETERMINATE')
        .catch(() => ({ status: 'REFUSED' as const, reason: 'consequence_envelope_unavailable' }));
      if (held.status !== 'INDETERMINATE') {
        return indeterminate('consequence_envelope_indeterminate_unconfirmed', true, publicAttempt(attempt));
      }
    }
    const outcome = normalizeEffectOutcome<TResult>(rawOutcome);
    if (!outcome) {
      return indeterminate('provider_outcome_invalid', true, publicAttempt(attempt));
    }
    if (outcome.state === 'INDETERMINATE') {
      return indeterminate(
        identifier(outcome.reason) ? outcome.reason : 'provider_outcome_indeterminate',
        true,
        publicAttempt(attempt),
      );
    }
    if (!validEvidence(outcome.evidence)) {
      return indeterminate('provider_evidence_invalid', true, publicAttempt(attempt));
    }

    // A one-time authorization is burned after any provider invocation with an
    // authoritative terminal outcome. A later attempt requires a new action
    // instance and a fresh authorization, even when this attempt FAILED.
    const consumed = await reconcileAebExecutionDurable(
      options.aeb.store,
      reservationKey,
      'COMMITTED',
    );
    if (consumed.state !== 'CONSUMED') {
      return indeterminate('authorization_consumption_unconfirmed', true, publicAttempt(attempt));
    }
    // EXECUTED keeps the action fence closed; an authenticated FAILED hands it
    // back so a fresh authorization may retry the same action. An unconfirmed
    // release leaves the attempt INDETERMINATE for reconcile() to finish.
    if (!await closeComposedActionFence(holderKey, executedMarker, outcome.state === 'EXECUTED')) {
      return indeterminate('native_action_fence_release_unconfirmed', true, publicAttempt(attempt));
    }

    const terminalState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
    const providerEvidence: ConsequenceBoundaryProviderEvidence = cloneFrozen({
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
      const capacityTerminal = await options.consequence_envelope!
        .settle(
          envelopeReservation,
          outcome.state === 'EXECUTED' ? 'COMMITTED' : 'PROVEN_NOT_COMMITTED',
        )
        .catch(() => ({ status: 'REFUSED' as const, reason: 'consequence_envelope_unavailable' }));
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
      } as const);
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

  async function closeComposedActionFence(
    holderKey: string,
    executedMarker: string,
    executed: boolean,
    recovery?: { authorization: unknown; scope: AebRecoveryClaimScope },
  ): Promise<boolean> {
    if (executed) {
      // A holder left RESERVED still fences the action, so an unconfirmed
      // commit cannot reopen it.
      if (!recovery) await custody!.closeConfirmed(holderKey, 'CONSUMED');
      else await custody!.closeForRecovery(holderKey, 'CONSUMED', recovery.authorization, recovery.scope);
      await custody!.markActionExecuted(executedMarker);
      return true;
    }
    return !recovery
      ? custody!.releaseConfirmed(holderKey)
      : custody!.releaseForRecovery(holderKey, recovery.authorization, recovery.scope);
  }

  async function reconcile(
    input: ConsequenceBoundaryReconcileInput<TResult>,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let evaluation: AebEvaluationRecord;
    let attemptBinding: ConsequenceBoundaryAttemptBinding;
    let evaluationDigest: AebDigest;
    try {
      action = cloneFrozen(input?.action);
      evaluation = cloneFrozen(input?.evaluation) as AebEvaluationRecord;
      evaluationDigest = digestAeb(evaluation);
      attemptBinding = cloneFrozen(input?.attempt) as ConsequenceBoundaryAttemptBinding;
      if (!validAttemptBinding(attemptBinding)) throw new Error('attempt_invalid');
    } catch {
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
    const outcome = normalizeEffectOutcome<TResult>(input.outcome);
    // Without a durable attempt-state read the boundary cannot prove a stop
    // before provider entry, so only a terminal provider outcome can proceed.
    if ((!outcome || outcome.state === 'INDETERMINATE') && !readComposedAttemptState) {
      return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
    }

    let recovered: ConsequenceBoundaryAttemptReference | null = null;
    try {
      recovered = await options.attempts.recover({
        attempt: attemptBinding,
        recovery_authorization: input.recovery_authorization,
      });
    } catch {
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
    let holderKey: string;
    let executedMarker: string;
    try {
      const relyingPartyId = options.aeb.config.relying_party_id;
      if (!relyingPartyText(relyingPartyId) || !custody) throw new Error('fence_unkeyable');
      holderKey = consequenceBoundaryActionFenceHolderKey({
        reservation_key: reservationKey,
        attempt_id: attemptBinding.attempt_id,
      });
      executedMarker = nativeActionExecutedMarkerKey(actionFenceKeyUnchecked(
        relyingPartyId,
        provider,
        digestAebNativeAuthorizationAction(action),
      ));
    } catch {
      return refused('action_fence_binding_invalid');
    }
    const scope = (reservation: AebRecoveryClaimScope['reservation']): AebRecoveryClaimScope => ({
      attemptId: attemptBinding.attempt_id,
      operationId: evaluation.operation_id,
      recoveryOperationKey: reservationKey,
      reservation,
    });

    // Pre-entry recovery: a durable record that never reached INVOKING (or was
    // RELEASED without evidence) proves this boundary never entered the
    // provider for the attempt. The holder is released; while it is still
    // held it proves this attempt still owns the evaluation reservation, which
    // is closed as RELEASED_NOT_ENTERED so it can never be reserved again.
    if (readComposedAttemptState) {
      let snapshot = await composedAttemptState(recoveredReference);
      if (snapshot === null) {
        return indeterminate('attempt_state_unavailable', true, attemptBinding);
      }
      const preEntry = snapshot.state === 'RESERVED'
        || (snapshot.state === 'RELEASED' && snapshot.evidence === undefined);
      if (preEntry) {
        if (!outcome) return indeterminate('provider_outcome_indeterminate', false, attemptBinding);
        if (outcome.state === 'EXECUTED') return refused('reconciliation_outcome_conflict');
        if (snapshot.state === 'RESERVED') {
          await releaseComposedAttempt(recoveredReference);
          snapshot = await composedAttemptState(recoveredReference);
          if (snapshot === null) {
            return indeterminate('attempt_state_unavailable', true, attemptBinding);
          }
        }
        if (snapshot.state === 'RELEASED' && snapshot.evidence === undefined) {
          const holderState = await custody.state(holderKey);
          let released = holderState === 'AVAILABLE';
          if (holderState === 'RESERVED') {
            const evaluationClosed = !custody.hasTerminalRelease
              || await custody.closeForRecovery(
                reservationKey,
                'RELEASED_NOT_ENTERED',
                input.recovery_authorization,
                scope('operation'),
              );
            released = evaluationClosed && await custody.releaseForRecovery(
              holderKey,
              input.recovery_authorization,
              scope('action-fence-holder'),
            );
          } else if (holderState === null && !custody.hasStateRead) {
            released = await custody.releaseForRecovery(
              holderKey,
              input.recovery_authorization,
              scope('action-fence-holder'),
            );
          }
          return released
            ? refused('attempt_never_entered_provider')
            : indeterminate('native_pre_entry_release_unconfirmed', false, attemptBinding);
        }
      }
      if (!outcome || outcome.state === 'INDETERMINATE') {
        return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
      }
    }
    if (!outcome || outcome.state === 'INDETERMINATE') {
      return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
    }

    const consumed = await reconcileAebExecutionDurable(
      options.aeb.store,
      reservationKey,
      'COMMITTED',
    );
    // After a restart an ownership-fenced store (the shipped PostgreSQL store)
    // refuses the commit until the authorized recovery claim takes the row.
    if (consumed.state !== 'CONSUMED'
        && !await custody.closeForRecovery(
          reservationKey,
          'CONSUMED',
          input.recovery_authorization,
          scope('operation'),
        )) {
      return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
    }
    if (!await closeComposedActionFence(holderKey, executedMarker, outcome.state === 'EXECUTED', {
      authorization: input.recovery_authorization,
      scope: scope('action-fence-holder'),
    })) {
      return indeterminate('native_action_fence_release_unconfirmed', true, attemptBinding);
    }
    const providerEvidence: ConsequenceBoundaryProviderEvidence = cloneFrozen({
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
      }).catch(() => ({ status: 'REFUSED' as const, reason: 'consequence_envelope_unavailable' }));
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
      } as const);
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

type ConsumptionStoreLike = AebDurableConsumptionStore & {
  state?(key: string): AebConsumptionState | Promise<AebConsumptionState>;
  recoveryClaimSupported?: true;
  claimReservation?(
    key: string,
    authorization: unknown,
    scope?: AebRecoveryClaimScope,
  ): Promise<boolean>;
};

/**
 * Consumption-store operations with every method pinned at construction.
 * A write is confirmed by a durable state read when the store has one, and
 * otherwise only by an explicit `true` acknowledgement. A lost acknowledgement
 * is resolved by the read, never by assuming the write happened.
 */
function consumptionCustody(store: ConsumptionStoreLike) {
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

  async function state(key: string): Promise<AebConsumptionState | null> {
    if (!readState) return null;
    try {
      const value = await readState(key);
      return value === 'AVAILABLE' || value === 'RESERVED'
        || value === 'CONSUMED' || value === 'RELEASED_NOT_ENTERED'
        ? value
        : null;
    } catch {
      return null;
    }
  }

  /** Hand one open reservation back so its key and fences are AVAILABLE. */
  async function releaseConfirmed(key: string): Promise<boolean> {
    if (readState) {
      const before = await state(key);
      if (before === 'AVAILABLE') return true;
      if (before !== 'RESERVED') return false;
      try { await release(key); } catch { /* confirm through state */ }
      return await state(key) === 'AVAILABLE';
    }
    try {
      return await release(key) === true;
    } catch {
      return false;
    }
  }

  async function closeConfirmed(
    key: string,
    target: 'CONSUMED' | 'RELEASED_NOT_ENTERED',
  ): Promise<boolean> {
    if (target === 'RELEASED_NOT_ENTERED' && !releaseTerminal) return false;
    if (readState) {
      const before = await state(key);
      if (before === target) return true;
      if (before !== 'RESERVED') return false;
      try {
        if (target === 'CONSUMED') await commit(key);
        else await releaseTerminal!(key);
      } catch {
        // A lost acknowledgement is resolved by the durable state read below.
      }
      return await state(key) === target;
    }
    try {
      return target === 'CONSUMED'
        ? await commit(key) === true
        : await releaseTerminal!(key) === true;
    } catch {
      return false;
    }
  }

  /**
   * Take ownership of a RESERVED row through the store's authorized recovery
   * path. Only reconciliation calls this, after it has authenticated custody
   * of the attempt, and only for keys derived from that attempt.
   */
  async function claimFor(
    key: string,
    authorization: unknown,
    scope: AebRecoveryClaimScope,
  ): Promise<boolean> {
    if (!claim) return false;
    if (readState && await state(key) !== 'RESERVED') return false;
    try {
      return await claim(key, authorization, cloneFrozen(scope)) === true;
    } catch {
      return false;
    }
  }

  async function closeForRecovery(
    key: string,
    target: 'CONSUMED' | 'RELEASED_NOT_ENTERED',
    authorization: unknown,
    scope: AebRecoveryClaimScope,
  ): Promise<boolean> {
    if (await closeConfirmed(key, target)) return true;
    if (!await claimFor(key, authorization, scope)) return false;
    return closeConfirmed(key, target);
  }

  async function releaseForRecovery(
    key: string,
    authorization: unknown,
    scope: AebRecoveryClaimScope,
  ): Promise<boolean> {
    if (await releaseConfirmed(key)) return true;
    if (!await claimFor(key, authorization, scope)) return false;
    return releaseConfirmed(key);
  }

  async function markActionExecuted(markerKey: string): Promise<void> {
    // Diagnostic only: it lets a later refusal say "already executed" rather
    // than "in flight". The fence itself is the committed holder reservation.
    try {
      const marker = await reserve(markerKey, []);
      if (marker === true || marker === 'RESERVED') await commit(markerKey);
    } catch {
      // The committed or still-reserved holder keeps the action closed.
    }
  }

  async function actionFenceRefusal(markerKey: string): Promise<string> {
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
export function createNativeConsequenceBoundary<TResult>(
  options: NativeConsequenceBoundaryOptions<TResult>,
) {
  let provider: ConsequenceBoundaryProvider;
  let pins: AebNativeAuthorizationPins;
  let configured = false;
  let pinRefusal: string | null = null;
  try {
    provider = cloneFrozen(options?.provider);
    pins = cloneFrozen(options?.native_authorization?.pins);
    // A pin set the verifier would refuse (aliased issuers without one shared
    // namespace, mixed namespace declarations, duplicates) is refused here,
    // before any attempt can run under it.
    const pinCheck = verifyAebNativeAuthorizationPins(pins);
    if (!pinCheck.valid) pinRefusal = pinCheck.reasons[0] ?? 'native_pins_invalid';
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
  } catch {
    configured = false;
  }
  if (!configured) {
    throw new TypeError(pinRefusal
      ? `native_consequence_boundary_configuration_invalid: ${pinRefusal}`
      : 'native_consequence_boundary_configuration_invalid');
  }
  provider = provider!;
  pins = pins!;

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
  const providerOutcomeVerificationProgramDigest =
    options.provider_outcomes.verification_program_digest;
  const authorizationProgramDigest = digestAeb({
    domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:AUTHORIZATION-PROGRAM`,
    executor_id: executorId,
    provider,
    trust_snapshot_id: trustSnapshotId,
    trust_snapshot_digest: trustSnapshotDigest,
    local_authorization_program_digest: localAuthorizationProgramDigest,
    provider_outcome_verification_program_digest:
      providerOutcomeVerificationProgramDigest,
  });

  function deriveAuthorizationProgramDigest(input: {
    trust_snapshot_id: string;
    trust_snapshot_digest: AebDigest;
    local_authorization_program_digest: AebDigest;
    provider_outcome_verification_program_digest: AebDigest;
  }): AebDigest {
    return digestAeb({
      domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:AUTHORIZATION-PROGRAM`,
      executor_id: executorId,
      provider,
      ...input,
    });
  }

  function deriveLocalDecision(input: {
    decided_at: string;
    action_digest: AebNativeAuthorizationDigest;
    handoff_digest: AebNativeAuthorizationDigest;
    native_replay_unit: AebNativeAuthorizationDigest;
    program_digest: AebDigest;
  }): NativeConsequenceBoundaryLocalDecision {
    const decision = {
      decision: 'PERMIT' as const,
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

  type NativeAttemptSnapshot = {
    state: 'RESERVED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
    evidence?: unknown;
  };

  async function attemptState(
    reference: NativeConsequenceBoundaryAttemptReference,
  ): Promise<NativeAttemptSnapshot | null> {
    try {
      const snapshot = dataRecord(await readAttemptState(reference));
      if (!snapshot
          || typeof snapshot.state !== 'string'
          || !['RESERVED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'RELEASED']
            .includes(snapshot.state)) return null;
      const state = snapshot.state as NativeAttemptSnapshot['state'];
      if (snapshot.evidence === undefined) return { state };
      return { state, evidence: cloneFrozen(snapshot.evidence) };
    } catch {
      return null;
    }
  }

  async function transitionAttempt(
    reference: NativeConsequenceBoundaryAttemptReference,
    expected: 'RESERVED' | 'INVOKING',
    next: 'INVOKING' | 'INDETERMINATE' | 'RELEASED',
  ): Promise<boolean> {
    const before = await attemptState(reference);
    if (before?.state === next) return true;
    if (before?.state !== expected) return false;
    try {
      await transitionAttemptState({
        ...reference,
        expected_state: expected,
        next_state: next,
      } as ConsequenceBoundaryAttemptReference & ConsequenceBoundaryAttemptTransition);
    } catch {
      // A lost acknowledgement is resolved by the durable state read below.
    }
    return (await attemptState(reference))?.state === next;
  }

  function terminalRecordMatches(
    snapshot: NativeAttemptSnapshot | null,
    next: 'COMMITTED' | 'RELEASED',
    evidence: NativeConsequenceBoundaryProviderEvidence,
  ): boolean {
    try {
      return snapshot?.state === next
        && snapshot.evidence !== undefined
        && canonicalizeAeb(snapshot.evidence) === canonicalizeAeb(evidence);
    } catch {
      return false;
    }
  }

  async function closeAttempt(
    reference: NativeConsequenceBoundaryAttemptReference,
    next: 'COMMITTED' | 'RELEASED',
    evidence: NativeConsequenceBoundaryProviderEvidence,
  ): Promise<boolean> {
    let current = await attemptState(reference);
    if (terminalRecordMatches(current, next, evidence)) return true;
    if (current?.state !== 'INDETERMINATE') return false;
    try {
      await reconcileAttempt({
        ...reference,
        expected_state: 'INDETERMINATE',
        next_state: next,
        evidence,
      });
    } catch {
      // A lost acknowledgement is resolved by the durable state read below.
    }
    current = await attemptState(reference);
    return terminalRecordMatches(current, next, evidence);
  }

  async function verifyProviderOutcome(
    attempt: NativeConsequenceBoundaryAttemptBinding,
    outcome: Exclude<ConsequenceBoundaryEffectOutcome<TResult>, { state: 'INDETERMINATE' }>,
  ): Promise<boolean> {
    try {
      return await verifyOutcome(cloneFrozen({
        provider,
        operation_id: attempt.operation_id,
        action_digest: attempt.action_digest,
        native_replay_unit: attempt.native_replay_unit,
        verification_program_digest:
          attempt.provider_outcome_verification_program_digest,
        attempt,
        outcome,
      })) === true;
    } catch {
      return false;
    }
  }

  function providerEvidence(
    attemptBinding: NativeConsequenceBoundaryAttemptBinding,
    outcome: Exclude<ConsequenceBoundaryEffectOutcome<TResult>, { state: 'INDETERMINATE' }>,
  ): NativeConsequenceBoundaryProviderEvidence {
    return cloneFrozen({
      ...attemptBinding,
      evidence_id: outcome.evidence.evidence_id,
      observed_at: outcome.evidence.observed_at,
      outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
      evidence_digest: outcome.evidence.evidence_digest,
    });
  }

  function claimScope(
    keys: NativeConsumptionKeys,
    attempt: NativeConsequenceBoundaryAttemptBinding,
    reservation: AebRecoveryClaimScope['reservation'],
  ): AebRecoveryClaimScope {
    return {
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
  async function closeActionFence(
    keys: NativeConsumptionKeys,
    executed: boolean,
    recovery?: { authorization: unknown; attempt: NativeConsequenceBoundaryAttemptBinding },
  ): Promise<boolean> {
    if (executed) {
      // A holder left RESERVED still fences the action, so an unconfirmed
      // commit here cannot reopen it.
      if (!recovery) await custody.closeConfirmed(keys.holder, 'CONSUMED');
      else {
        await custody.closeForRecovery(
          keys.holder,
          'CONSUMED',
          recovery.authorization,
          claimScope(keys, recovery.attempt, 'action-fence-holder'),
        );
      }
      await custody.markActionExecuted(keys.executed_marker);
      return true;
    }
    return !recovery
      ? custody.releaseConfirmed(keys.holder)
      : custody.releaseForRecovery(
        keys.holder,
        recovery.authorization,
        claimScope(keys, recovery.attempt, 'action-fence-holder'),
      );
  }

  function terminalResult(
    outcome: Exclude<ConsequenceBoundaryEffectOutcome<TResult>, { state: 'INDETERMINATE' }>,
    attemptBinding: NativeConsequenceBoundaryAttemptBinding,
  ): ConsequenceBoundaryResult<TResult> {
    if (outcome.state === 'EXECUTED') {
      return Object.freeze({
        state: 'EXECUTED', invoked: true, retry_allowed: false,
        result: outcome.result, evidence: outcome.evidence, attempt: attemptBinding,
      } as const);
    }
    return Object.freeze({
      state: 'FAILED', invoked: true, retry_allowed: false,
      reason: outcome.reason, evidence: outcome.evidence, attempt: attemptBinding,
    });
  }

  async function run(
    input: NativeConsequenceBoundaryRunInput,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let handoff: unknown;
    let operationId: string;
    let decisionNow: string;
    try {
      const record = dataRecord(input);
      if (!record || !exactKeys(record, ['operation_id', 'handoff', 'action'])
          || containsProxy(record)) {
        throw new Error('native_execution_input_invalid');
      }
      action = cloneFrozen(record.action);
      handoff = cloneFrozen(record.handoff);
      operationId = record.operation_id as string;
      decisionNow = now();
      if (!identifier(operationId) || !canonicalInstant(decisionNow)) {
        throw new Error('native_execution_input_invalid');
      }
    } catch {
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

    let status: AebNativeAuthorizationStatus;
    try {
      status = cloneFrozen(await resolveNativeStatus(
        preflight.handoff,
      ));
    } catch {
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
    if (verification.handoff.relying_party_id !== relyingPartyId) {
      return refused('native_consequence_binding_invalid');
    }

    let providerIdempotencyKey: string;
    try {
      providerIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
        provider,
        action_digest: verification.action_digest,
        native_replay_unit: verification.native_replay_unit,
      });
      // Every key but the attempt-bound rows is derivable now; a binding Gate
      // cannot key is a refusal with no callback and no store write.
      nativeConsequenceBoundaryReservationKey({
        relying_party_id: relyingPartyId,
        operation_id: operationId,
        action_digest: verification.action_digest,
      });
    } catch {
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
    } catch {
      localAuthorization = false;
    }
    if (!localAuthorization) return refused('local_authorization_denied');

    let localDecidedAt: string;
    try {
      localDecidedAt = now();
      if (!canonicalInstant(localDecidedAt)) throw new Error('clock_invalid');
    } catch {
      return refused('native_local_decision_time_invalid');
    }
    const localDecision = deriveLocalDecision({
      decided_at: localDecidedAt,
      action_digest: verification.action_digest,
      handoff_digest: verification.record_digest,
      native_replay_unit: verification.native_replay_unit,
      program_digest: localAuthorizationProgramDigest,
    });

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
      provider_outcome_verification_program_digest:
        providerOutcomeVerificationProgramDigest,
      provider_idempotency_key: providerIdempotencyKey,
    });

    let attemptId: string;
    try {
      attemptId = await createAttemptId({
        operation_id: operationId,
        request_digest: requestDigest,
      });
      if (!identifier(attemptId)) throw new Error('attempt_id_invalid');
    } catch {
      return refused('attempt_allocation_failed');
    }
    const derivedKeys = deriveNativeConsumptionKeys({
      relying_party_id: relyingPartyId,
      provider,
      operation_id: operationId,
      action_digest: verification.action_digest,
      attempt_id: attemptId,
    });
    if (!derivedKeys) return refused('native_consequence_binding_invalid');
    const keys: NativeConsumptionKeys = derivedKeys;
    const attemptBinding: NativeConsequenceBoundaryAttemptBinding = cloneFrozen({
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
      provider_outcome_verification_program_digest:
        providerOutcomeVerificationProgramDigest,
    });

    // 1. The durable attempt record comes before any reservation, so every
    //    reservation below belongs to an attempt that reconcile() can find
    //    and prove never reached provider entry.
    let owner: ConsequenceBoundaryOwnerHandle;
    try {
      const reserved = dataRecord(await reserveAttempt(attemptBinding));
      if (reserved?.reserved !== true || !opaqueOwner(reserved.owner)) {
        return refused(identifier(reserved?.reason) ? reserved.reason : 'attempt_conflict');
      }
      owner = reserved.owner;
    } catch {
      return refused('attempt_store_unavailable');
    }
    const attempt: NativeConsequenceBoundaryAttemptReference = {
      ...attemptBinding,
      owner,
    };

    // Attempt-bound rows this call wrote or may have written (a reserve that
    // threw can still have landed). No other attempt can own these keys.
    const held: string[] = [];

    // Reservations are handed back only after the attempt itself is durably
    // RELEASED, so an attempt that is still RESERVED or INVOKING keeps its
    // fences until reconcile() proves it never entered the provider.
    async function stopBeforeEntry(
      expected: 'RESERVED' | 'INVOKING',
      reason: string,
    ): Promise<ConsequenceBoundaryResult<TResult>> {
      const attemptReleased = await transitionAttempt(attempt, expected, 'RELEASED');
      if (held.length === 0) return refused(reason);
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
    const reservations: Array<[string, string[], () => Promise<string>]> = [
      [keys.operation, [keys.operation_fence], async () => 'consumption_conflict'],
      [keys.authority, [verification.replay_key], async () => 'native_replay_conflict'],
      [keys.holder, [keys.action_fence], () => custody.actionFenceRefusal(keys.executed_marker)],
    ];
    for (const [key, fences, conflictReason] of reservations) {
      let reservation: unknown;
      try {
        reservation = await custody.reserve(key, fences);
      } catch {
        held.push(key);
        return stopBeforeEntry('RESERVED', 'consumption_store_unavailable');
      }
      if (reservation !== true && reservation !== 'RESERVED') {
        return stopBeforeEntry('RESERVED', await conflictReason());
      }
      held.push(key);
    }

    let entryVerification: AebNativeAuthorizationHandoffVerification;
    try {
      const entryStatus = cloneFrozen(await resolveNativeStatus(
        verification.handoff,
      ));
      const entryNow = now();
      if (!canonicalInstant(entryNow)) throw new Error('clock_invalid');
      entryVerification = verifyAebNativeAuthorizationHandoff(verification.handoff, {
        mode: 'execution',
        pins,
        expected_action: action,
        status: entryStatus,
        now: entryNow,
      });
    } catch {
      entryVerification = {
        ...verification,
        valid: false,
        execution_authorizing: false,
        reasons: ['native_status_resolution_failed'],
      };
    }
    if (!entryVerification.valid || !entryVerification.execution_authorizing) {
      return stopBeforeEntry(
        'RESERVED',
        entryVerification.reasons[0] ?? 'native_handoff_not_verified_at_provider_entry',
      );
    }

    const started = await transitionAttempt(attempt, 'RESERVED', 'INVOKING');
    if (!started) {
      return indeterminate('attempt_start_unconfirmed', false, publicNativeAttempt(attempt));
    }

    // The custody transition itself can block. Resolve status once more after
    // it completes so no delayed store call can carry stale authority into the
    // provider callback.
    let providerEntryVerification: AebNativeAuthorizationHandoffVerification;
    try {
      const providerEntryStatus = cloneFrozen(
        await resolveNativeStatus(verification.handoff),
      );
      const providerEntryNow = now();
      if (!canonicalInstant(providerEntryNow)) throw new Error('clock_invalid');
      providerEntryVerification = verifyAebNativeAuthorizationHandoff(
        verification.handoff,
        {
          mode: 'execution',
          pins,
          expected_action: action,
          status: providerEntryStatus,
          now: providerEntryNow,
        },
      );
    } catch {
      providerEntryVerification = {
        ...verification,
        valid: false,
        execution_authorizing: false,
        reasons: ['native_status_resolution_failed'],
      };
    }
    if (!providerEntryVerification.valid
        || !providerEntryVerification.execution_authorizing) {
      return stopBeforeEntry(
        'INVOKING',
        providerEntryVerification.reasons[0]
          ?? 'native_handoff_not_verified_at_provider_entry',
      );
    }

    let rawOutcome: unknown;
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
        provider_outcome_verification_program_digest:
          providerOutcomeVerificationProgramDigest,
        provider_idempotency_key: providerIdempotencyKey,
        attempt: attemptBinding,
      }));
    } catch {
      await transitionAttempt(attempt, 'INVOKING', 'INDETERMINATE');
      return indeterminate('provider_outcome_indeterminate', true, publicNativeAttempt(attempt));
    }

    const frozen = await transitionAttempt(attempt, 'INVOKING', 'INDETERMINATE');
    if (!frozen) return indeterminate('attempt_freeze_failed', true, publicNativeAttempt(attempt));
    const outcome = normalizeEffectOutcome<TResult>(rawOutcome, true);
    if (!outcome) return indeterminate('provider_outcome_invalid', true, publicNativeAttempt(attempt));
    if (outcome.state === 'INDETERMINATE') {
      return indeterminate(outcome.reason, true, publicNativeAttempt(attempt));
    }
    if (!await verifyProviderOutcome(attemptBinding, outcome)) {
      return indeterminate(
        'provider_outcome_authentication_failed',
        true,
        publicNativeAttempt(attempt),
      );
    }

    // Any terminal provider result follows provider entry and therefore burns
    // the one-time native authorization and the operation identity, including
    // an authenticated NOT_COMMITTED.
    if (!await custody.closeConfirmed(keys.authority, 'CONSUMED')
        || !await custody.closeConfirmed(keys.operation, 'CONSUMED')) {
      return indeterminate(
        'authorization_consumption_unconfirmed',
        true,
        publicNativeAttempt(attempt),
      );
    }
    // The fence closes before the terminal record, so an unconfirmed release
    // leaves the attempt INDETERMINATE and any authenticated reconciliation
    // can finish it. The holder is keyed by this attempt, so a repeated close
    // can never reach a later attempt's fence.
    if (!await closeActionFence(keys, outcome.state === 'EXECUTED')) {
      return indeterminate(
        'native_action_fence_release_unconfirmed',
        true,
        publicNativeAttempt(attempt),
      );
    }
    const evidence = providerEvidence(attemptBinding, outcome);
    const terminal = await closeAttempt(
      attempt,
      outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED',
      evidence,
    );
    if (!terminal) {
      return indeterminate(
        'attempt_terminal_record_unconfirmed',
        true,
        publicNativeAttempt(attempt),
      );
    }
    return terminalResult(outcome, attemptBinding);
  }

  const RECONCILE_KEYS = [
    'operation_id', 'handoff', 'action', 'attempt', 'outcome', 'recovery_authorization',
  ];

  async function reconcile(
    input: NativeConsequenceBoundaryReconcileInput<TResult>,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let handoff: unknown;
    let attemptBinding: NativeConsequenceBoundaryAttemptBinding;
    let operationId: string;
    let decisionNow: string;
    let rawOutcome: unknown;
    let recoveryAuthorization: unknown;
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
      attemptBinding = cloneFrozen(record.attempt) as NativeConsequenceBoundaryAttemptBinding;
      operationId = record.operation_id as string;
      rawOutcome = record.outcome;
      recoveryAuthorization = record.recovery_authorization;
      decisionNow = now();
      if (!identifier(operationId) || !canonicalInstant(decisionNow)
          || !validNativeAttemptBinding(attemptBinding)) throw new Error('input_invalid');
    } catch {
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
    let recovered: ConsequenceBoundaryAttemptReference | null = null;
    try {
      recovered = await recoverAttempt({
        attempt: attemptBinding,
        recovery_authorization: recoveryAuthorization,
      });
    } catch {
      recovered = null;
    }
    if (!validNativeAttemptReference(recovered)) return refused('attempt_recovery_refused');
    let recoveredReference: NativeConsequenceBoundaryAttemptReference;
    try {
      recoveredReference = cloneFrozen(recovered);
      if (canonicalizeAeb(publicNativeAttempt(recoveredReference))
          !== canonicalizeAeb(attemptBinding)) {
        return refused('attempt_recovery_binding_mismatch');
      }
    } catch {
      return refused('attempt_recovery_refused');
    }

    let historicalPins: AebNativeAuthorizationPins | null = null;
    try {
      historicalPins = await resolveHistoricalPins({
        trust_snapshot_id: attemptBinding.trust_snapshot_id,
        trust_snapshot_digest: attemptBinding.trust_snapshot_digest,
      });
      if (historicalPins !== null) historicalPins = cloneFrozen(historicalPins);
    } catch {
      historicalPins = null;
    }
    if (!historicalPins) return refused('native_historical_trust_snapshot_unavailable');
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
      attempt_id: attemptBinding.attempt_id,
    });
    if (!derivedKeys) return refused('native_consequence_binding_invalid');
    const keys: NativeConsumptionKeys = derivedKeys;
    let expectedProviderIdempotencyKey: string;
    try {
      expectedProviderIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
        provider,
        action_digest: verification.action_digest,
        native_replay_unit: verification.native_replay_unit,
      });
    } catch {
      return refused('native_consequence_binding_invalid');
    }
    const expectedAuthorizationProgramDigest = deriveAuthorizationProgramDigest({
      trust_snapshot_id: attemptBinding.trust_snapshot_id,
      trust_snapshot_digest: attemptBinding.trust_snapshot_digest,
      local_authorization_program_digest:
        attemptBinding.local_authorization_program_digest,
      provider_outcome_verification_program_digest:
        attemptBinding.provider_outcome_verification_program_digest,
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
      provider_outcome_verification_program_digest:
        attemptBinding.provider_outcome_verification_program_digest,
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
    const outcome = normalizeEffectOutcome<TResult>(rawOutcome, true);

    let recoveredState = await attemptState(recoveredReference);
    if (recoveredState === null) {
      return indeterminate('attempt_state_unavailable', true, attemptBinding);
    }

    // Pre-entry recovery. Gate calls the provider only after moving the
    // attempt to INVOKING, and records RELEASED without evidence only for a
    // stop before the provider callback. So a durable record that is RESERVED,
    // or RELEASED without evidence, proves Gate never entered the provider for
    // this attempt. The caller's provider lookup, where one exists, must agree:
    // an authenticated FAILED ("not found") or an explicit INDETERMINATE when
    // no lookup is available. An EXECUTED claim contradicts the record and
    // releases nothing.
    const preEntryRecord = recoveredState.state === 'RESERVED'
      || (recoveredState.state === 'RELEASED' && recoveredState.evidence === undefined);
    if (preEntryRecord) {
      if (!outcome) return indeterminate('provider_outcome_indeterminate', false, attemptBinding);
      if (outcome.state === 'EXECUTED') return refused('reconciliation_outcome_conflict');
      if (outcome.state === 'FAILED' && !await verifyProviderOutcome(attemptBinding, outcome)) {
        return indeterminate('provider_outcome_authentication_failed', false, attemptBinding);
      }
      if (recoveredState.state === 'RESERVED'
          && !await transitionAttempt(recoveredReference, 'RESERVED', 'RELEASED')) {
        // The original call may have won the race to INVOKING; only a
        // provider outcome can close an attempt that reached it.
        recoveredState = await attemptState(recoveredReference);
        if (recoveredState === null) {
          return indeterminate('attempt_state_unavailable', true, attemptBinding);
        }
      } else {
        recoveredState = { state: 'RELEASED' };
      }
      if (recoveredState.state === 'RELEASED' && recoveredState.evidence === undefined) {
        let released = true;
        for (const [key, reservation] of [
          [keys.holder, 'action-fence-holder'],
          [keys.authority, 'native-authority'],
          [keys.operation, 'operation'],
        ] as const) {
          released = await custody.releaseForRecovery(
            key,
            recoveryAuthorization,
            claimScope(keys, attemptBinding, reservation),
          ) && released;
        }
        return released
          ? refused('attempt_never_entered_provider')
          : indeterminate('native_pre_entry_release_unconfirmed', false, attemptBinding);
      }
    }

    if (!outcome || outcome.state === 'INDETERMINATE') {
      return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
    }
    const evidence = providerEvidence(attemptBinding, outcome);
    const terminalState = outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED';
    if ((recoveredState.state === 'COMMITTED' || recoveredState.state === 'RELEASED')
        && !terminalRecordMatches(recoveredState, terminalState, evidence)) {
      // A terminal record is never rewritten, and a conflicting outcome must
      // not touch the reservations that record already closed.
      return refused('reconciliation_outcome_conflict');
    }
    if (recoveredState.state === 'RESERVED') {
      return indeterminate('attempt_state_unavailable', true, attemptBinding);
    }
    if (recoveredState.state === 'INVOKING'
        && !await transitionAttempt(recoveredReference, 'INVOKING', 'INDETERMINATE')) {
      return indeterminate('attempt_freeze_unconfirmed', true, attemptBinding);
    }

    if (!await verifyProviderOutcome(attemptBinding, outcome)) {
      return indeterminate('provider_outcome_authentication_failed', true, attemptBinding);
    }

    // Any terminal provider result follows provider entry and therefore burns
    // the one-time native authorization and the operation identity, including
    // an authenticated NOT_COMMITTED. After a restart the reservations may be
    // owned by a dead process; the store's authorized recovery claim takes
    // them over, one credential scoped to this attempt for all three.
    const custodyClosed = await custody.closeForRecovery(
      keys.authority,
      'CONSUMED',
      recoveryAuthorization,
      claimScope(keys, attemptBinding, 'native-authority'),
    ) && await custody.closeForRecovery(
      keys.operation,
      'CONSUMED',
      recoveryAuthorization,
      claimScope(keys, attemptBinding, 'operation'),
    );
    if (!custodyClosed) {
      return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
    }
    if (!await closeActionFence(keys, outcome.state === 'EXECUTED', {
      authorization: recoveryAuthorization,
      attempt: attemptBinding,
    })) {
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
  consequenceBoundaryActionFenceHolderKey,
  nativeConsequenceBoundaryReservationKey,
  nativeConsequenceBoundaryActionFenceKey,
  nativeConsequenceBoundaryAttemptReservationKeys,
  nativeConsequenceBoundaryActionFenceHolderKey,
  nativeConsequenceBoundaryProviderIdempotencyKey,
  nativeConsequenceBoundaryRequestDigest,
  createNativeConsequenceBoundary,
});
