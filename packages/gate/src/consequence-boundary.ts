// SPDX-License-Identifier: Apache-2.0
/**
 * Neutral consequence boundary over CAID, AEC, and AEB.
 *
 * Native evidence stays native. The direct path verifies a relying-party-
 * pinned gateway handoff; it does not re-verify the native permit or artifact.
 * The boundary durably fences every native replay unit, records dispatch
 * custody, and invokes one provider adapter. It does not acquire approvals,
 * mint authority, or require an EMILIA receipt.
 */

import crypto from 'node:crypto';
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
  verifyAebNativeAuthorizationHandoff,
  type AebNativeAuthorizationDigest,
  type AebNativeAuthorizationHandoff,
  type AebNativeAuthorizationHandoffVerification,
  type AebNativeAuthorizationPins,
  type AebNativeAuthorizationStatus,
} from '@emilia-protocol/verify/aeb';
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
    store: AebDurableConsumptionStore;
  };
  attempts: {
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
    pins: AebNativeAuthorizationPins;
    /** Stable operator identifier for the exact accepted pins below. */
    trust_snapshot_id: string;
    store: AebDurableConsumptionStore & {
      state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
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

function dataRecord(value: unknown): JsonObject | null {
  if (!isObject(value)) return null;
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
      record[key] = descriptor.value;
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
    try {
      attemptId = await createAttemptId({
        operation_id: evaluation.operation_id,
        request_digest: requestDigest,
      });
      if (!identifier(attemptId)) throw new Error('attempt_id_invalid');
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
          await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
          return indeterminate('attempt_start_conflict', false, publicAttempt(attempt));
        }
        await options.aeb.store.release(reservationKey).catch(() => false);
        return refused('attempt_start_conflict');
      }
    } catch {
      if (envelopeReservation) {
        await options.consequence_envelope!.settle(envelopeReservation, 'INDETERMINATE').catch(() => null);
        return indeterminate('attempt_store_unavailable', false, publicAttempt(attempt));
      }
      await options.aeb.store.release(reservationKey).catch(() => false);
      return refused('attempt_store_unavailable');
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
    if (!outcome || outcome.state === 'INDETERMINATE') {
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
    const consumed = await reconcileAebExecutionDurable(
      options.aeb.store,
      reservationKey,
      'COMMITTED',
    );
    if (consumed.state !== 'CONSUMED') {
      return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
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

/**
 * Build the direct native path. The native system has already made the policy
 * decision; Gate verifies the pinned gateway handoff, not the native permit or
 * artifact. It applies its own operational authorization and atomically fences
 * the operation and native replay unit.
 */
export function createNativeConsequenceBoundary<TResult>(
  options: NativeConsequenceBoundaryOptions<TResult>,
) {
  let provider: ConsequenceBoundaryProvider;
  let pins: AebNativeAuthorizationPins;
  try {
    provider = cloneFrozen(options?.provider);
    pins = cloneFrozen(options?.native_authorization?.pins);
  } catch {
    throw new TypeError('native_consequence_boundary_configuration_invalid');
  }
  if (!isObject(options)
      || !identifier(options.executor_id)
      || !isObject(provider)
      || !identifier(provider.tenant_id)
      || !identifier(provider.provider_id)
      || !identifier(provider.provider_account_id)
      || !identifier(provider.environment)
      || !isObject(options.native_authorization)
      || !identifier(options.native_authorization.trust_snapshot_id)
      || !secureNativeConsumptionStore(options.native_authorization.store)
      || typeof options.native_authorization.resolve_status !== 'function'
      || typeof options.native_authorization.resolve_historical_pins !== 'function'
      || pins.executor_id !== options.executor_id
      || canonicalizeAeb(pins.provider) !== canonicalizeAeb(provider)
      || !isObject(options.attempts)
      || !secureNativeAttemptStore(options.attempts.store)
      || (options.attempts.create_id !== undefined
        && typeof options.attempts.create_id !== 'function')
      || typeof options.attempts.recover !== 'function'
      || !digest(options.local_authorization_program_digest)
      || typeof options.local_authorize !== 'function'
      || typeof options.invoke !== 'function'
      || !isObject(options.provider_outcomes)
      || !digest(options.provider_outcomes.verification_program_digest)
      || typeof options.provider_outcomes.verify !== 'function'
      || (options.now !== undefined && typeof options.now !== 'function')) {
    throw new TypeError('native_consequence_boundary_configuration_invalid');
  }

  const store = options.native_authorization.store;
  const attemptStore = options.attempts.store;
  const executorId = options.executor_id;
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

  async function consumptionState(key: string): Promise<AebConsumptionState | null> {
    try {
      const state = await readConsumptionState(key);
      return state === 'AVAILABLE' || state === 'RESERVED'
        || state === 'CONSUMED' || state === 'RELEASED_NOT_ENTERED'
        ? state
        : null;
    } catch {
      return null;
    }
  }

  async function closeConsumption(
    key: string,
    target: 'CONSUMED' | 'RELEASED_NOT_ENTERED',
  ): Promise<boolean> {
    const before = await consumptionState(key);
    if (before === target) return true;
    if (before !== 'RESERVED') return false;
    try {
      if (target === 'CONSUMED') await commitConsumption(key);
      else if (releaseTerminalConsumption) {
        await releaseTerminalConsumption(key);
      } else {
        return false;
      }
    } catch {
      // A lost acknowledgement is resolved by the durable state read below.
    }
    return await consumptionState(key) === target;
  }

  async function releaseUnenteredConsumption(key: string): Promise<boolean> {
    const before = await consumptionState(key);
    if (before === 'AVAILABLE') return true;
    if (before !== 'RESERVED') return false;
    try { await releaseConsumption(key); } catch { /* confirm through state */ }
    return await consumptionState(key) === 'AVAILABLE';
  }

  async function attemptState(reference: NativeConsequenceBoundaryAttemptReference) {
    try {
      const snapshot = await readAttemptState(reference);
      if (!isObject(snapshot)
          || !identifier(snapshot.state)
          || !['RESERVED', 'INVOKING', 'INDETERMINATE', 'COMMITTED', 'RELEASED']
            .includes(snapshot.state)) return null;
      return snapshot;
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

  async function closeAttempt(
    reference: NativeConsequenceBoundaryAttemptReference,
    next: 'COMMITTED' | 'RELEASED',
    evidence: NativeConsequenceBoundaryProviderEvidence,
  ): Promise<boolean> {
    const matches = (snapshot: Awaited<ReturnType<typeof attemptState>>) =>
      snapshot?.state === next
      && snapshot.evidence !== undefined
      && canonicalizeAeb(snapshot.evidence) === canonicalizeAeb(evidence);
    let current = await attemptState(reference);
    if (matches(current)) return true;
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
    return matches(current);
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

  async function run(
    input: NativeConsequenceBoundaryRunInput,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let handoff: unknown;
    let operationId: string;
    let decisionNow: string;
    try {
      const record = dataRecord(input);
      if (!record || !exactKeys(record, ['operation_id', 'handoff', 'action'])) {
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

    const operationReservationKey = nativeConsequenceBoundaryReservationKey({
      relying_party_id: verification.handoff.relying_party_id,
      operation_id: operationId,
      action_digest: verification.action_digest,
    });
    try {
      const reservation = await reserveConsumption(
        operationReservationKey,
        [verification.replay_key],
      );
      if (reservation !== true && reservation !== 'RESERVED') {
        return refused(reservation === 'NATIVE_REPLAY_CONFLICT'
          ? 'native_replay_conflict'
          : 'consumption_conflict');
      }
    } catch {
      const released = await releaseUnenteredConsumption(operationReservationKey);
      return released
        ? refused('consumption_store_unavailable')
        : indeterminate('consumption_reservation_state_unconfirmed', false);
    }

    const providerIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
      provider,
      action_digest: verification.action_digest,
      native_replay_unit: verification.native_replay_unit,
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
      const released = await releaseUnenteredConsumption(operationReservationKey);
      return released
        ? refused('attempt_allocation_failed')
        : indeterminate('native_pre_entry_release_unconfirmed', false);
    }
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
    let reserved;
    try {
      reserved = await reserveAttempt(attemptBinding);
    } catch {
      const released = await releaseUnenteredConsumption(operationReservationKey);
      return released
        ? refused('attempt_store_unavailable')
        : indeterminate('native_pre_entry_release_unconfirmed', false);
    }
    if (!reserved.reserved) {
      const released = await releaseUnenteredConsumption(operationReservationKey);
      return released
        ? refused(reserved.reason || 'attempt_conflict')
        : indeterminate('native_pre_entry_release_unconfirmed', false);
    }
    const attempt: NativeConsequenceBoundaryAttemptReference = {
      ...attemptBinding,
      owner: reserved.owner,
    };

    let entryNow: string;
    let entryStatus: AebNativeAuthorizationStatus;
    let entryVerification: AebNativeAuthorizationHandoffVerification;
    try {
      entryStatus = cloneFrozen(await resolveNativeStatus(
        verification.handoff,
      ));
      entryNow = now();
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
      const attemptReleased = await transitionAttempt(attempt, 'RESERVED', 'RELEASED');
      const authorizationReleased = await releaseUnenteredConsumption(operationReservationKey);
      return attemptReleased && authorizationReleased
        ? refused(entryVerification.reasons[0] ?? 'native_handoff_not_verified_at_provider_entry')
        : indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
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
      const attemptReleased = await transitionAttempt(attempt, 'INVOKING', 'RELEASED');
      const authorizationReleased = await releaseUnenteredConsumption(operationReservationKey);
      return attemptReleased && authorizationReleased
        ? refused(
          providerEntryVerification.reasons[0]
            ?? 'native_handoff_not_verified_at_provider_entry',
        )
        : indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
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

    if (!await closeConsumption(operationReservationKey, 'CONSUMED')) {
      return indeterminate(
        'authorization_consumption_unconfirmed',
        true,
        publicNativeAttempt(attempt),
      );
    }
    const evidence: NativeConsequenceBoundaryProviderEvidence = cloneFrozen({
      ...attemptBinding,
      operation_id: operationId,
      action_digest: verification.action_digest,
      native_replay_unit: verification.native_replay_unit,
      evidence_id: outcome.evidence.evidence_id,
      observed_at: outcome.evidence.observed_at,
      outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
      evidence_digest: outcome.evidence.evidence_digest,
    });
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

  async function reconcile(
    input: NativeConsequenceBoundaryReconcileInput<TResult>,
  ): Promise<ConsequenceBoundaryResult<TResult>> {
    let action: unknown;
    let handoff: unknown;
    let attemptBinding: NativeConsequenceBoundaryAttemptBinding;
    let operationId: string;
    let decisionNow: string;
    try {
      action = cloneFrozen(input?.action);
      handoff = cloneFrozen(input?.handoff);
      attemptBinding = cloneFrozen(input?.attempt) as NativeConsequenceBoundaryAttemptBinding;
      operationId = input?.operation_id;
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
        recovery_authorization: input.recovery_authorization,
      });
    } catch {
      recovered = null;
    }
    if (!validNativeAttemptReference(recovered)) return refused('attempt_recovery_refused');
    const recoveredReference = cloneFrozen(recovered);
    if (canonicalizeAeb(publicNativeAttempt(recoveredReference))
        !== canonicalizeAeb(attemptBinding)) {
      return refused('attempt_recovery_binding_mismatch');
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
    const expectedProviderIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
      provider,
      action_digest: verification.action_digest,
      native_replay_unit: verification.native_replay_unit,
    });
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
    const outcome = normalizeEffectOutcome<TResult>(input.outcome, true);
    if (!outcome || outcome.state === 'INDETERMINATE') {
      return indeterminate('provider_outcome_indeterminate', true, attemptBinding);
    }

    const recoveredState = await attemptState(recoveredReference);
    if (recoveredState?.state === 'INVOKING'
        && !await transitionAttempt(recoveredReference, 'INVOKING', 'INDETERMINATE')) {
      return indeterminate('attempt_freeze_unconfirmed', true, attemptBinding);
    }
    if (recoveredState?.state === 'RESERVED') {
      return refused('attempt_never_entered_provider');
    }
    if (recoveredState === null) {
      return indeterminate('attempt_state_unavailable', true, attemptBinding);
    }

    if (!await verifyProviderOutcome(attemptBinding, outcome)) {
      return indeterminate('provider_outcome_authentication_failed', true, attemptBinding);
    }

    const operationReservationKey = nativeConsequenceBoundaryReservationKey({
      relying_party_id: verification.handoff.relying_party_id,
      operation_id: operationId,
      action_digest: verification.action_digest,
    });
    // Any terminal provider result follows provider entry and therefore burns
    // the one-time native authorization, including authenticated NOT_COMMITTED.
    const custodyClosed = await closeConsumption(operationReservationKey, 'CONSUMED');
    if (!custodyClosed) {
      return indeterminate('authorization_consumption_unconfirmed', true, attemptBinding);
    }
    const evidence: NativeConsequenceBoundaryProviderEvidence = cloneFrozen({
      ...attemptBinding,
      operation_id: operationId,
      action_digest: verification.action_digest,
      native_replay_unit: verification.native_replay_unit,
      evidence_id: outcome.evidence.evidence_id,
      observed_at: outcome.evidence.observed_at,
      outcome: outcome.state === 'EXECUTED' ? 'COMMITTED' : 'NOT_COMMITTED',
      evidence_digest: outcome.evidence.evidence_digest,
    });
    const terminal = await closeAttempt(
      recoveredReference,
      outcome.state === 'EXECUTED' ? 'COMMITTED' : 'RELEASED',
      evidence,
    );
    if (!terminal) {
      return indeterminate('attempt_terminal_record_unconfirmed', true, attemptBinding);
    }
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
  nativeConsequenceBoundaryProviderIdempotencyKey,
  nativeConsequenceBoundaryRequestDigest,
  createNativeConsequenceBoundary,
});
