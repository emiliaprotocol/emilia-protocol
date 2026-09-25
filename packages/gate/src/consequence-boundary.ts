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
    /** `pins.relying_party_id` must also satisfy the Gate identifier grammar. */
    pins: AebNativeAuthorizationPins;
    /** Stable operator identifier for the exact accepted pins below. */
    trust_snapshot_id: string;
    /**
     * Durable consumption store. It holds the operation reservation with the
     * native replay key, and a second reservation per operation that holds
     * the exact-action in-flight fence. `state()` must be a durable read.
     * A store whose commit and release are fenced to the reserving process
     * (the shipped PostgreSQL store) must also declare
     * `recoveryClaimSupported: true` so reconciliation after a restart can
     * claim both reservations with the caller's `recovery_authorization`.
     */
    store: AebDurableConsumptionStore & {
      state(key: string): AebConsumptionState | Promise<AebConsumptionState>;
      recoveryClaimSupported?: true;
      claimReservation?(key: string, authorization: unknown): Promise<boolean>;
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

/**
 * Durable identity of one exact action at one effecting target: the relying
 * party, the provider coordinates the boundary invokes, and the canonical
 * action digest. While an attempt for this identity is RESERVED, INVOKING, or
 * INDETERMINATE, a new attempt is refused as `native_action_in_flight` even
 * when it carries a fresh native authorization and a fresh operation ID.
 * Intentional repeats must differ in the canonical action itself, for example
 * through a caller-chosen instance field that the action digest covers.
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
export function nativeConsequenceBoundaryActionFenceHolderKey(input: {
  relying_party_id: string;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
}): string {
  const operationKey = nativeConsequenceBoundaryReservationKey(input);
  return `aeb-native-action-holder:${digestAeb({
    domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-FENCE-HOLDER`,
    operation_key: operationKey,
  })}`;
}

function nativeActionExecutedMarkerKey(actionFenceKey: string): string {
  return `aeb-native-action-executed:${digestAeb({
    domain: `${NATIVE_CONSEQUENCE_BOUNDARY_VERSION}:ACTION-EXECUTED`,
    action_fence_key: actionFenceKey,
  })}`;
}

interface NativeConsumptionKeys {
  /** Operation reservation; carries the native replay key. */
  operation: string;
  /** Per-operation holder reservation; carries the action fence. */
  holder: string;
  /** Replay-style fence shared by every attempt for the same exact action. */
  action_fence: string;
  /** Diagnostic marker written after an authenticated EXECUTED result. */
  executed_marker: string;
}

function deriveNativeConsumptionKeys(input: {
  relying_party_id: string;
  provider: ConsequenceBoundaryProvider;
  operation_id: string;
  action_digest: AebNativeAuthorizationDigest;
}): NativeConsumptionKeys | null {
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
  } catch {
    configured = false;
  }
  if (!configured) {
    throw new TypeError('native_consequence_boundary_configuration_invalid');
  }
  provider = provider!;
  pins = pins!;

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

  /** Delete an open reservation and every fence it holds; AVAILABLE after. */
  async function releaseReservation(key: string): Promise<boolean> {
    const before = await consumptionState(key);
    if (before === 'AVAILABLE') return true;
    if (before !== 'RESERVED') return false;
    try { await releaseConsumption(key); } catch { /* confirm through state */ }
    return await consumptionState(key) === 'AVAILABLE';
  }

  /**
   * Take ownership of a RESERVED row through the store's authorized recovery
   * path. Only reconciliation calls this, after it has authenticated the
   * attempt, its historical trust snapshot, and the provider outcome.
   */
  async function claimForRecovery(key: string, recoveryAuthorization: unknown): Promise<boolean> {
    if (!claimConsumption || await consumptionState(key) !== 'RESERVED') return false;
    try {
      return await claimConsumption(key, recoveryAuthorization) === true;
    } catch {
      return false;
    }
  }

  async function closeConsumptionForRecovery(
    key: string,
    target: 'CONSUMED',
    recoveryAuthorization: unknown,
  ): Promise<boolean> {
    if (await closeConsumption(key, target)) return true;
    if (!await claimForRecovery(key, recoveryAuthorization)) return false;
    return closeConsumption(key, target);
  }

  async function releaseReservationForRecovery(
    key: string,
    recoveryAuthorization: unknown,
  ): Promise<boolean> {
    if (await releaseReservation(key)) return true;
    if (!await claimForRecovery(key, recoveryAuthorization)) return false;
    return releaseReservation(key);
  }

  /** Pre-entry release: the fence holder first, then the operation. */
  async function releaseNotEntered(keys: NativeConsumptionKeys): Promise<boolean> {
    const fenceReleased = await releaseReservation(keys.holder);
    const authorizationReleased = await releaseReservation(keys.operation);
    return fenceReleased && authorizationReleased;
  }

  async function actionFenceRefusal(keys: NativeConsumptionKeys): Promise<string> {
    return await consumptionState(keys.executed_marker) === 'CONSUMED'
      ? 'native_action_already_executed'
      : 'native_action_in_flight';
  }

  async function markActionExecuted(keys: NativeConsumptionKeys): Promise<void> {
    // Diagnostic only: it lets a later refusal say "already executed" rather
    // than "in flight". The fence itself is the committed holder reservation.
    try {
      const marker = await reserveConsumption(keys.executed_marker, []);
      if (marker === true || marker === 'RESERVED') await commitConsumption(keys.executed_marker);
    } catch {
      // The committed fence keeps the action closed without the marker.
    }
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

  /**
   * Close the action fence once the provider outcome is authenticated.
   * EXECUTED keeps it closed for this exact action; an authenticated FAILED
   * releases it so a fresh native authorization may retry the same action.
   */
  async function closeActionFence(
    keys: NativeConsumptionKeys,
    executed: boolean,
    recoveryAuthorization?: unknown,
  ): Promise<boolean> {
    if (executed) {
      // A holder left RESERVED still fences the action, so an unconfirmed
      // commit here cannot reopen it.
      if (recoveryAuthorization === undefined) await closeConsumption(keys.holder, 'CONSUMED');
      else await closeConsumptionForRecovery(keys.holder, 'CONSUMED', recoveryAuthorization);
      await markActionExecuted(keys);
      return true;
    }
    return recoveryAuthorization === undefined
      ? releaseReservation(keys.holder)
      : releaseReservationForRecovery(keys.holder, recoveryAuthorization);
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
    const keys: NativeConsumptionKeys = derivedKeys;
    let providerIdempotencyKey: string;
    try {
      providerIdempotencyKey = nativeConsequenceBoundaryProviderIdempotencyKey({
        provider,
        action_digest: verification.action_digest,
        native_replay_unit: verification.native_replay_unit,
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

    // 1. The operation reservation atomically claims the operation ID and the
    //    native replay key derived from (namespace, issuer, authorization ID).
    try {
      const reservation = await reserveConsumption(
        keys.operation,
        [verification.replay_key],
      );
      if (reservation !== true && reservation !== 'RESERVED') {
        return refused(reservation === 'NATIVE_REPLAY_CONFLICT'
          ? 'native_replay_conflict'
          : 'consumption_conflict');
      }
    } catch {
      const released = await releaseReservation(keys.operation);
      return released
        ? refused('consumption_store_unavailable')
        : indeterminate('consumption_reservation_state_unconfirmed', false);
    }

    // 2. The holder reservation claims the exact-action fence. Another
    //    attempt for the same action that is RESERVED, INVOKING, or
    //    INDETERMINATE (or EXECUTED) already holds it.
    let fenceReservation: unknown;
    try {
      fenceReservation = await reserveConsumption(keys.holder, [keys.action_fence]);
    } catch {
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
      const released = await releaseNotEntered(keys);
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
    let owner: ConsequenceBoundaryOwnerHandle;
    try {
      const reserved = dataRecord(await reserveAttempt(attemptBinding));
      if (reserved?.reserved !== true || !opaqueOwner(reserved.owner)) {
        const released = await releaseNotEntered(keys);
        return released
          ? refused(identifier(reserved?.reason) ? reserved.reason : 'attempt_conflict')
          : indeterminate('native_pre_entry_release_unconfirmed', false);
      }
      owner = reserved.owner;
    } catch {
      const released = await releaseNotEntered(keys);
      return released
        ? refused('attempt_store_unavailable')
        : indeterminate('native_pre_entry_release_unconfirmed', false);
    }
    const attempt: NativeConsequenceBoundaryAttemptReference = {
      ...attemptBinding,
      owner,
    };

    // Reservations are released only after the attempt itself is durably
    // RELEASED. An attempt that is still RESERVED or INVOKING keeps both the
    // native authorization and the action fence, so no later attempt can
    // reuse its operation key while it could still be reconciled.
    async function refuseBeforeEntry(
      expected: 'RESERVED' | 'INVOKING',
      reason: string,
    ): Promise<ConsequenceBoundaryResult<TResult>> {
      const attemptReleased = await transitionAttempt(attempt, expected, 'RELEASED');
      const reservationsReleased = attemptReleased && await releaseNotEntered(keys);
      return attemptReleased && reservationsReleased
        ? refused(reason)
        : indeterminate('native_pre_entry_release_unconfirmed', false, publicNativeAttempt(attempt));
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
      return refuseBeforeEntry(
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
      return refuseBeforeEntry(
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
    // the one-time native authorization, including authenticated NOT_COMMITTED.
    if (!await closeConsumption(keys.operation, 'CONSUMED')) {
      return indeterminate(
        'authorization_consumption_unconfirmed',
        true,
        publicNativeAttempt(attempt),
      );
    }
    // The fence closes before the terminal record, so an unconfirmed release
    // leaves the attempt INDETERMINATE and any authenticated reconciliation
    // can finish it. The holder is scoped to this operation, so a repeated
    // close can never reach a later attempt's fence.
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
    const custodyClosed = await closeConsumptionForRecovery(
      keys.operation,
      'CONSUMED',
      recoveryAuthorization,
    );
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
