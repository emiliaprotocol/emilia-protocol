// SPDX-License-Identifier: Apache-2.0
/**
 * Gate Qualification v2 admission custody.
 *
 * The immutable snapshot is the complete input to one consequential operation.
 * Mutable lifecycle state lives in a separately CAS-owned record and every
 * accepted transition is chained into an append-only journal.  The in-memory
 * implementation is a linearizable reference for conformance and crash-model
 * tests; it is deliberately not a durability claim.
 */

import crypto from 'node:crypto';
import { canonicalizeFiniteJson } from './strict-json.js';
import {
  verifyBoundedExecutionProgram,
  type ExecutionProgramAction,
  type ExecutionProgramCharge,
  type ExecutionProgramNode,
  type VerifiedBoundedExecutionProgram,
} from './bounded-execution-program.js';
import {
  RISK_ID,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const ADMISSION_SNAPSHOT_VERSION = 'EP-GATE-ADMISSION-SNAPSHOT-v2';
export const ADMISSION_RECORD_VERSION = 'EP-GATE-ADMISSION-RECORD-v2';
export const ADMISSION_JOURNAL_VERSION = 'EP-GATE-ADMISSION-JOURNAL-v2';
export const ADMISSION_CURRENTNESS_VERSION = 'EP-GATE-ADMISSION-CURRENTNESS-v2';
export const EXECUTION_PROGRAM_RUNTIME_VERSION = 'EP-BOUNDED-EXECUTION-PROGRAM-RUNTIME-v1';
export const EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION = 'EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1';
export const EXECUTION_PROGRAM_STATUS_VERSION = 'EP-BOUNDED-EXECUTION-PROGRAM-STATUS-v1';
export const EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION =
  'EP-BOUNDED-EXECUTION-PROGRAM-REPORT-SNAPSHOT-v1';

export const ADMISSION_LIMITS = Object.freeze({
  inputs: 128,
  resources: 64,
  testResults: 64,
  agentEvidence: 32,
  identifierBytes: 512,
  currentnessMaxAgeMs: 5_000,
});

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = RISK_ID;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const OWNER_TOKEN = /^admission-owner:v2:[A-Za-z0-9_-]{32,128}$/;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type AdmissionDigest = `sha256:${string}`;

export type AdmissionInputRole =
  | 'candidate_manifest'
  | 'runtime_measurement'
  | 'test_result'
  | 'agent_evaluation_evidence'
  | 'qualification_statement'
  | 'qualification_status'
  | 'aeb'
  | 'aec'
  | 'local_policy'
  | 'authorization';

const REQUIRED_SINGLETON_ROLES = Object.freeze([
  'candidate_manifest',
  'runtime_measurement',
  'qualification_statement',
  'qualification_status',
  'aeb',
  'aec',
  'local_policy',
  'authorization',
] as const satisfies readonly AdmissionInputRole[]);
const REPEATABLE_ROLES = new Set<AdmissionInputRole>([
  'test_result',
  'agent_evaluation_evidence',
]);
const ROLE_ORDER = new Map<AdmissionInputRole, number>([
  'candidate_manifest', 'runtime_measurement', 'test_result',
  'agent_evaluation_evidence', 'qualification_statement',
  'qualification_status', 'aeb', 'aec', 'local_policy', 'authorization',
].map((role, index) => [role as AdmissionInputRole, index]));

export interface AdmissionInput {
  role: AdmissionInputRole;
  artifact_type: string;
  subject: string;
  payload_digest: AdmissionDigest;
  profile_digest: AdmissionDigest;
  verifier_id: string;
  trust_configuration_digest: AdmissionDigest;
  valid_until: string;
}

export type AdmissionResourceKind =
  | 'replay'
  | 'capability'
  | 'budget'
  | 'qualification_use'
  | 'provider_operation'
  | 'external_lease'
  | 'monotonic_counter'
  | 'execution_program';

export interface AdmissionResourceReservationInput {
  kind: AdmissionResourceKind;
  resource_id: string;
  reservation_id: string;
  digest: AdmissionDigest;
  expires_at: string;
  /** Present only for monotonic_counter. */
  expected_value?: number;
  /** Present only for monotonic_counter and strictly greater than expected_value. */
  next_value?: number;
}

export interface CandidateCustodyBinding {
  request_construction: 'GATE' | 'EXECUTOR_ADAPTER' | 'EXTERNAL';
  mutation_credential_custody: 'GATE' | 'EXECUTOR_ADAPTER' | 'EXTERNAL';
  enforcement_placement: 'SYSTEM_OF_RECORD' | 'ACTUATOR' | 'MIDDLEWARE';
  evidence_digest: AdmissionDigest;
}

export interface QualificationStatusBinding {
  authority_id: string;
  sequence: number;
  head_payload_digest: AdmissionDigest;
  observed_at: string;
  expires_at: string;
}

export interface ProviderBinding {
  provider_id: string;
  account_id: string;
  environment: string;
}

export interface AdmissionRelation {
  tenant_id: string;
  admission_id: string;
  operation_id: string;
  snapshot_digest: AdmissionDigest;
}

export interface AdmissionSnapshotInput {
  tenant_id: string;
  admission_id: string;
  operation_id: string;
  candidate_manifest_digest: AdmissionDigest;
  runtime_measurement_digest: AdmissionDigest;
  candidate_custody: CandidateCustodyBinding;
  assignment_digest: AdmissionDigest;
  qualification_policy_digest: AdmissionDigest;
  test_result_payload_digests: AdmissionDigest[];
  agent_evaluation_evidence_payload_digests: AdmissionDigest[];
  qualification_statement_payload_digest: AdmissionDigest;
  qualification_status: QualificationStatusBinding;
  caid: string;
  action_digest: AdmissionDigest;
  effect_request_digest: AdmissionDigest;
  provider: ProviderBinding;
  executor_adapter_digest: AdmissionDigest;
  idempotency_key: string;
  authorization_policy_digest: AdmissionDigest;
  trust_epoch: number;
  trust_configuration_digest: AdmissionDigest;
  configuration_epoch: number;
  configuration_digest: AdmissionDigest;
  inputs: AdmissionInput[];
  resource_reservations: AdmissionResourceReservationInput[];
  admitted_at: string;
  expires_at: string;
  supersedes_admission_id?: string | null;
  remedy_for?: AdmissionRelation | null;
}

export interface AdmissionSnapshotBody extends Omit<AdmissionSnapshotInput,
  'supersedes_admission_id' | 'remedy_for'> {
  '@version': typeof ADMISSION_SNAPSHOT_VERSION;
  supersedes_admission_id: string | null;
  remedy_for: Readonly<AdmissionRelation> | null;
}

export interface AdmissionSnapshot {
  body: Readonly<AdmissionSnapshotBody>;
  snapshot_digest: AdmissionDigest;
}

export type AdmissionState =
  | 'RESERVED'
  | 'RELEASED'
  | 'EXPIRED'
  | 'SUPERSEDED'
  | 'INVOKING'
  | 'INDETERMINATE'
  | 'COMMITTED'
  | 'PROVEN_NOT_COMMITTED';
export type AdmissionExecutionRight = 'RESERVED' | 'RELEASED' | 'CONSUMED';
export type AdmissionProviderAttempt =
  | 'NOT_ENTERED'
  | 'INVOKING'
  | 'INDETERMINATE'
  | 'COMMITTED'
  | 'PROVEN_NOT_COMMITTED';
export type AdmissionProviderOutcome = 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE';
export type AdmissionEffectRelation = 'OBSERVED_AS_REQUESTED' | 'DIVERGED' | 'INDETERMINATE';
export type AdmissionResourceState = 'RESERVED' | 'RELEASED' | 'CONSUMED';

export interface AdmissionEvidenceOutcome<T extends string> {
  value: T;
  evidence_digest: AdmissionDigest | null;
  observed_at: string;
}

export interface AdmissionResourceReservation extends AdmissionResourceReservationInput {
  state: AdmissionResourceState;
}

export interface AdmissionRecord {
  '@version': typeof ADMISSION_RECORD_VERSION;
  tenant_id: string;
  admission_id: string;
  operation_id: string;
  snapshot_digest: AdmissionDigest;
  revision: number;
  state: AdmissionState;
  execution_right: AdmissionExecutionRight;
  provider_attempt: AdmissionProviderAttempt;
  owner_digest: AdmissionDigest;
  invocation_token_digest: AdmissionDigest | null;
  provider_outcome: Readonly<AdmissionEvidenceOutcome<AdmissionProviderOutcome>> | null;
  effect_relation: Readonly<AdmissionEvidenceOutcome<AdmissionEffectRelation>> | null;
  resources: readonly Readonly<AdmissionResourceReservation>[];
  superseded_by_admission_id: string | null;
  refusal_reason: string | null;
  invocation_started_at: string | null;
  created_at: string;
  updated_at: string;
  predecessor_record_digest: AdmissionDigest | null;
  record_digest: AdmissionDigest;
}

export type AdmissionJournalEvent =
  | 'RESERVED'
  | 'RELEASED'
  | 'EXPIRED'
  | 'ABANDONED_BEFORE_INVOCATION'
  | 'SUPERSEDED'
  | 'INVOKING'
  | 'RECOVERED_INDETERMINATE'
  | 'PROVIDER_OUTCOME'
  | 'EFFECT_RELATION';

export interface AdmissionJournalEntry {
  '@version': typeof ADMISSION_JOURNAL_VERSION;
  tenant_id: string;
  admission_id: string;
  operation_id: string;
  sequence: number;
  event: AdmissionJournalEvent;
  snapshot_digest: AdmissionDigest;
  record_digest: AdmissionDigest;
  predecessor_digest: AdmissionDigest | null;
  recorded_at: string;
  entry_digest: AdmissionDigest;
}

export interface AdmissionCurrentnessObservation {
  '@version': typeof ADMISSION_CURRENTNESS_VERSION;
  observed_at: string;
  qualification_status_authority_id: string;
  qualification_status_sequence: number;
  qualification_status_head_digest: AdmissionDigest;
  qualification_status_expires_at: string;
  trust_epoch: number;
  trust_configuration_digest: AdmissionDigest;
  configuration_epoch: number;
  configuration_digest: AdmissionDigest;
  runtime_measurement_digest: AdmissionDigest;
  candidate_match: 'EXACT_MATCH' | 'MISMATCH' | 'STALE' | 'UNPINNABLE';
  external_leases: Array<{
    resource_id: string;
    digest: AdmissionDigest;
    expires_at: string;
  }>;
}

export interface AdmissionCurrentnessOracle {
  read(snapshot: Readonly<AdmissionSnapshot>): Promise<AdmissionCurrentnessObservation>;
}

export interface AdmissionMonotonicCounterHead {
  tenant_id: string;
  resource_id: string;
  current_value: number;
}

export type AdmissionRefusalReason =
  | 'admission_exists'
  | 'admission_not_found'
  | 'operation_exists'
  | 'operation_conflict'
  | 'revision_conflict'
  | 'owner_conflict'
  | 'resource_conflict'
  | 'admission_expired'
  | 'currentness_refused'
  | 'execution_right_consumed'
  | 'state_conflict'
  | 'relation_not_found'
  | 'relation_conflict'
  | 'outcome_conflict'
  | 'evidence_required'
  | 'invocation_token_conflict'
  | 'program_required'
  | 'program_not_found'
  | 'program_not_active'
  | 'program_expired'
  | 'program_suspended'
  | 'program_revoked'
  | 'program_status_indeterminate'
  | 'program_superseded'
  | 'program_budget_exhausted'
  | 'program_concurrency_exhausted';
export type AdmissionRefusal = { ok: false; reason: AdmissionRefusalReason };
export type AdmissionTransitionResult = { ok: true; record: Readonly<AdmissionRecord> } | AdmissionRefusal;
export type AdmissionReserveResult = {
  ok: true;
  snapshot: Readonly<AdmissionSnapshot>;
  record: Readonly<AdmissionRecord>;
  owner_token: string;
} | AdmissionRefusal;
export type AdmissionBeginResult = {
  ok: true;
  snapshot: Readonly<AdmissionSnapshot>;
  record: Readonly<AdmissionRecord>;
  invocation_token: string;
} | AdmissionRefusal;
export type AdmissionSupersedeResult = {
  ok: true;
  predecessor_record: Readonly<AdmissionRecord>;
  successor_snapshot: Readonly<AdmissionSnapshot>;
  successor_record: Readonly<AdmissionRecord>;
  successor_owner_token: string;
} | AdmissionRefusal;
export type AdmissionRecoveryResult = {
  ok: true;
  record: Readonly<AdmissionRecord>;
  reconciliation_token: string;
} | AdmissionRefusal;

export interface AdmissionReference {
  tenant_id: string;
  admission_id: string;
}
export interface AdmissionOperationReference {
  tenant_id: string;
  operation_id: string;
}
export interface AdmissionCas extends AdmissionReference {
  expected_revision: number;
  owner_token: string;
}
export interface AdmissionRecoveryInput extends AdmissionReference {
  owner_token: string;
}
export interface AdmissionExpiredRecoveryInput extends AdmissionReference {
  expected_revision: number;
}
export interface AdmissionProviderOutcomeInput extends AdmissionCas {
  invocation_token: string;
  value: AdmissionProviderOutcome;
  evidence_digest: AdmissionDigest | null;
  observed_at: string;
}
export interface AdmissionEffectRelationInput extends AdmissionCas {
  invocation_token: string;
  value: AdmissionEffectRelation;
  evidence_digest: AdmissionDigest | null;
  observed_at: string;
}
export interface AdmissionSupersedeInput extends AdmissionCas {
  successor: AdmissionSnapshotInput;
}

export interface AdmissionInvariantCheck { ok: boolean; violations: readonly string[] }

export type ExecutionProgramRuntimeStatus =
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'REVOKED'
  | 'SUPERSEDED';
export type ExecutionProgramAuthorizerKeyStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export type ExecutionProgramCurrentStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export type ExecutionProgramOccurrenceState =
  | 'RESERVED'
  | 'RELEASED'
  | 'INVOKING'
  | 'INDETERMINATE'
  | 'COMMITTED'
  | 'PROVEN_NOT_COMMITTED';

export interface ExecutionProgramBudgetState {
  budget_id: string;
  unit: string;
  limit: number;
  reserved: number;
  consumed: number;
}

export interface ExecutionProgramTrustedAuthorizerKey {
  issuer_id: string;
  public_key: string;
  role: 'program_authorizer';
  status: ExecutionProgramAuthorizerKeyStatus;
}

export interface ExecutionProgramVerificationPolicy {
  trusted_keys: Readonly<Record<string, Readonly<ExecutionProgramTrustedAuthorizerKey>>>;
}

export interface ExecutionProgramRegistrationContext {
  expected_program_id: string;
  expected_tenant_id: string;
  expected_authorization_digest: string;
  expected_audience: string;
}

export interface ExecutionProgramStatusReference {
  tenant_id: string;
  program_id: string;
  program_digest: string;
  version: number;
}

export interface ExecutionProgramStatusObservation extends ExecutionProgramStatusReference {
  '@version': typeof EXECUTION_PROGRAM_STATUS_VERSION;
  status: ExecutionProgramCurrentStatus;
  sequence: number;
  observed_at: string;
  expires_at: string;
}

export interface ExecutionProgramStatusOracle {
  read(
    reference: Readonly<ExecutionProgramStatusReference>,
  ): Promise<ExecutionProgramStatusObservation | null>;
}

export interface ExecutionProgramActionMatchExpected {
  tenant_id: string;
  profile_id: string;
  profile_digest: AdmissionDigest;
  subject_id: string;
  operation_id: string;
  caid: string;
  action_digest: AdmissionDigest;
  verifier_id: string;
  evidence_payload_digest: AdmissionDigest;
  evidence_trust_configuration_digest: AdmissionDigest;
  trust_epoch: number;
  trust_configuration_digest: AdmissionDigest;
}

export interface ExecutionProgramActionMatchVerification
  extends ExecutionProgramActionMatchExpected {
  valid: true;
  result: 'MATCH';
}

export interface ExecutionProgramActionMatchVerifier {
  verify(input: Readonly<{
    evidence: unknown;
    expected: Readonly<ExecutionProgramActionMatchExpected>;
  }>): Promise<ExecutionProgramActionMatchVerification | null>;
}

export interface ExecutionProgramRuntimeState {
  '@version': typeof EXECUTION_PROGRAM_RUNTIME_VERSION;
  tenant_id: string;
  program_id: string;
  program_digest: string;
  version: number;
  status: ExecutionProgramRuntimeStatus;
  status_sequence: number;
  status_observed_at: string;
  status_expires_at: string;
  authorizer_id: string;
  registered_at: string;
  superseded_by_program_digest: string | null;
  total_occurrences: number;
  budgets: readonly Readonly<ExecutionProgramBudgetState>[];
  program: Readonly<VerifiedBoundedExecutionProgram>;
}

export interface ExecutionProgramOccurrence {
  tenant_id: string;
  program_digest: string;
  node_id: string;
  occurrence_id: string;
  admission_id: string;
  snapshot_digest: AdmissionDigest;
  state: ExecutionProgramOccurrenceState;
  charges: readonly Readonly<ExecutionProgramCharge>[];
  created_at: string;
  updated_at: string;
}

export interface ExecutionProgramReportSnapshotBody {
  '@version': typeof EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION;
  tenant_id: string;
  program_digest: string;
  runtime_state: Readonly<ExecutionProgramRuntimeState>;
  occurrences: readonly Readonly<ExecutionProgramOccurrence>[];
}

export interface ExecutionProgramReportSnapshot extends ExecutionProgramReportSnapshotBody {
  snapshot_marker: AdmissionDigest;
}

/** @deprecated Trace-fixture shape only; not accepted by ExecutionProgramReserveInput. */
export interface LegacyExecutionProgramActionMatch {
  result: 'MATCH';
  profile_id: string;
  profile_digest: string;
  evidence_payload_digest: AdmissionDigest;
}

export interface ExecutionProgramReserveInput {
  program_digest: string;
  node_id: string;
  occurrence_id: string;
  admission: AdmissionSnapshotInput | AdmissionSnapshot;
  action_match_evidence?: unknown;
}

export type ExecutionProgramRefusalReason =
  | AdmissionRefusalReason
  | 'program_exists'
  | 'program_not_found'
  | 'program_inactive'
  | 'program_superseded'
  | 'program_binding_mismatch'
  | 'program_node_unreachable'
  | 'program_occurrence_exhausted'
  | 'program_total_occurrence_exhausted'
  | 'program_occurrence_conflict'
  | 'program_budget_exhausted'
  | 'program_concurrency_exhausted'
  | 'program_expiration_mismatch'
  | 'program_suspended'
  | 'program_revoked'
  | 'program_status_indeterminate'
  | 'program_reserved_work_exists'
  | 'program_supersession_invalid'
  | 'program_signature_invalid'
  | 'program_issuer_untrusted'
  | 'program_schema_invalid'
  | 'context_binding_required'
  | 'authorizer_mismatch'
  | 'program_id_mismatch'
  | 'tenant_mismatch'
  | 'authorization_mismatch'
  | 'audience_mismatch'
  | 'verification_time_invalid'
  | 'program_not_active'
  | 'program_expired';

export type ExecutionProgramRegistrationResult = {
  ok: true;
  program: Readonly<ExecutionProgramRuntimeState>;
} | { ok: false; reason: ExecutionProgramRefusalReason };

export type ExecutionProgramReserveResult = AdmissionReserveResult | {
  ok: false;
  reason: ExecutionProgramRefusalReason;
};

export interface ExecutionProgramReference {
  tenant_id: string;
  program_digest: string;
}

export interface ExecutionProgramAdmissionBindingInput {
  tenant_id: string;
  program_digest: string;
  node_id: string;
  occurrence_id: string;
  expires_at: string;
}

export interface AdmissionStore {
  readonly durable: boolean;
  readonly atomic: true;
  readonly compareAndSwap: true;
  readonly appendOnlyJournal: true;
  readonly exclusiveActuation: true;
  readonly transactionalCurrentness: true;
  readonly testOnly?: true;
  reserve(input: AdmissionSnapshotInput | AdmissionSnapshot): Promise<AdmissionReserveResult>;
  release(input: AdmissionCas, reason?: string): Promise<AdmissionTransitionResult>;
  expire(input: AdmissionCas): Promise<AdmissionTransitionResult>;
  /**
   * Deadline-gated recovery for a reservation whose per-operation owner token
   * was lost before provider entry. This transition has no owner-token input:
   * access to the recovery RPC is the authority, and state, immutable expiry,
   * tenant/admission identity, and revision are all checked atomically.
   */
  reapExpiredReservation(input: AdmissionExpiredRecoveryInput): Promise<AdmissionTransitionResult>;
  supersede(input: AdmissionSupersedeInput): Promise<AdmissionSupersedeResult>;
  beginInvocation(input: AdmissionCas): Promise<AdmissionBeginResult>;
  recoverIndeterminate(input: AdmissionRecoveryInput): Promise<AdmissionRecoveryResult>;
  recordProviderOutcome(input: AdmissionProviderOutcomeInput): Promise<AdmissionTransitionResult>;
  recordEffectRelation(input: AdmissionEffectRelationInput): Promise<AdmissionTransitionResult>;
  read(input: AdmissionReference): Promise<Readonly<AdmissionRecord> | null>;
  readByOperation(input: AdmissionOperationReference): Promise<Readonly<AdmissionRecord> | null>;
  readSnapshot(digest: AdmissionDigest): Promise<Readonly<AdmissionSnapshot> | null>;
  journal(input: AdmissionReference): Promise<readonly Readonly<AdmissionJournalEntry>[]>;
  checkInvariants(): Promise<AdmissionInvariantCheck>;
}

export interface ExecutionProgramAdmissionStore extends AdmissionStore {
  registerExecutionProgram(
    artifact: unknown,
    context: ExecutionProgramRegistrationContext,
  ): Promise<ExecutionProgramRegistrationResult>;
  reserveExecutionProgramAdmission(
    input: ExecutionProgramReserveInput,
  ): Promise<ExecutionProgramReserveResult>;
  beginExecutionProgramInvocation(input: AdmissionCas): Promise<AdmissionBeginResult>;
  releaseExecutionProgramAdmission(
    input: AdmissionCas,
    reason?: string,
  ): Promise<AdmissionTransitionResult>;
  expireExecutionProgramAdmission(input: AdmissionCas): Promise<AdmissionTransitionResult>;
  supersedeExecutionProgram(
    artifact: unknown,
    context: ExecutionProgramRegistrationContext,
  ): Promise<ExecutionProgramRegistrationResult>;
  readExecutionProgram(
    input: ExecutionProgramReference,
  ): Promise<Readonly<ExecutionProgramRuntimeState> | null>;
  readExecutionProgramReportSnapshot(
    input: ExecutionProgramReference,
  ): Promise<Readonly<ExecutionProgramReportSnapshot> | null>;
  readExecutionProgramOccurrence(input: ExecutionProgramReference & {
    occurrence_id: string;
  }): Promise<Readonly<ExecutionProgramOccurrence> | null>;
}

export interface CreateMemoryAdmissionStoreOptions {
  now?: number | string | Date | (() => number | string | Date);
  currentnessOracle?: AdmissionCurrentnessOracle;
  maxCurrentnessAgeMs?: number;
  executionProgramVerificationPolicy?: ExecutionProgramVerificationPolicy;
  executionProgramStatusOracle?: ExecutionProgramStatusOracle;
  maxExecutionProgramStatusAgeMs?: number;
  executionProgramActionMatchVerifier?: ExecutionProgramActionMatchVerifier;
  ownerTokenFactory?: () => string;
  invocationTokenFactory?: () => string;
  /** Trusted current heads provisioned before reservation; missing heads fail closed. */
  initialMonotonicCounterHeads?: readonly AdmissionMonotonicCounterHead[];
}

export class AdmissionStoreValidationError extends TypeError {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'AdmissionStoreValidationError';
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new AdmissionStoreValidationError(code, message);
}

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function canonical(value: Json): string {
  try { return canonicalizeFiniteJson(value); }
  catch { throw new AdmissionStoreValidationError('invalid_json', 'value is outside canonical JSON'); }
}

function hash(domain: string, value: unknown): AdmissionDigest {
  return `sha256:${crypto.createHash('sha256').update(domain).update('\0').update(canonical(value as Json)).digest('hex')}`;
}

/** Deterministic marker over the complete closed report-snapshot body. */
export function executionProgramReportSnapshotMarker(
  snapshot: Readonly<ExecutionProgramReportSnapshotBody>,
): AdmissionDigest {
  if (!plain(snapshot)
      || Reflect.ownKeys(snapshot).length !== 5
      || ![
        '@version', 'tenant_id', 'program_digest', 'runtime_state', 'occurrences',
      ].every((key) => Object.hasOwn(snapshot, key))
      || snapshot['@version'] !== EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION
      || typeof snapshot.tenant_id !== 'string' || !IDENTIFIER.test(snapshot.tenant_id)
      || typeof snapshot.program_digest !== 'string' || !SHA256.test(snapshot.program_digest)
      || !plain(snapshot.runtime_state)
      || !Array.isArray(snapshot.occurrences)) {
    fail('invalid_execution_program_report_snapshot', 'report snapshot body is invalid');
  }
  return hash(`${EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION}:MARKER`, snapshot);
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function frozenCopy<T>(value: T): Readonly<T> {
  return deepFreeze(JSON.parse(canonicalizeFiniteJson(value)) as T);
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) fail('invalid_identifier', `${field} is invalid`);
  return value;
}

function digest(value: unknown, field: string): AdmissionDigest {
  if (typeof value !== 'string' || !SHA256.test(value)) fail('invalid_digest', `${field} is invalid`);
  return value as AdmissionDigest;
}

function instant(value: unknown, field: string): { iso: string; ms: number } {
  if (typeof value !== 'string' || !RFC3339.test(value)) fail('invalid_instant', `${field} must be RFC 3339`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) fail('invalid_instant', `${field} must identify an instant`);
  return { iso: new Date(ms).toISOString(), ms };
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail('invalid_integer', `${field} is invalid`);
  return value as number;
}

function stringBytes(value: string): number { return Buffer.byteLength(value, 'utf8'); }

function currentMs(source: CreateMemoryAdmissionStoreOptions['now']): number {
  const raw = typeof source === 'function' ? source() : source;
  if (raw === undefined) return Date.now();
  if (raw instanceof Date) return raw.getTime();
  if (typeof raw === 'string') return instant(raw, 'now').ms;
  if (!Number.isFinite(raw)) fail('invalid_time', 'now is invalid');
  return raw as number;
}

const EXECUTION_PROGRAM_CONTEXT_KEYS = Object.freeze([
  'expected_program_id',
  'expected_tenant_id',
  'expected_authorization_digest',
  'expected_audience',
] as const);

function executionProgramRegistrationContext(
  raw: unknown,
): ExecutionProgramRegistrationContext | null {
  if (!plain(raw)
      || Reflect.ownKeys(raw).length !== EXECUTION_PROGRAM_CONTEXT_KEYS.length
      || !EXECUTION_PROGRAM_CONTEXT_KEYS.every((key) => Object.hasOwn(raw, key))) {
    return null;
  }
  try {
    return {
      expected_program_id: identifier(raw.expected_program_id, 'expected_program_id'),
      expected_tenant_id: identifier(raw.expected_tenant_id, 'expected_tenant_id'),
      expected_authorization_digest: digest(
        raw.expected_authorization_digest,
        'expected_authorization_digest',
      ),
      expected_audience: identifier(raw.expected_audience, 'expected_audience'),
    };
  } catch {
    return null;
  }
}

function executionProgramTrustPolicy(
  raw: ExecutionProgramVerificationPolicy | undefined,
): {
  trustedKeys: TrustedRiskKeys;
  activeAuthorizers: ReadonlyMap<string, string>;
} {
  const trustedKeys = Object.create(null) as TrustedRiskKeys;
  const activeAuthorizers = new Map<string, string>();
  if (raw === undefined) return { trustedKeys, activeAuthorizers };
  if (!plain(raw) || Reflect.ownKeys(raw).length !== 1
      || !Object.hasOwn(raw, 'trusted_keys') || !plain(raw.trusted_keys)) {
    fail('invalid_program_verification_policy', 'execution program verification policy is invalid');
  }
  for (const [keyId, value] of Object.entries(raw.trusted_keys)) {
    if (!IDENTIFIER.test(keyId)
        || !plain(value)
        || Reflect.ownKeys(value).length !== 4
        || !['issuer_id', 'public_key', 'role', 'status'].every((key) => Object.hasOwn(value, key))
        || !IDENTIFIER.test(String(value.issuer_id ?? ''))
        || typeof value.public_key !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(value.public_key)
        || value.role !== 'program_authorizer'
        || !['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(String(value.status ?? ''))) {
      fail('invalid_program_verification_policy', 'execution program authorizer pin is invalid');
    }
    if (value.status !== 'ACTIVE') continue;
    trustedKeys[keyId] = {
      issuer_id: value.issuer_id as string,
      public_key: value.public_key,
    };
    activeAuthorizers.set(keyId, value.issuer_id as string);
  }
  return { trustedKeys, activeAuthorizers };
}

function normalizeInputs(raw: unknown, admittedAt: number): AdmissionInput[] {
  if (!Array.isArray(raw) || raw.length > ADMISSION_LIMITS.inputs) fail('invalid_inputs', 'inputs are invalid');
  const counts = new Map<AdmissionInputRole, number>();
  const seen = new Set<string>();
  const inputs = raw.map((entry, index) => {
    if (!plain(entry)) fail('invalid_input', `inputs[${index}] is invalid`);
    const role = entry.role as AdmissionInputRole;
    if (!ROLE_ORDER.has(role)) fail('invalid_input_role', `inputs[${index}].role is invalid`);
    const normalized: AdmissionInput = {
      role,
      artifact_type: identifier(entry.artifact_type, `inputs[${index}].artifact_type`),
      subject: identifier(entry.subject, `inputs[${index}].subject`),
      payload_digest: digest(entry.payload_digest, `inputs[${index}].payload_digest`),
      profile_digest: digest(entry.profile_digest, `inputs[${index}].profile_digest`),
      verifier_id: identifier(entry.verifier_id, `inputs[${index}].verifier_id`),
      trust_configuration_digest: digest(entry.trust_configuration_digest, `inputs[${index}].trust_configuration_digest`),
      valid_until: instant(entry.valid_until, `inputs[${index}].valid_until`).iso,
    };
    if (Date.parse(normalized.valid_until) <= admittedAt) fail('expired_input', `inputs[${index}] is expired`);
    const key = canonical(normalized as unknown as Json);
    if (seen.has(key)) fail('duplicate_input', `inputs[${index}] is duplicated`);
    seen.add(key);
    counts.set(role, (counts.get(role) ?? 0) + 1);
    if (!REPEATABLE_ROLES.has(role) && (counts.get(role) ?? 0) > 1) fail('duplicate_input_role', `${role} is singleton`);
    return normalized;
  });
  for (const role of REQUIRED_SINGLETON_ROLES) if (counts.get(role) !== 1) fail('missing_input_role', `${role} is required exactly once`);
  for (const role of REPEATABLE_ROLES) if ((counts.get(role) ?? 0) < 1) fail('missing_input_role', `${role} is required`);
  inputs.sort((left, right) => {
    const role = (ROLE_ORDER.get(left.role) ?? 99) - (ROLE_ORDER.get(right.role) ?? 99);
    if (role !== 0) return role;
    return Buffer.from(canonical(left as unknown as Json)).compare(Buffer.from(canonical(right as unknown as Json)));
  });
  return inputs;
}

function normalizeDigests(raw: unknown, field: string, limit: number): AdmissionDigest[] {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > limit) fail('invalid_digest_list', `${field} is invalid`);
  const values = raw.map((value, index) => digest(value, `${field}[${index}]`)).sort();
  if (new Set(values).size !== values.length) fail('duplicate_digest', `${field} contains duplicates`);
  return values;
}

function normalizeResources(raw: unknown, admittedAt: number): AdmissionResourceReservationInput[] {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > ADMISSION_LIMITS.resources) fail('invalid_resources', 'resource reservations are invalid');
  const allowed = new Set<AdmissionResourceKind>([
    'replay', 'capability', 'budget', 'qualification_use', 'provider_operation',
    'external_lease', 'monotonic_counter', 'execution_program',
  ]);
  const seen = new Set<string>();
  const values = raw.map((entry, index) => {
    if (!plain(entry) || !allowed.has(entry.kind as AdmissionResourceKind)) fail('invalid_resource', `resource[${index}] is invalid`);
    const counter = entry.kind === 'monotonic_counter';
    const allowedKeys = new Set([
      'kind', 'resource_id', 'reservation_id', 'digest', 'expires_at',
      ...(counter ? ['expected_value', 'next_value'] : []),
    ]);
    if (Reflect.ownKeys(entry).some((key) => typeof key !== 'string' || !allowedKeys.has(key))) {
      fail('invalid_resource', `resource[${index}] has unknown fields`);
    }
    const value: AdmissionResourceReservationInput = {
      kind: entry.kind as AdmissionResourceKind,
      resource_id: identifier(entry.resource_id, `resource[${index}].resource_id`),
      reservation_id: identifier(entry.reservation_id, `resource[${index}].reservation_id`),
      digest: digest(entry.digest, `resource[${index}].digest`),
      expires_at: instant(entry.expires_at, `resource[${index}].expires_at`).iso,
    };
    if (counter) {
      value.expected_value = nonNegativeInteger(
        entry.expected_value,
        `resource[${index}].expected_value`,
      );
      value.next_value = nonNegativeInteger(
        entry.next_value,
        `resource[${index}].next_value`,
      );
      if (value.next_value <= value.expected_value || value.next_value > 0xffffffff) {
        fail('invalid_resource', `resource[${index}] counter transition is invalid`);
      }
    } else if (entry.expected_value !== undefined || entry.next_value !== undefined) {
      fail('invalid_resource', `resource[${index}] counter fields are invalid`);
    }
    if (Date.parse(value.expires_at) <= admittedAt) fail('expired_resource', `resource[${index}] is expired`);
    const key = `${value.kind}\0${value.resource_id}`;
    if (seen.has(key)) fail('duplicate_resource', `resource[${index}] is duplicated`);
    seen.add(key);
    return value;
  });
  values.sort((left, right) => Buffer.from(`${left.kind}\0${left.resource_id}`).compare(Buffer.from(`${right.kind}\0${right.resource_id}`)));
  return values;
}

function normalizeRelation(raw: unknown): AdmissionRelation | null {
  if (raw === undefined || raw === null) return null;
  if (!plain(raw)) fail('invalid_relation', 'relation is invalid');
  return {
    tenant_id: identifier(raw.tenant_id, 'relation.tenant_id'),
    admission_id: identifier(raw.admission_id, 'relation.admission_id'),
    operation_id: identifier(raw.operation_id, 'relation.operation_id'),
    snapshot_digest: digest(raw.snapshot_digest, 'relation.snapshot_digest'),
  };
}

export function createAdmissionSnapshot(raw: AdmissionSnapshotInput): Readonly<AdmissionSnapshot> {
  try { raw = JSON.parse(canonicalizeFiniteJson(raw)) as AdmissionSnapshotInput; }
  catch { fail('invalid_snapshot', 'snapshot input is outside canonical JSON'); }
  if (!plain(raw)) fail('invalid_snapshot', 'snapshot input is invalid');
  const admitted = instant(raw.admitted_at, 'admitted_at');
  const expires = instant(raw.expires_at, 'expires_at');
  if (expires.ms <= admitted.ms) fail('invalid_expiration', 'expires_at must follow admitted_at');
  const inputs = normalizeInputs(raw.inputs, admitted.ms);
  const resources = normalizeResources(raw.resource_reservations, admitted.ms);
  const status = raw.qualification_status;
  if (!plain(status)) fail('invalid_status_binding', 'qualification_status is invalid');
  const statusBinding: QualificationStatusBinding = {
    authority_id: identifier(status.authority_id, 'qualification_status.authority_id'),
    sequence: nonNegativeInteger(status.sequence, 'qualification_status.sequence'),
    head_payload_digest: digest(status.head_payload_digest, 'qualification_status.head_payload_digest'),
    observed_at: instant(status.observed_at, 'qualification_status.observed_at').iso,
    expires_at: instant(status.expires_at, 'qualification_status.expires_at').iso,
  };
  const custody = raw.candidate_custody;
  if (!plain(custody)
      || !['GATE', 'EXECUTOR_ADAPTER', 'EXTERNAL'].includes(custody.request_construction)
      || !['GATE', 'EXECUTOR_ADAPTER', 'EXTERNAL'].includes(custody.mutation_credential_custody)
      || !['SYSTEM_OF_RECORD', 'ACTUATOR', 'MIDDLEWARE'].includes(custody.enforcement_placement)) {
    fail('invalid_custody', 'candidate_custody is invalid');
  }
  const provider = raw.provider;
  if (!plain(provider)) fail('invalid_provider', 'provider is invalid');
  const body: AdmissionSnapshotBody = {
    '@version': ADMISSION_SNAPSHOT_VERSION,
    tenant_id: identifier(raw.tenant_id, 'tenant_id'),
    admission_id: identifier(raw.admission_id, 'admission_id'),
    operation_id: identifier(raw.operation_id, 'operation_id'),
    candidate_manifest_digest: digest(raw.candidate_manifest_digest, 'candidate_manifest_digest'),
    runtime_measurement_digest: digest(raw.runtime_measurement_digest, 'runtime_measurement_digest'),
    candidate_custody: {
      request_construction: custody.request_construction as CandidateCustodyBinding['request_construction'],
      mutation_credential_custody: custody.mutation_credential_custody as CandidateCustodyBinding['mutation_credential_custody'],
      enforcement_placement: custody.enforcement_placement as CandidateCustodyBinding['enforcement_placement'],
      evidence_digest: digest(custody.evidence_digest, 'candidate_custody.evidence_digest'),
    },
    assignment_digest: digest(raw.assignment_digest, 'assignment_digest'),
    qualification_policy_digest: digest(raw.qualification_policy_digest, 'qualification_policy_digest'),
    test_result_payload_digests: normalizeDigests(raw.test_result_payload_digests, 'test_result_payload_digests', ADMISSION_LIMITS.testResults),
    agent_evaluation_evidence_payload_digests: normalizeDigests(raw.agent_evaluation_evidence_payload_digests, 'agent_evaluation_evidence_payload_digests', ADMISSION_LIMITS.agentEvidence),
    qualification_statement_payload_digest: digest(raw.qualification_statement_payload_digest, 'qualification_statement_payload_digest'),
    qualification_status: statusBinding,
    caid: typeof raw.caid === 'string' && CAID.test(raw.caid) ? raw.caid : fail('invalid_caid', 'caid is invalid'),
    action_digest: digest(raw.action_digest, 'action_digest'),
    effect_request_digest: digest(raw.effect_request_digest, 'effect_request_digest'),
    provider: {
      provider_id: identifier(provider.provider_id, 'provider.provider_id'),
      account_id: identifier(provider.account_id, 'provider.account_id'),
      environment: identifier(provider.environment, 'provider.environment'),
    },
    executor_adapter_digest: digest(raw.executor_adapter_digest, 'executor_adapter_digest'),
    idempotency_key: identifier(raw.idempotency_key, 'idempotency_key'),
    authorization_policy_digest: digest(raw.authorization_policy_digest, 'authorization_policy_digest'),
    trust_epoch: nonNegativeInteger(raw.trust_epoch, 'trust_epoch'),
    trust_configuration_digest: digest(raw.trust_configuration_digest, 'trust_configuration_digest'),
    configuration_epoch: nonNegativeInteger(raw.configuration_epoch, 'configuration_epoch'),
    configuration_digest: digest(raw.configuration_digest, 'configuration_digest'),
    inputs,
    resource_reservations: resources,
    admitted_at: admitted.iso,
    expires_at: expires.iso,
    supersedes_admission_id: raw.supersedes_admission_id === undefined || raw.supersedes_admission_id === null
      ? null : identifier(raw.supersedes_admission_id, 'supersedes_admission_id'),
    remedy_for: normalizeRelation(raw.remedy_for),
  };
  const ceilings = [statusBinding.expires_at, ...inputs.map((input) => input.valid_until), ...resources.map((resource) => resource.expires_at)];
  if (ceilings.some((ceiling) => expires.ms > Date.parse(ceiling))) fail('expiration_exceeds_evidence', 'expires_at exceeds an input deadline');
  const snapshot: AdmissionSnapshot = {
    body: frozenCopy(body),
    snapshot_digest: hash(`${ADMISSION_SNAPSHOT_VERSION}:DIGEST`, body),
  };
  return frozenCopy(snapshot);
}

function validateSnapshot(raw: AdmissionSnapshot): Readonly<AdmissionSnapshot> {
  if (!plain(raw) || !plain(raw.body)) fail('invalid_snapshot', 'snapshot is invalid');
  const recreated = createAdmissionSnapshot(raw.body as unknown as AdmissionSnapshotInput);
  if (raw.snapshot_digest !== recreated.snapshot_digest) fail('snapshot_digest_mismatch', 'snapshot digest does not match body');
  return recreated;
}

function operationKey(tenant: string, operation: string): string { return JSON.stringify([tenant, operation]); }
function admissionKey(tenant: string, admission: string): string { return JSON.stringify([tenant, admission]); }
function resourceKey(tenant: string, resource: AdmissionResourceReservationInput): string { return JSON.stringify([tenant, resource.kind, resource.resource_id]); }
function monotonicCounterKey(tenant: string, resourceId: string): string { return JSON.stringify([tenant, 'monotonic_counter', resourceId]); }
function tokenDigest(token: string): AdmissionDigest { return hash(`${ADMISSION_RECORD_VERSION}:TOKEN`, token); }

export function createExecutionProgramAdmissionBinding(
  input: ExecutionProgramAdmissionBindingInput,
): AdmissionResourceReservationInput {
  const tenantId = identifier(input.tenant_id, 'tenant_id');
  const programDigest = digest(input.program_digest, 'program_digest');
  const nodeId = identifier(input.node_id, 'node_id');
  const occurrenceId = identifier(input.occurrence_id, 'occurrence_id');
  const expiresAt = instant(input.expires_at, 'expires_at').iso;
  const identityTuple = [tenantId, programDigest, nodeId, occurrenceId] as const;
  const identityDigest = hash(
    `${EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION}:IDENTITY`,
    identityTuple as unknown as Json,
  );
  const binding = {
    '@version': EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION,
    tenant_id: tenantId,
    program_digest: programDigest,
    node_id: nodeId,
    occurrence_id: occurrenceId,
    expires_at: expiresAt,
  };
  return frozenCopy({
    kind: 'execution_program',
    resource_id: `execution-program:${identityDigest}`,
    reservation_id: `execution-program-reservation:${identityDigest}`,
    digest: hash(`${EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION}:DIGEST`, binding),
    expires_at: expiresAt,
  });
}

function defaultOwnerToken(): string { return `admission-owner:v2:${crypto.randomBytes(32).toString('base64url')}`; }
function defaultInvocationToken(): string { return `admission-invocation:v2:${crypto.randomBytes(32).toString('base64url')}`; }
function validateOwner(value: unknown): string {
  if (typeof value !== 'string' || !OWNER_TOKEN.test(value)) fail('invalid_owner_token', 'owner token is invalid');
  return value;
}

type MutableRecord = Omit<AdmissionRecord, 'record_digest' | 'resources'> & {
  resources: AdmissionResourceReservation[];
  record_digest?: AdmissionDigest;
};
interface Stored { record: Readonly<AdmissionRecord>; ownerToken: string }

interface MutableExecutionProgramState extends Omit<ExecutionProgramRuntimeState, 'budgets'> {
  budgets: ExecutionProgramBudgetState[];
}

interface MutableExecutionProgramOccurrence extends Omit<ExecutionProgramOccurrence, 'charges'> {
  charges: ExecutionProgramCharge[];
}

function finalizeRecord(raw: MutableRecord): Readonly<AdmissionRecord> {
  const { record_digest: _ignored, ...body } = raw;
  return frozenCopy({ ...body, record_digest: hash(`${ADMISSION_RECORD_VERSION}:DIGEST`, body) } as AdmissionRecord);
}

function finalizeJournal(raw: Omit<AdmissionJournalEntry, 'entry_digest'>): Readonly<AdmissionJournalEntry> {
  return frozenCopy({ ...raw, entry_digest: hash(`${ADMISSION_JOURNAL_VERSION}:DIGEST`, raw) });
}

export function verifyAdmissionJournal(entries: readonly AdmissionJournalEntry[]): { ok: true } | { ok: false; at: number; reason: string } {
  let predecessor: string | null = null;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.sequence !== index) return { ok: false, at: index, reason: 'sequence_mismatch' };
    if (entry.predecessor_digest !== predecessor) return { ok: false, at: index, reason: 'predecessor_mismatch' };
    const { entry_digest, ...body } = entry;
    if (hash(`${ADMISSION_JOURNAL_VERSION}:DIGEST`, body) !== entry_digest) return { ok: false, at: index, reason: 'digest_mismatch' };
    predecessor = entry_digest;
  }
  return { ok: true };
}

function exactOperationIdentity(left: AdmissionSnapshotBody, right: AdmissionSnapshotBody): boolean {
  return left.tenant_id === right.tenant_id
    && left.operation_id === right.operation_id
    && left.caid === right.caid
    && left.action_digest === right.action_digest
    && left.effect_request_digest === right.effect_request_digest
    && canonical(left.provider as unknown as Json) === canonical(right.provider as unknown as Json)
    && left.executor_adapter_digest === right.executor_adapter_digest
    && left.idempotency_key === right.idempotency_key;
}

function currentnessMatches(
  snapshot: Readonly<AdmissionSnapshot>,
  observation: AdmissionCurrentnessObservation,
  now: number,
  maxAgeMs: number,
): boolean {
  const body = snapshot.body;
  const observedAt = Date.parse(observation.observed_at);
  if (observation['@version'] !== ADMISSION_CURRENTNESS_VERSION
      || observation.candidate_match !== 'EXACT_MATCH'
      || !Number.isFinite(observedAt)
      || observedAt > now
      || now - observedAt > maxAgeMs
      || Date.parse(observation.qualification_status_expires_at) <= now
      || observation.qualification_status_authority_id !== body.qualification_status.authority_id
      || observation.qualification_status_sequence !== body.qualification_status.sequence
      || observation.qualification_status_head_digest !== body.qualification_status.head_payload_digest
      || observation.trust_epoch !== body.trust_epoch
      || observation.trust_configuration_digest !== body.trust_configuration_digest
      || observation.configuration_epoch !== body.configuration_epoch
      || observation.configuration_digest !== body.configuration_digest
      || observation.runtime_measurement_digest !== body.runtime_measurement_digest) return false;
  const expected = body.resource_reservations.filter((resource) => resource.kind === 'external_lease');
  if (observation.external_leases.length !== expected.length) return false;
  const byId = new Map(observation.external_leases.map((lease) => [lease.resource_id, lease]));
  return expected.every((lease) => {
    const current = byId.get(lease.resource_id);
    return current?.digest === lease.digest && Date.parse(current.expires_at) > now;
  });
}

/** Linearizable, explicitly test-only reference implementation. */
export function createMemoryAdmissionStore(options: CreateMemoryAdmissionStoreOptions = {}): ExecutionProgramAdmissionStore & { readonly testOnly: true } {
  const snapshots = new Map<string, Readonly<AdmissionSnapshot>>();
  const records = new Map<string, Stored>();
  const operationHeads = new Map<string, string>();
  const resourceOwners = new Map<string, string>();
  const monotonicCounterHeads = new Map<string, number>();
  const configuredCounterHeads = options.initialMonotonicCounterHeads ?? [];
  if (!Array.isArray(configuredCounterHeads)) {
    fail('invalid_counter_heads', 'initial monotonic counter heads are invalid');
  }
  const counterHeadKeys = new Set(['tenant_id', 'resource_id', 'current_value']);
  for (const [index, head] of configuredCounterHeads.entries()) {
    if (!plain(head)
        || Reflect.ownKeys(head).some((key) => typeof key !== 'string' || !counterHeadKeys.has(key))
        || Reflect.ownKeys(head).length !== counterHeadKeys.size) {
      fail('invalid_counter_head', `initial monotonic counter head[${index}] is invalid`);
    }
    const tenant = identifier(head.tenant_id, `initialMonotonicCounterHeads[${index}].tenant_id`);
    const resourceId = identifier(head.resource_id, `initialMonotonicCounterHeads[${index}].resource_id`);
    const currentValue = nonNegativeInteger(
      head.current_value,
      `initialMonotonicCounterHeads[${index}].current_value`,
    );
    if (currentValue > 0xffffffff) {
      fail('invalid_counter_head', `initial monotonic counter head[${index}] is invalid`);
    }
    const key = monotonicCounterKey(tenant, resourceId);
    if (monotonicCounterHeads.has(key)) {
      fail('duplicate_counter_head', `initial monotonic counter head[${index}] is duplicated`);
    }
    monotonicCounterHeads.set(key, currentValue);
  }
  const journals = new Map<string, readonly Readonly<AdmissionJournalEntry>[]>();
  const executionPrograms = new Map<string, MutableExecutionProgramState>();
  const executionProgramHeads = new Map<string, string>();
  const executionProgramOccurrences = new Map<string, MutableExecutionProgramOccurrence>();
  const executionProgramAdmissions = new Map<string, string>();
  const executionProgramAuthorizationOwners = new Map<string, string>();
  const executionProgramNodeOccurrenceCounts = new Map<string, number>();
  const executionProgramTerminalOutcomeCounts = new Map<string, number>();
  const currentnessOracle = options.currentnessOracle;
  const executionProgramStatusOracle = options.executionProgramStatusOracle;
  const executionProgramActionMatchVerifier = options.executionProgramActionMatchVerifier;
  const programTrust = executionProgramTrustPolicy(options.executionProgramVerificationPolicy);
  const ownerFactory = options.ownerTokenFactory ?? defaultOwnerToken;
  const invocationFactory = options.invocationTokenFactory ?? defaultInvocationToken;
  const maxCurrentnessAgeMs = options.maxCurrentnessAgeMs
    ?? ADMISSION_LIMITS.currentnessMaxAgeMs;
  if (!Number.isSafeInteger(maxCurrentnessAgeMs)
      || maxCurrentnessAgeMs < 1
      || maxCurrentnessAgeMs > 300_000) {
    fail('invalid_currentness_age', 'max currentness age is invalid');
  }
  const maxExecutionProgramStatusAgeMs = options.maxExecutionProgramStatusAgeMs
    ?? ADMISSION_LIMITS.currentnessMaxAgeMs;
  if (!Number.isSafeInteger(maxExecutionProgramStatusAgeMs)
      || maxExecutionProgramStatusAgeMs < 1
      || maxExecutionProgramStatusAgeMs > 300_000) {
    fail('invalid_program_status_age', 'max execution program status age is invalid');
  }
  let queue: Promise<void> = Promise.resolve();
  const externalVerificationTimeoutMs = 5_000;

  function atomic<T>(fn: () => T | Promise<T>): Promise<T> {
    const next = queue.then(fn, fn);
    queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async function boundedExternalVerification<T>(
    operation: () => Promise<T>,
  ): Promise<T | null> {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation(),
        new Promise<null>((resolve) => {
          timeout = setTimeout(() => resolve(null), externalVerificationTimeoutMs);
          timeout.unref();
        }),
      ]);
    } catch {
      return null;
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
    }
  }

  function append(key: string, ownerToken: string, draft: MutableRecord, event: AdmissionJournalEvent, at: string): Readonly<AdmissionRecord> {
    const history = journals.get(key) ?? [];
    if (draft.revision !== history.length) throw new Error('admission invariant: revision/journal mismatch');
    const record = finalizeRecord(draft);
    const previous = history.at(-1);
    const entry = finalizeJournal({
      '@version': ADMISSION_JOURNAL_VERSION,
      tenant_id: record.tenant_id,
      admission_id: record.admission_id,
      operation_id: record.operation_id,
      sequence: history.length,
      event,
      snapshot_digest: record.snapshot_digest,
      record_digest: record.record_digest,
      predecessor_digest: previous?.entry_digest ?? null,
      recorded_at: at,
    });
    journals.set(key, [...history, entry]);
    records.set(key, { record, ownerToken });
    return record;
  }

  function next(current: Readonly<AdmissionRecord>, at: string, changes: Partial<MutableRecord>): MutableRecord {
    return {
      ...current,
      ...changes,
      revision: current.revision + 1,
      updated_at: at,
      predecessor_record_digest: current.record_digest,
      resources: changes.resources ?? current.resources.map((resource) => ({ ...resource })),
      record_digest: undefined,
    };
  }

  function selectCas(input: AdmissionCas): { key: string; stored: Stored } | AdmissionRefusal {
    const key = admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'));
    const stored = records.get(key);
    if (!stored) return { ok: false, reason: 'admission_not_found' };
    if (stored.record.revision !== nonNegativeInteger(input.expected_revision, 'expected_revision')) return { ok: false, reason: 'revision_conflict' };
    if (stored.ownerToken !== validateOwner(input.owner_token)) return { ok: false, reason: 'owner_conflict' };
    return { key, stored };
  }

  function resourcesAvailable(snapshot: Readonly<AdmissionSnapshot>, ignored?: string): boolean {
    return snapshot.body.resource_reservations.every((resource) => {
      if (resource.kind === 'monotonic_counter') {
        const current = monotonicCounterHeads.get(resourceKey(snapshot.body.tenant_id, resource));
        return current === resource.expected_value;
      }
      const owner = resourceOwners.get(resourceKey(snapshot.body.tenant_id, resource));
      return owner === undefined || owner === ignored;
    });
  }
  // Monotonic counter heads advance atomically with the successful reservation mutation.
  function claimResources(snapshot: Readonly<AdmissionSnapshot>, key: string): void {
    for (const resource of snapshot.body.resource_reservations) {
      const rKey = resourceKey(snapshot.body.tenant_id, resource);
      if (resource.kind === 'monotonic_counter') {
        monotonicCounterHeads.set(rKey, resource.next_value!);
      } else resourceOwners.set(rKey, key);
    }
  }
  function freeResources(record: Readonly<AdmissionRecord>, key: string): void {
    for (const resource of record.resources) {
      if (resource.kind === 'monotonic_counter') continue;
      const rKey = resourceKey(record.tenant_id, resource);
      if (resourceOwners.get(rKey) === key) resourceOwners.delete(rKey);
    }
  }

  function executionProgramKey(tenantId: string, programDigest: string): string {
    return JSON.stringify([tenantId, programDigest]);
  }

  function executionProgramHeadKey(tenantId: string, programId: string): string {
    return JSON.stringify([tenantId, programId]);
  }

  function executionProgramAuthorizationKey(
    tenantId: string,
    authorizationDigest: string,
  ): string {
    return JSON.stringify([tenantId, authorizationDigest]);
  }

  function executionProgramOccurrenceKey(
    tenantId: string,
    programDigest: string,
    occurrenceId: string,
  ): string {
    return JSON.stringify([tenantId, programDigest, occurrenceId]);
  }

  function executionProgramNodeCountKey(
    tenantId: string,
    programDigest: string,
    nodeId: string,
  ): string {
    return JSON.stringify([tenantId, programDigest, nodeId]);
  }

  function executionProgramTerminalCountKey(
    tenantId: string,
    programDigest: string,
    nodeId: string,
    outcome: 'COMMITTED' | 'PROVEN_NOT_COMMITTED',
  ): string {
    return JSON.stringify([tenantId, programDigest, nodeId, outcome]);
  }

  function incrementIndex(index: Map<string, number>, key: string, amount: 1 | -1): void {
    const nextValue = (index.get(key) ?? 0) + amount;
    if (nextValue < 0) throw new Error('execution program invariant: negative index');
    if (nextValue === 0) index.delete(key);
    else index.set(key, nextValue);
  }

  function publicExecutionProgram(
    state: MutableExecutionProgramState,
  ): Readonly<ExecutionProgramRuntimeState> {
    return frozenCopy(state);
  }

  function findProgramNode(
    state: Readonly<ExecutionProgramRuntimeState>,
    nodeId: string,
  ): Readonly<ExecutionProgramNode> | null {
    return state.program.nodes.find((node) => node.node_id === nodeId) ?? null;
  }

  async function executionProgramActionMatches(
    state: Readonly<ExecutionProgramRuntimeState>,
    action: Readonly<ExecutionProgramAction>,
    snapshot: Readonly<AdmissionSnapshot>,
    evidence: unknown,
  ): Promise<boolean> {
    if (action.mode === 'exact') {
      return evidence === undefined
        && snapshot.body.caid === action.caid
        && snapshot.body.action_digest === action.action_digest;
    }
    const verifier = executionProgramActionMatchVerifier;
    const input = snapshot.body.inputs.find((entry) => entry.role === 'aeb');
    if (evidence === undefined || !verifier || !input
        || input.subject !== state.program.subject_id
        || input.profile_digest !== action.profile_digest) return false;
    const expected: ExecutionProgramActionMatchExpected = {
      tenant_id: state.tenant_id,
      profile_id: action.profile_id,
      profile_digest: action.profile_digest as AdmissionDigest,
      subject_id: state.program.subject_id,
      operation_id: snapshot.body.operation_id,
      caid: snapshot.body.caid,
      action_digest: snapshot.body.action_digest,
      verifier_id: input.verifier_id,
      evidence_payload_digest: input.payload_digest,
      evidence_trust_configuration_digest: input.trust_configuration_digest,
      trust_epoch: snapshot.body.trust_epoch,
      trust_configuration_digest: snapshot.body.trust_configuration_digest,
    };
    try {
      const result = await boundedExternalVerification(() => verifier.verify({
        evidence,
        expected: frozenCopy(expected),
      }));
      if (!plain(result)
          || Reflect.ownKeys(result).length !== Reflect.ownKeys(expected).length + 2
          || result.valid !== true || result.result !== 'MATCH') return false;
      return Object.entries(expected).every(([key, value]) => result[key] === value);
    } catch {
      return false;
    }
  }

  function executionProgramDependenciesSatisfied(
    state: MutableExecutionProgramState,
    node: Readonly<ExecutionProgramNode>,
  ): boolean {
    return node.depends_on.every((dependency) => dependency.outcomes.some((outcome) => (
      (executionProgramTerminalOutcomeCounts.get(executionProgramTerminalCountKey(
        state.tenant_id,
        state.program_digest,
        dependency.node_id,
        outcome,
      )) ?? 0) > 0
    )));
  }

  function executionProgramStatusReason(
    state: MutableExecutionProgramState,
  ): ExecutionProgramRefusalReason | null {
    if (state.status === 'SUPERSEDED') return 'program_superseded';
    if (state.status === 'SUSPENDED') return 'program_suspended';
    if (state.status === 'REVOKED') return 'program_revoked';
    return null;
  }

  async function readExecutionProgramStatus(
    state: Readonly<ExecutionProgramRuntimeState>,
  ): Promise<ExecutionProgramStatusObservation | null> {
    const oracle = executionProgramStatusOracle;
    if (!oracle || typeof oracle.read !== 'function') return null;
    return boundedExternalVerification(() => oracle.read(frozenCopy({
      tenant_id: state.tenant_id,
      program_id: state.program_id,
      program_digest: state.program_digest,
      version: state.version,
    })));
  }

  function applyExecutionProgramStatus(
    state: MutableExecutionProgramState,
    observation: ExecutionProgramStatusObservation | null,
    now: number,
  ): ExecutionProgramRefusalReason | null {
    if (state.status === 'SUPERSEDED' || state.status === 'REVOKED') {
      return executionProgramStatusReason(state);
    }
    const expectedKeys = [
      '@version', 'tenant_id', 'program_id', 'program_digest', 'version',
      'status', 'sequence', 'observed_at', 'expires_at',
    ];
    const observedAt = plain(observation) && typeof observation.observed_at === 'string'
      ? Date.parse(observation.observed_at) : NaN;
    const expiresAt = plain(observation) && typeof observation.expires_at === 'string'
      ? Date.parse(observation.expires_at) : NaN;
    if (!plain(observation)
        || Reflect.ownKeys(observation).length !== expectedKeys.length
        || !expectedKeys.every((key) => Object.hasOwn(observation, key))
        || observation['@version'] !== EXECUTION_PROGRAM_STATUS_VERSION
        || observation.tenant_id !== state.tenant_id
        || observation.program_id !== state.program_id
        || observation.program_digest !== state.program_digest
        || observation.version !== state.version
        || !['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(String(observation.status ?? ''))
        || !Number.isSafeInteger(observation.sequence) || observation.sequence < 0
        || !Number.isFinite(observedAt) || !Number.isFinite(expiresAt)
        || observedAt > now || now - observedAt > maxExecutionProgramStatusAgeMs
        || expiresAt <= now || observation.sequence < state.status_sequence
        || (observation.sequence === state.status_sequence
          && (observation.status !== state.status
            || observation.observed_at !== state.status_observed_at
            || observation.expires_at !== state.status_expires_at))) {
      return 'program_status_indeterminate';
    }
    state.status = observation.status;
    state.status_sequence = observation.sequence;
    state.status_observed_at = new Date(observedAt).toISOString();
    state.status_expires_at = new Date(expiresAt).toISOString();
    const statusReason = executionProgramStatusReason(state);
    if (statusReason) return statusReason;
    if (now < Date.parse(state.program.valid_from)) return 'program_not_active';
    if (now >= Date.parse(state.program.expires_at)) return 'program_expired';
    return null;
  }

  function releaseExecutionProgramOccurrenceForAdmission(
    key: string,
    at: string,
  ): void {
    const occurrenceKey = executionProgramAdmissions.get(key);
    if (!occurrenceKey) return;
    const occurrence = executionProgramOccurrences.get(occurrenceKey);
    if (!occurrence || occurrence.state !== 'RESERVED') return;
    const programState = executionPrograms.get(executionProgramKey(
      occurrence.tenant_id,
      occurrence.program_digest,
    ));
    if (!programState) throw new Error('execution program invariant: program missing');
    for (const charge of occurrence.charges) {
      const budget = programState.budgets.find((entry) => entry.budget_id === charge.budget_id);
      if (!budget || budget.reserved < charge.amount) {
        throw new Error('execution program invariant: reserved budget mismatch');
      }
      budget.reserved -= charge.amount;
    }
    incrementIndex(
      executionProgramNodeOccurrenceCounts,
      executionProgramNodeCountKey(
        occurrence.tenant_id,
        occurrence.program_digest,
        occurrence.node_id,
      ),
      -1,
    );
    occurrence.state = 'RELEASED';
    occurrence.updated_at = at;
  }

  function consumeExecutionProgramOccurrenceForAdmission(
    key: string,
    at: string,
  ): ExecutionProgramRefusalReason | null {
    const occurrenceKey = executionProgramAdmissions.get(key);
    if (!occurrenceKey) return 'program_required';
    const occurrence = executionProgramOccurrences.get(occurrenceKey);
    if (!occurrence || occurrence.state !== 'RESERVED') return 'state_conflict';
    const programState = executionPrograms.get(executionProgramKey(
      occurrence.tenant_id,
      occurrence.program_digest,
    ));
    if (!programState) return 'program_not_found';
    const statusReason = executionProgramStatusReason(programState);
    if (statusReason) return statusReason;
    const now = Date.parse(at);
    if (now < Date.parse(programState.program.valid_from)) return 'program_not_active';
    if (now >= Date.parse(programState.program.expires_at)) return 'program_expired';
    const openEffects = [...executionProgramOccurrences.values()].filter((candidate) => (
      candidate.tenant_id === programState.tenant_id
      && candidate.program_digest === programState.program_digest
      && (candidate.state === 'INVOKING' || candidate.state === 'INDETERMINATE')
    )).length;
    if (openEffects >= programState.program.max_concurrent_effects) {
      return 'program_concurrency_exhausted';
    }
    for (const charge of occurrence.charges) {
      const budget = programState.budgets.find((entry) => entry.budget_id === charge.budget_id);
      if (!budget || budget.reserved < charge.amount) return 'program_budget_exhausted';
    }
    for (const charge of occurrence.charges) {
      const budget = programState.budgets.find((entry) => entry.budget_id === charge.budget_id)!;
      budget.reserved -= charge.amount;
      budget.consumed += charge.amount;
    }
    occurrence.state = 'INVOKING';
    occurrence.updated_at = at;
    return null;
  }

  function updateExecutionProgramOccurrenceForAdmission(
    key: string,
    state: Extract<ExecutionProgramOccurrenceState,
      'INDETERMINATE' | 'COMMITTED' | 'PROVEN_NOT_COMMITTED'>,
    at: string,
  ): void {
    const occurrenceKey = executionProgramAdmissions.get(key);
    if (!occurrenceKey) return;
    const occurrence = executionProgramOccurrences.get(occurrenceKey);
    if (!occurrence || !['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(occurrence.state)) {
      throw new Error('execution program invariant: occurrence state mismatch');
    }
    const previous = occurrence.state;
    occurrence.state = state;
    occurrence.updated_at = at;
    if ((state === 'COMMITTED' || state === 'PROVEN_NOT_COMMITTED')
        && previous !== state) {
      incrementIndex(
        executionProgramTerminalOutcomeCounts,
        executionProgramTerminalCountKey(
          occurrence.tenant_id,
          occurrence.program_digest,
          occurrence.node_id,
          state,
        ),
        1,
      );
    }
  }

  function reserveCore(
    raw: AdmissionSnapshotInput | AdmissionSnapshot,
    programAware = false,
  ): AdmissionReserveResult {
    const snapshot = plain(raw) && Object.hasOwn(raw, 'snapshot_digest')
      ? validateSnapshot(raw as AdmissionSnapshot)
      : createAdmissionSnapshot(raw as AdmissionSnapshotInput);
    const body = snapshot.body;
    const authorization = body.inputs.find((entry) => entry.role === 'authorization');
    if (!programAware && authorization && executionProgramAuthorizationOwners.has(
      executionProgramAuthorizationKey(body.tenant_id, authorization.payload_digest),
    )) return { ok: false, reason: 'program_required' };
    if (body.supersedes_admission_id !== null) return { ok: false, reason: 'relation_conflict' };
    const key = admissionKey(body.tenant_id, body.admission_id);
    const opKey = operationKey(body.tenant_id, body.operation_id);
    if (records.has(key)) return { ok: false, reason: 'admission_exists' };
    if (operationHeads.has(opKey)) return { ok: false, reason: 'operation_exists' };
    const now = currentMs(options.now);
    if (Date.parse(body.expires_at) <= now) return { ok: false, reason: 'admission_expired' };
    if (body.remedy_for !== null) {
      const target = records.get(admissionKey(body.remedy_for.tenant_id, body.remedy_for.admission_id));
      if (!target || target.record.snapshot_digest !== body.remedy_for.snapshot_digest) return { ok: false, reason: 'relation_not_found' };
      if (!['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(target.record.state)) return { ok: false, reason: 'relation_conflict' };
      const targetSnapshot = snapshots.get(target.record.snapshot_digest);
      if (!targetSnapshot || targetSnapshot.body.operation_id === body.operation_id || targetSnapshot.body.caid === body.caid) return { ok: false, reason: 'relation_conflict' };
    }
    if (!resourcesAvailable(snapshot)) return { ok: false, reason: 'resource_conflict' };
    const owner = validateOwner(ownerFactory());
    const at = new Date(now).toISOString();
    snapshots.set(snapshot.snapshot_digest, snapshot);
    operationHeads.set(opKey, key);
    claimResources(snapshot, key);
    const record = append(key, owner, {
      '@version': ADMISSION_RECORD_VERSION,
      tenant_id: body.tenant_id,
      admission_id: body.admission_id,
      operation_id: body.operation_id,
      snapshot_digest: snapshot.snapshot_digest,
      revision: 0,
      state: 'RESERVED',
      execution_right: 'RESERVED',
      provider_attempt: 'NOT_ENTERED',
      owner_digest: tokenDigest(owner),
      invocation_token_digest: null,
      provider_outcome: null,
      effect_relation: null,
      resources: body.resource_reservations.map((resource) => ({ ...resource, state: 'RESERVED' })),
      superseded_by_admission_id: null,
      refusal_reason: null,
      invocation_started_at: null,
      created_at: at,
      updated_at: at,
      predecessor_record_digest: null,
    }, 'RESERVED', at);
    return { ok: true, snapshot, record, owner_token: owner };
  }

  function releaseReservedForRefusal(
    key: string,
    stored: Stored,
    reason: string,
    at: string,
  ): void {
    freeResources(stored.record, key);
    append(key, stored.ownerToken, next(stored.record, at, {
      state: 'RELEASED', execution_right: 'RELEASED', refusal_reason: reason,
      resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
    }), 'RELEASED', at);
    releaseExecutionProgramOccurrenceForAdmission(key, at);
  }

  function releaseCore(
    input: AdmissionCas,
    reason: string,
    programAware: boolean,
  ): AdmissionTransitionResult {
    const selected = selectCas(input);
    if ('ok' in selected) return selected;
    const { key, stored } = selected;
    if (executionProgramAdmissions.has(key) && !programAware) {
      return { ok: false, reason: 'program_required' };
    }
    if (programAware && !executionProgramAdmissions.has(key)) {
      return { ok: false, reason: 'program_required' };
    }
    if (stored.record.execution_right === 'CONSUMED') return { ok: false, reason: 'execution_right_consumed' };
    if (stored.record.state !== 'RESERVED') return { ok: false, reason: 'state_conflict' };
    const at = new Date(currentMs(options.now)).toISOString();
    freeResources(stored.record, key);
    const record = append(key, stored.ownerToken, next(stored.record, at, {
      state: 'RELEASED', execution_right: 'RELEASED', refusal_reason: reason,
      resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
    }), 'RELEASED', at);
    releaseExecutionProgramOccurrenceForAdmission(key, at);
    return { ok: true, record };
  }

  function expireCore(
    input: AdmissionCas,
    programAware: boolean,
  ): AdmissionTransitionResult {
    const selected = selectCas(input);
    if ('ok' in selected) return selected;
    const { key, stored } = selected;
    if (executionProgramAdmissions.has(key) && !programAware) {
      return { ok: false, reason: 'program_required' };
    }
    if (programAware && !executionProgramAdmissions.has(key)) {
      return { ok: false, reason: 'program_required' };
    }
    if (stored.record.state !== 'RESERVED') return { ok: false, reason: 'state_conflict' };
    const snapshot = snapshots.get(stored.record.snapshot_digest)!;
    const now = currentMs(options.now);
    if (Date.parse(snapshot.body.expires_at) > now) return { ok: false, reason: 'state_conflict' };
    const at = new Date(now).toISOString();
    freeResources(stored.record, key);
    const record = append(key, stored.ownerToken, next(stored.record, at, {
      state: 'EXPIRED', execution_right: 'RELEASED', refusal_reason: 'admission_expired',
      resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
    }), 'EXPIRED', at);
    releaseExecutionProgramOccurrenceForAdmission(key, at);
    return { ok: true, record };
  }

  async function beginInvocationCore(
    input: AdmissionCas,
    programAware: boolean,
  ): Promise<AdmissionBeginResult> {
    const prepared = await atomic(() => {
      const selected = selectCas(input);
      if ('ok' in selected) return { ready: false as const, result: selected };
      const { key, stored } = selected;
      const linked = executionProgramAdmissions.has(key);
      if (linked !== programAware) {
        return {
          ready: false as const,
          result: { ok: false as const, reason: 'program_required' as const },
        };
      }
      if (stored.record.state !== 'RESERVED'
          || stored.record.execution_right !== 'RESERVED'
          || stored.record.provider_attempt !== 'NOT_ENTERED') {
        return {
          ready: false as const,
          result: { ok: false as const, reason: 'state_conflict' as const },
        };
      }
      const snapshot = snapshots.get(stored.record.snapshot_digest)!;
      let programState: Readonly<ExecutionProgramRuntimeState> | null = null;
      if (programAware) {
        const occurrenceKey = executionProgramAdmissions.get(key);
        const occurrence = occurrenceKey
          ? executionProgramOccurrences.get(occurrenceKey) : undefined;
        const mutableProgramState = occurrence
          ? executionPrograms.get(executionProgramKey(
            occurrence.tenant_id,
            occurrence.program_digest,
          ))
          : undefined;
        if (!mutableProgramState) {
          return {
            ready: false as const,
            result: { ok: false as const, reason: 'program_not_found' as const },
          };
        }
        programState = publicExecutionProgram(mutableProgramState);
      }
      return { ready: true as const, key, snapshot, programState };
    });
    if (!prepared.ready) return prepared.result;

    const [statusObservation, currentnessObservation] = await Promise.all([
      prepared.programState
        ? readExecutionProgramStatus(prepared.programState)
        : Promise.resolve(null),
      currentnessOracle && typeof currentnessOracle.read === 'function'
        ? boundedExternalVerification(() => currentnessOracle.read(prepared.snapshot))
        : Promise.resolve(null),
    ]);
    const validationTime = currentMs(options.now);

    return atomic(() => {
      const selected = selectCas(input);
      if ('ok' in selected) return selected;
      const { key, stored } = selected;
      if (key !== prepared.key
          || stored.record.snapshot_digest !== prepared.snapshot.snapshot_digest
          || executionProgramAdmissions.has(key) !== programAware) {
        return { ok: false, reason: 'revision_conflict' };
      }
      if (stored.record.state !== 'RESERVED'
          || stored.record.execution_right !== 'RESERVED'
          || stored.record.provider_attempt !== 'NOT_ENTERED') {
        return { ok: false, reason: 'state_conflict' };
      }
      const snapshot = snapshots.get(stored.record.snapshot_digest)!;
      if (programAware) {
        const occurrenceKey = executionProgramAdmissions.get(key);
        const occurrence = occurrenceKey
          ? executionProgramOccurrences.get(occurrenceKey) : undefined;
        const programState = occurrence
          ? executionPrograms.get(executionProgramKey(
            occurrence.tenant_id,
            occurrence.program_digest,
          ))
          : undefined;
        const refusal = programState
          ? applyExecutionProgramStatus(programState, statusObservation, validationTime)
          : 'program_not_found';
        if (refusal) {
          const at = new Date(validationTime).toISOString();
          releaseReservedForRefusal(key, stored, refusal, at);
          return { ok: false, reason: refusal as AdmissionRefusalReason };
        }
      }
      if (Date.parse(snapshot.body.expires_at) <= validationTime) {
        return { ok: false, reason: 'admission_expired' };
      }
      const countersCurrent = snapshot.body.resource_reservations.every((resource) => (
        resource.kind !== 'monotonic_counter'
        || (monotonicCounterHeads.get(resourceKey(snapshot.body.tenant_id, resource)) ?? -1)
          >= resource.next_value!
      ));
      if (!currentnessObservation
          || !countersCurrent
          || !currentnessMatches(
            snapshot,
            currentnessObservation,
            validationTime,
            maxCurrentnessAgeMs,
          )) {
        const at = new Date(validationTime).toISOString();
        releaseReservedForRefusal(key, stored, 'currentness_refused', at);
        return { ok: false, reason: 'currentness_refused' };
      }
      const invocationToken = invocationFactory();
      if (typeof invocationToken !== 'string' || invocationToken.length < 48) {
        fail('invalid_invocation_token', 'invocation token is invalid');
      }
      const at = new Date(validationTime).toISOString();
      if (programAware) {
        const programRefusal = consumeExecutionProgramOccurrenceForAdmission(key, at);
        if (programRefusal !== null) {
          return { ok: false, reason: programRefusal as AdmissionRefusalReason };
        }
      }
      const record = append(key, stored.ownerToken, next(stored.record, at, {
        state: 'INVOKING', execution_right: 'CONSUMED', provider_attempt: 'INVOKING',
        invocation_token_digest: tokenDigest(invocationToken), invocation_started_at: at,
        resources: stored.record.resources.map((resource) => ({ ...resource, state: 'CONSUMED' })),
      }), 'INVOKING', at);
      return { ok: true, snapshot, record, invocation_token: invocationToken };
    });
  }

  function invariantViolations(): string[] {
    const violations: string[] = [];
    for (const [key, stored] of records) {
      const record = stored.record;
      const history = journals.get(key) ?? [];
      if (!snapshots.has(record.snapshot_digest)) violations.push(`${key}:snapshot_missing`);
      if (!verifyAdmissionJournal(history).ok) violations.push(`${key}:journal_invalid`);
      if (history.length !== record.revision + 1 || history.at(-1)?.record_digest !== record.record_digest) violations.push(`${key}:head_mismatch`);
      if (record.state === 'RESERVED' && (record.execution_right !== 'RESERVED' || record.provider_attempt !== 'NOT_ENTERED')) violations.push(`${key}:reserved_invalid`);
      const snapshot = snapshots.get(record.snapshot_digest);
      if (record.state === 'RESERVED'
          && snapshot
          && Date.parse(snapshot.body.expires_at) <= currentMs(options.now)) {
        violations.push(`${key}:reserved_past_expiry`);
      }
      for (const resource of record.resources) {
        if (resource.kind === 'monotonic_counter') {
          const head = monotonicCounterHeads.get(resourceKey(record.tenant_id, resource));
          if (head === undefined || head < resource.next_value!) {
            violations.push(`${key}:monotonic_counter_head_invalid`);
          }
        }
      }
      if (['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(record.state)
          && (record.execution_right !== 'CONSUMED' || record.resources.some((resource) => resource.state !== 'CONSUMED'))) violations.push(`${key}:consumption_invalid`);
      if (record.state === 'SUPERSEDED') {
        if (record.superseded_by_admission_id === null) {
          violations.push(`${key}:supersession_missing`);
        } else {
          const predecessorSnapshot = snapshots.get(record.snapshot_digest);
          const successorKey = admissionKey(record.tenant_id, record.superseded_by_admission_id);
          const successor = records.get(successorKey);
          const successorSnapshot = successor
            ? snapshots.get(successor.record.snapshot_digest)
            : undefined;
          if (!successor
              || !predecessorSnapshot
              || !successorSnapshot
              || successorSnapshot.body.supersedes_admission_id !== record.admission_id
              || !exactOperationIdentity(predecessorSnapshot.body, successorSnapshot.body)) {
            violations.push(`${key}:supersession_target_invalid`);
          }
          const operationHead = operationHeads.get(operationKey(record.tenant_id, record.operation_id));
          if (operationHead !== successorKey) {
            violations.push(`${key}:supersession_head_invalid`);
          }
        }
      }
    }
    for (const [op, admission] of operationHeads) {
      const stored = records.get(admission);
      if (!stored || operationKey(stored.record.tenant_id, stored.record.operation_id) !== op) violations.push(`${op}:operation_head_invalid`);
    }
    for (const [key, programState] of executionPrograms) {
      const expected = new Map(programState.budgets.map((budget) => [
        budget.budget_id,
        { reserved: 0, consumed: 0 },
      ]));
      const expectedNodeCounts = new Map<string, number>();
      const expectedTerminalCounts = new Map<string, number>();
      let expectedTotalOccurrences = 0;
      let expectedOpenEffects = 0;
      for (const occurrence of executionProgramOccurrences.values()) {
        if (occurrence.tenant_id !== programState.tenant_id
            || occurrence.program_digest !== programState.program_digest) continue;
        expectedTotalOccurrences += 1;
        if (occurrence.state === 'INVOKING' || occurrence.state === 'INDETERMINATE') {
          expectedOpenEffects += 1;
        }
        if (occurrence.state !== 'RELEASED') {
          const countKey = executionProgramNodeCountKey(
            occurrence.tenant_id,
            occurrence.program_digest,
            occurrence.node_id,
          );
          expectedNodeCounts.set(countKey, (expectedNodeCounts.get(countKey) ?? 0) + 1);
        }
        if (occurrence.state === 'COMMITTED' || occurrence.state === 'PROVEN_NOT_COMMITTED') {
          const terminalKey = executionProgramTerminalCountKey(
            occurrence.tenant_id,
            occurrence.program_digest,
            occurrence.node_id,
            occurrence.state,
          );
          expectedTerminalCounts.set(
            terminalKey,
            (expectedTerminalCounts.get(terminalKey) ?? 0) + 1,
          );
        }
        for (const charge of occurrence.charges) {
          const aggregate = expected.get(charge.budget_id);
          if (!aggregate) {
            violations.push(`${key}:occurrence_budget_unknown`);
            continue;
          }
          if (occurrence.state === 'RESERVED') aggregate.reserved += charge.amount;
          if (['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(occurrence.state)) {
            aggregate.consumed += charge.amount;
          }
        }
        const admission = records.get(admissionKey(occurrence.tenant_id, occurrence.admission_id));
        if (!admission || admission.record.snapshot_digest !== occurrence.snapshot_digest) {
          violations.push(`${key}:occurrence_admission_missing`);
        } else if ((admission.record.state === 'EXPIRED' ? 'RELEASED' : admission.record.state)
            !== occurrence.state) {
          violations.push(`${key}:occurrence_admission_state_mismatch`);
        }
      }
      for (const budget of programState.budgets) {
        const aggregate = expected.get(budget.budget_id)!;
        if (budget.reserved !== aggregate.reserved
            || budget.consumed !== aggregate.consumed
            || budget.reserved + budget.consumed > budget.limit) {
          violations.push(`${key}:program_budget_mismatch:${budget.budget_id}`);
        }
      }
      if (programState.total_occurrences !== expectedTotalOccurrences
          || programState.total_occurrences > programState.program.max_total_occurrences) {
        violations.push(`${key}:program_total_occurrence_mismatch`);
      }
      if (expectedOpenEffects > programState.program.max_concurrent_effects) {
        violations.push(`${key}:program_concurrent_effect_limit_exceeded`);
      }
      for (const node of programState.program.nodes) {
        const countKey = executionProgramNodeCountKey(
          programState.tenant_id,
          programState.program_digest,
          node.node_id,
        );
        if ((executionProgramNodeOccurrenceCounts.get(countKey) ?? 0)
            !== (expectedNodeCounts.get(countKey) ?? 0)) {
          violations.push(`${key}:program_node_count_mismatch:${node.node_id}`);
        }
        for (const outcome of ['COMMITTED', 'PROVEN_NOT_COMMITTED'] as const) {
          const terminalKey = executionProgramTerminalCountKey(
            programState.tenant_id,
            programState.program_digest,
            node.node_id,
            outcome,
          );
          if ((executionProgramTerminalOutcomeCounts.get(terminalKey) ?? 0)
              !== (expectedTerminalCounts.get(terminalKey) ?? 0)) {
            violations.push(`${key}:program_terminal_count_mismatch:${node.node_id}:${outcome}`);
          }
        }
      }
      const head = executionProgramHeads.get(executionProgramHeadKey(
        programState.tenant_id,
        programState.program_id,
      ));
      if (programState.status === 'ACTIVE' && head !== programState.program_digest) {
        violations.push(`${key}:program_head_mismatch`);
      }
    }
    return violations;
  }

  const store: ExecutionProgramAdmissionStore & { readonly testOnly: true } = {
    testOnly: true,
    durable: false,
    atomic: true,
    compareAndSwap: true,
    appendOnlyJournal: true,
    exclusiveActuation: true,
    transactionalCurrentness: true,

    reserve(raw) {
      return atomic(() => reserveCore(raw));
    },

    release(input, reason = 'released_before_invocation') {
      return atomic(() => releaseCore(input, reason, false));
    },

    expire(input) {
      return atomic(() => expireCore(input, false));
    },

    reapExpiredReservation(input) {
      return atomic(() => {
        const tenantId = identifier(input.tenant_id, 'tenant_id');
        const admissionId = identifier(input.admission_id, 'admission_id');
        const expectedRevision = nonNegativeInteger(input.expected_revision, 'expected_revision');
        const key = admissionKey(tenantId, admissionId);
        const stored = records.get(key);
        if (!stored) return { ok: false, reason: 'admission_not_found' };
        if (stored.record.revision !== expectedRevision) {
          return { ok: false, reason: 'revision_conflict' };
        }
        if (stored.record.state !== 'RESERVED'
            || stored.record.execution_right !== 'RESERVED'
            || stored.record.provider_attempt !== 'NOT_ENTERED') {
          return { ok: false, reason: 'state_conflict' };
        }
        const snapshot = snapshots.get(stored.record.snapshot_digest)!;
        const now = currentMs(options.now);
        if (Date.parse(snapshot.body.expires_at) > now) {
          return { ok: false, reason: 'state_conflict' };
        }
        const at = new Date(now).toISOString();
        freeResources(stored.record, key);
        const record = append(key, stored.ownerToken, next(stored.record, at, {
          state: 'EXPIRED',
          execution_right: 'RELEASED',
          refusal_reason: 'abandoned_before_invocation',
          resources: stored.record.resources.map((resource) => ({
            ...resource,
            state: 'RELEASED',
          })),
        }), 'ABANDONED_BEFORE_INVOCATION', at);
        return { ok: true, record };
      });
    },

    supersede(input) {
      return atomic(() => {
        const selected = selectCas(input);
        if ('ok' in selected) return selected;
        const { key, stored } = selected;
        if (executionProgramAdmissions.has(key)) return { ok: false, reason: 'program_required' };
        if (stored.record.state !== 'RESERVED' || stored.record.execution_right !== 'RESERVED') return { ok: false, reason: 'state_conflict' };
        const predecessor = snapshots.get(stored.record.snapshot_digest)!;
        const successor = createAdmissionSnapshot({ ...input.successor, supersedes_admission_id: stored.record.admission_id, remedy_for: null });
        if (successor.body.admission_id === stored.record.admission_id || !exactOperationIdentity(predecessor.body, successor.body)) return { ok: false, reason: 'operation_conflict' };
        const successorKey = admissionKey(successor.body.tenant_id, successor.body.admission_id);
        if (records.has(successorKey)) return { ok: false, reason: 'admission_exists' };
        const now = currentMs(options.now);
        if (Date.parse(successor.body.expires_at) <= now) return { ok: false, reason: 'admission_expired' };
        if (!resourcesAvailable(successor, key)) return { ok: false, reason: 'resource_conflict' };
        const owner = validateOwner(ownerFactory());
        const at = new Date(now).toISOString();
        freeResources(stored.record, key);
        const predecessorRecord = append(key, stored.ownerToken, next(stored.record, at, {
          state: 'SUPERSEDED', execution_right: 'RELEASED', superseded_by_admission_id: successor.body.admission_id,
          resources: stored.record.resources.map((resource) => ({ ...resource, state: 'RELEASED' })),
        }), 'SUPERSEDED', at);
        snapshots.set(successor.snapshot_digest, successor);
        claimResources(successor, successorKey);
        operationHeads.set(operationKey(successor.body.tenant_id, successor.body.operation_id), successorKey);
        const successorRecord = append(successorKey, owner, {
          '@version': ADMISSION_RECORD_VERSION,
          tenant_id: successor.body.tenant_id,
          admission_id: successor.body.admission_id,
          operation_id: successor.body.operation_id,
          snapshot_digest: successor.snapshot_digest,
          revision: 0,
          state: 'RESERVED', execution_right: 'RESERVED', provider_attempt: 'NOT_ENTERED',
          owner_digest: tokenDigest(owner), invocation_token_digest: null,
          provider_outcome: null, effect_relation: null,
          resources: successor.body.resource_reservations.map((resource) => ({ ...resource, state: 'RESERVED' })),
          superseded_by_admission_id: null, refusal_reason: null, invocation_started_at: null,
          created_at: at, updated_at: at, predecessor_record_digest: null,
        }, 'RESERVED', at);
        return { ok: true, predecessor_record: predecessorRecord, successor_snapshot: successor, successor_record: successorRecord, successor_owner_token: owner };
      });
    },

    beginInvocation(input) {
      return beginInvocationCore(input, false);
    },

    recoverIndeterminate(input) {
      return atomic(() => {
        const key = admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'));
        const stored = records.get(key);
        if (!stored) return { ok: false, reason: 'admission_not_found' };
        if (stored.ownerToken !== validateOwner(input.owner_token)) return { ok: false, reason: 'owner_conflict' };
        if (stored.record.state !== 'INVOKING') return { ok: false, reason: 'state_conflict' };
        const reconciliationToken = invocationFactory();
        if (typeof reconciliationToken !== 'string' || reconciliationToken.length < 48) fail('invalid_invocation_token', 'reconciliation token is invalid');
        const at = new Date(currentMs(options.now)).toISOString();
        const record = append(key, stored.ownerToken, next(stored.record, at, {
          state: 'INDETERMINATE', provider_attempt: 'INDETERMINATE',
          invocation_token_digest: tokenDigest(reconciliationToken),
          provider_outcome: { value: 'INDETERMINATE', evidence_digest: null, observed_at: at },
          refusal_reason: 'ambiguous_provider_entry',
        }), 'RECOVERED_INDETERMINATE', at);
        updateExecutionProgramOccurrenceForAdmission(key, 'INDETERMINATE', at);
        return { ok: true, record, reconciliation_token: reconciliationToken };
      });
    },

    recordProviderOutcome(input) {
      return atomic(() => {
        const selected = selectCas(input);
        if ('ok' in selected) return selected;
        const { key, stored } = selected;
        if (stored.record.execution_right !== 'CONSUMED' || stored.record.invocation_token_digest !== tokenDigest(input.invocation_token)) return { ok: false, reason: 'invocation_token_conflict' };
        if (!['INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED'].includes(stored.record.state)) return { ok: false, reason: 'state_conflict' };
        if (!['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(input.value)) fail('invalid_provider_outcome', 'provider outcome is invalid');
        const observed = instant(input.observed_at, 'observed_at').iso;
        const evidence = input.evidence_digest === null ? null : digest(input.evidence_digest, 'evidence_digest');
        if (input.value !== 'INDETERMINATE' && evidence === null) return { ok: false, reason: 'evidence_required' };
        const current = stored.record.provider_outcome;
        if (current && current.value !== 'INDETERMINATE' && (current.value !== input.value || current.evidence_digest !== evidence)) return { ok: false, reason: 'outcome_conflict' };
        const at = new Date(currentMs(options.now)).toISOString();
        const record = append(key, stored.ownerToken, next(stored.record, at, {
          state: input.value,
          provider_attempt: input.value,
          provider_outcome: { value: input.value, evidence_digest: evidence, observed_at: observed },
        }), 'PROVIDER_OUTCOME', at);
        updateExecutionProgramOccurrenceForAdmission(key, input.value, at);
        return { ok: true, record };
      });
    },

    recordEffectRelation(input) {
      return atomic(() => {
        const selected = selectCas(input);
        if ('ok' in selected) return selected;
        const { key, stored } = selected;
        if (stored.record.execution_right !== 'CONSUMED' || stored.record.invocation_token_digest !== tokenDigest(input.invocation_token)) return { ok: false, reason: 'invocation_token_conflict' };
        if (!['OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE'].includes(input.value)) fail('invalid_effect_relation', 'effect relation is invalid');
        const observed = instant(input.observed_at, 'observed_at').iso;
        const evidence = input.evidence_digest === null ? null : digest(input.evidence_digest, 'evidence_digest');
        if (input.value !== 'INDETERMINATE' && evidence === null) return { ok: false, reason: 'evidence_required' };
        const current = stored.record.effect_relation;
        if (current && current.value !== 'INDETERMINATE' && (current.value !== input.value || current.evidence_digest !== evidence)) return { ok: false, reason: 'outcome_conflict' };
        const at = new Date(currentMs(options.now)).toISOString();
        const record = append(key, stored.ownerToken, next(stored.record, at, {
          effect_relation: { value: input.value, evidence_digest: evidence, observed_at: observed },
        }), 'EFFECT_RELATION', at);
        return { ok: true, record };
      });
    },

    registerExecutionProgram(artifact, context) {
      return atomic(() => {
        if (!executionProgramStatusOracle
            || typeof executionProgramStatusOracle.read !== 'function') {
          return { ok: false, reason: 'program_status_indeterminate' };
        }
        const normalizedContext = executionProgramRegistrationContext(context);
        if (!normalizedContext) return { ok: false, reason: 'context_binding_required' };
        const keyId = plain(artifact) && plain(artifact.issuer)
          && typeof artifact.issuer.key_id === 'string'
          ? artifact.issuer.key_id : '';
        const expectedAuthorizer = programTrust.activeAuthorizers.get(keyId) ?? '';
        const verified = verifyBoundedExecutionProgram(artifact, {
          ...normalizedContext,
          expected_authorizer_id: expectedAuthorizer,
          trusted_keys: programTrust.trustedKeys,
          now: currentMs(options.now),
        });
        if (!verified.accepted || !verified.program || !verified.program_digest) {
          return { ok: false, reason: verified.reason as ExecutionProgramRefusalReason };
        }
        const program = verified.program;
        if (program.version !== 1 || program.supersedes_program_digest !== null) {
          return { ok: false, reason: 'program_supersession_invalid' };
        }
        const key = executionProgramKey(program.tenant_id, verified.program_digest);
        const headKey = executionProgramHeadKey(program.tenant_id, program.program_id);
        const authorizationKey = executionProgramAuthorizationKey(
          program.tenant_id,
          program.authorization_digest,
        );
        if (executionPrograms.has(key) || executionProgramHeads.has(headKey)) {
          return { ok: false, reason: 'program_exists' };
        }
        if (executionProgramAuthorizationOwners.has(authorizationKey)) {
          return { ok: false, reason: 'program_binding_mismatch' };
        }
        const existingUnconsumedAuthorization = [...records.values()].some(({ record }) => {
          if (record.tenant_id !== program.tenant_id || record.execution_right !== 'RESERVED') return false;
          const snapshot = snapshots.get(record.snapshot_digest);
          return snapshot?.body.inputs.some((entry) => (
            entry.role === 'authorization'
            && entry.payload_digest === program.authorization_digest
          )) ?? false;
        });
        if (existingUnconsumedAuthorization) {
          return { ok: false, reason: 'program_binding_mismatch' };
        }
        const state: MutableExecutionProgramState = {
          '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
          tenant_id: program.tenant_id,
          program_id: program.program_id,
          program_digest: verified.program_digest,
          version: program.version,
          status: 'ACTIVE',
          status_sequence: 0,
          status_observed_at: new Date(currentMs(options.now)).toISOString(),
          status_expires_at: program.expires_at,
          authorizer_id: verified.authorizer_id,
          registered_at: new Date(currentMs(options.now)).toISOString(),
          superseded_by_program_digest: null,
          total_occurrences: 0,
          budgets: program.budgets.map((budget) => ({
            budget_id: budget.budget_id,
            unit: budget.unit,
            limit: budget.limit,
            reserved: 0,
            consumed: 0,
          })),
          program,
        };
        executionPrograms.set(key, state);
        executionProgramHeads.set(headKey, verified.program_digest);
        executionProgramAuthorizationOwners.set(authorizationKey, verified.program_digest);
        return { ok: true, program: publicExecutionProgram(state) };
      });
    },

    reserveExecutionProgramAdmission(input) {
      const programDigest = digest(input.program_digest, 'program_digest');
      const occurrenceId = identifier(input.occurrence_id, 'occurrence_id');
      const nodeId = identifier(input.node_id, 'node_id');
      const initialSnapshot = plain(input.admission) && Object.hasOwn(input.admission, 'snapshot_digest')
        ? validateSnapshot(input.admission as AdmissionSnapshot)
        : createAdmissionSnapshot(input.admission as AdmissionSnapshotInput);
      return (async () => {
        const prepared = await atomic(() => {
          const state = executionPrograms.get(executionProgramKey(
            initialSnapshot.body.tenant_id,
            programDigest,
          ));
          if (!state) {
            return {
              ready: false as const,
              result: { ok: false as const, reason: 'program_not_found' as const },
            };
          }
          const node = findProgramNode(state, nodeId);
          if (!node) {
            return {
              ready: false as const,
              result: { ok: false as const, reason: 'program_binding_mismatch' as const },
            };
          }
          return {
            ready: true as const,
            state: publicExecutionProgram(state),
            node: frozenCopy(node),
          };
        });
        if (!prepared.ready) return prepared.result;
        const [statusObservation, actionMatches] = await Promise.all([
          readExecutionProgramStatus(prepared.state),
          executionProgramActionMatches(
            prepared.state,
            prepared.node.action,
            initialSnapshot,
            input.action_match_evidence,
          ),
        ]);
        const validationTime = currentMs(options.now);

        return atomic(() => {
          const state = executionPrograms.get(executionProgramKey(
            initialSnapshot.body.tenant_id,
            programDigest,
          ));
          if (!state) return { ok: false, reason: 'program_not_found' };
          const statusRefusal = applyExecutionProgramStatus(
            state,
            statusObservation,
            validationTime,
          );
          if (statusRefusal) return { ok: false, reason: statusRefusal };
          const node = findProgramNode(state, nodeId);
          if (!node) return { ok: false, reason: 'program_binding_mismatch' };
        const candidate = initialSnapshot.body.inputs.find((entry) => entry.role === 'candidate_manifest');
        const authorization = initialSnapshot.body.inputs.find((entry) => entry.role === 'authorization');
        if (candidate?.subject !== state.program.subject_id
            || authorization?.payload_digest !== state.program.authorization_digest
            || initialSnapshot.body.authorization_policy_digest !== node.trust_program_digest
            || !actionMatches) {
          return { ok: false, reason: 'program_binding_mismatch' };
        }
        if (Date.parse(initialSnapshot.body.expires_at) > Date.parse(state.program.expires_at)) {
          return { ok: false, reason: 'program_expiration_mismatch' };
        }
        const programBinding = createExecutionProgramAdmissionBinding({
          tenant_id: initialSnapshot.body.tenant_id,
          program_digest: state.program_digest,
          node_id: node.node_id,
          occurrence_id: occurrenceId,
          expires_at: initialSnapshot.body.expires_at,
        });
        const existingBindings = initialSnapshot.body.resource_reservations.filter(
          (resource) => resource.kind === 'execution_program',
        );
        if (existingBindings.length > 1
            || (existingBindings.length === 1
              && canonical(existingBindings[0] as unknown as Json)
                !== canonical(programBinding as unknown as Json))) {
          return { ok: false, reason: 'program_binding_mismatch' };
        }
        let snapshot = initialSnapshot;
        if (existingBindings.length === 0) {
          if (plain(input.admission) && Object.hasOwn(input.admission, 'snapshot_digest')) {
            return { ok: false, reason: 'program_binding_mismatch' };
          }
          const { '@version': _version, ...body } = initialSnapshot.body;
          snapshot = createAdmissionSnapshot({
            ...body,
            resource_reservations: [
              ...initialSnapshot.body.resource_reservations,
              programBinding,
            ],
          });
        }
        const occurrenceKey = executionProgramOccurrenceKey(
          state.tenant_id,
          state.program_digest,
          occurrenceId,
        );
        if (executionProgramOccurrences.has(occurrenceKey)) {
          return { ok: false, reason: 'program_occurrence_conflict' };
        }
        if (state.total_occurrences >= state.program.max_total_occurrences) {
          return { ok: false, reason: 'program_total_occurrence_exhausted' };
        }
        const nodeCountKey = executionProgramNodeCountKey(
          state.tenant_id,
          state.program_digest,
          node.node_id,
        );
        const occurrenceCount = executionProgramNodeOccurrenceCounts.get(nodeCountKey) ?? 0;
        if (occurrenceCount >= node.max_occurrences) {
          return { ok: false, reason: 'program_occurrence_exhausted' };
        }
        if (!executionProgramDependenciesSatisfied(state, node)) {
          return { ok: false, reason: 'program_node_unreachable' };
        }
        for (const charge of node.charges) {
          const budget = state.budgets.find((entry) => entry.budget_id === charge.budget_id);
          if (!budget || budget.reserved + budget.consumed + charge.amount > budget.limit) {
            return { ok: false, reason: 'program_budget_exhausted' };
          }
        }
        const reserved = reserveCore(snapshot, true);
        if (!reserved.ok) return reserved;
        const at = new Date(validationTime).toISOString();
        for (const charge of node.charges) {
          state.budgets.find((entry) => entry.budget_id === charge.budget_id)!.reserved += charge.amount;
        }
        const occurrence: MutableExecutionProgramOccurrence = {
          tenant_id: state.tenant_id,
          program_digest: state.program_digest,
          node_id: node.node_id,
          occurrence_id: occurrenceId,
          admission_id: reserved.snapshot.body.admission_id,
          snapshot_digest: reserved.snapshot.snapshot_digest,
          state: 'RESERVED',
          charges: node.charges.map((charge) => ({ ...charge })),
          created_at: at,
          updated_at: at,
        };
        executionProgramOccurrences.set(occurrenceKey, occurrence);
        state.total_occurrences += 1;
        incrementIndex(executionProgramNodeOccurrenceCounts, nodeCountKey, 1);
        executionProgramAdmissions.set(admissionKey(
          reserved.snapshot.body.tenant_id,
          reserved.snapshot.body.admission_id,
        ), occurrenceKey);
        return reserved;
      });
      })();
    },

    beginExecutionProgramInvocation(input) {
      return beginInvocationCore(input, true);
    },

    releaseExecutionProgramAdmission(input, reason = 'program_released_before_invocation') {
      return atomic(() => releaseCore(input, reason, true));
    },

    expireExecutionProgramAdmission(input) {
      return atomic(() => expireCore(input, true));
    },

    supersedeExecutionProgram(artifact, context) {
      return atomic(() => {
        const normalizedContext = executionProgramRegistrationContext(context);
        if (!normalizedContext) return { ok: false, reason: 'context_binding_required' };
        const keyId = plain(artifact) && plain(artifact.issuer)
          && typeof artifact.issuer.key_id === 'string'
          ? artifact.issuer.key_id : '';
        const expectedAuthorizer = programTrust.activeAuthorizers.get(keyId) ?? '';
        const verified = verifyBoundedExecutionProgram(artifact, {
          ...normalizedContext,
          expected_authorizer_id: expectedAuthorizer,
          trusted_keys: programTrust.trustedKeys,
          now: currentMs(options.now),
        });
        if (!verified.accepted || !verified.program || !verified.program_digest) {
          return { ok: false, reason: verified.reason as ExecutionProgramRefusalReason };
        }
        const successor = verified.program;
        if (successor.version < 2 || successor.supersedes_program_digest === null) {
          return { ok: false, reason: 'program_supersession_invalid' };
        }
        const predecessor = executionPrograms.get(executionProgramKey(
          successor.tenant_id,
          successor.supersedes_program_digest,
        ));
        if (!predecessor) return { ok: false, reason: 'program_not_found' };
        const headKey = executionProgramHeadKey(successor.tenant_id, successor.program_id);
        if (predecessor.status !== 'ACTIVE'
            || executionProgramHeads.get(headKey) !== predecessor.program_digest
            || predecessor.program_id !== successor.program_id
            || predecessor.version + 1 !== successor.version
            || predecessor.authorizer_id !== verified.authorizer_id
            || predecessor.program.subject_id !== successor.subject_id
            || predecessor.program.audience !== successor.audience
            || predecessor.program.objective_digest !== successor.objective_digest
            || predecessor.program.presentation_digest !== successor.presentation_digest
            || predecessor.program.authorization_digest === successor.authorization_digest) {
          return { ok: false, reason: 'program_supersession_invalid' };
        }
        const hasReserved = [...executionProgramOccurrences.values()].some((occurrence) => (
          occurrence.tenant_id === predecessor.tenant_id
          && occurrence.program_digest === predecessor.program_digest
          && occurrence.state === 'RESERVED'
        ));
        if (hasReserved) return { ok: false, reason: 'program_reserved_work_exists' };
        const successorKey = executionProgramKey(successor.tenant_id, verified.program_digest);
        if (executionPrograms.has(successorKey)) return { ok: false, reason: 'program_exists' };
        const authorizationKey = executionProgramAuthorizationKey(
          successor.tenant_id,
          successor.authorization_digest,
        );
        const authorizationOwner = executionProgramAuthorizationOwners.get(authorizationKey);
        if (authorizationOwner !== undefined) {
          return { ok: false, reason: 'program_binding_mismatch' };
        }
        const nextState: MutableExecutionProgramState = {
          '@version': EXECUTION_PROGRAM_RUNTIME_VERSION,
          tenant_id: successor.tenant_id,
          program_id: successor.program_id,
          program_digest: verified.program_digest,
          version: successor.version,
          status: 'ACTIVE',
          status_sequence: 0,
          status_observed_at: new Date(currentMs(options.now)).toISOString(),
          status_expires_at: successor.expires_at,
          authorizer_id: verified.authorizer_id,
          registered_at: new Date(currentMs(options.now)).toISOString(),
          superseded_by_program_digest: null,
          total_occurrences: 0,
          budgets: successor.budgets.map((budget) => ({
            budget_id: budget.budget_id,
            unit: budget.unit,
            limit: budget.limit,
            reserved: 0,
            consumed: 0,
          })),
          program: successor,
        };
        predecessor.status = 'SUPERSEDED';
        predecessor.status_sequence += 1;
        predecessor.status_observed_at = new Date(currentMs(options.now)).toISOString();
        predecessor.status_expires_at = predecessor.program.expires_at;
        predecessor.superseded_by_program_digest = verified.program_digest;
        executionPrograms.set(successorKey, nextState);
        executionProgramHeads.set(headKey, verified.program_digest);
        executionProgramAuthorizationOwners.set(authorizationKey, verified.program_digest);
        return { ok: true, program: publicExecutionProgram(nextState) };
      });
    },

    readExecutionProgram(input) {
      return atomic(() => {
        const tenantId = identifier(input.tenant_id, 'tenant_id');
        const programDigest = digest(input.program_digest, 'program_digest');
        const state = executionPrograms.get(executionProgramKey(tenantId, programDigest));
        return state ? publicExecutionProgram(state) : null;
      });
    },

    readExecutionProgramReportSnapshot(input) {
      return atomic(() => {
        const tenantId = identifier(input.tenant_id, 'tenant_id');
        const programDigest = digest(input.program_digest, 'program_digest');
        const state = executionPrograms.get(executionProgramKey(tenantId, programDigest));
        if (!state) return null;
        const occurrences = [...executionProgramOccurrences.values()]
          .filter((occurrence) => (
            occurrence.tenant_id === tenantId
            && occurrence.program_digest === programDigest
          ))
          .sort((left, right) => (
            Buffer.compare(Buffer.from(left.node_id, 'utf8'), Buffer.from(right.node_id, 'utf8'))
              || Buffer.compare(
                Buffer.from(left.occurrence_id, 'utf8'),
                Buffer.from(right.occurrence_id, 'utf8'),
              )
          ));
        if (occurrences.length !== state.total_occurrences
            || occurrences.length > state.program.max_total_occurrences) {
          throw new Error('execution program invariant: report snapshot occurrence bound violated');
        }
        const body: ExecutionProgramReportSnapshotBody = {
          '@version': EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
          tenant_id: tenantId,
          program_digest: programDigest,
          runtime_state: publicExecutionProgram(state),
          occurrences: occurrences.map((occurrence) => frozenCopy(occurrence)),
        };
        return frozenCopy({
          ...body,
          snapshot_marker: executionProgramReportSnapshotMarker(body),
        });
      });
    },

    readExecutionProgramOccurrence(input) {
      return atomic(() => {
        const tenantId = identifier(input.tenant_id, 'tenant_id');
        const programDigest = digest(input.program_digest, 'program_digest');
        const occurrenceId = identifier(input.occurrence_id, 'occurrence_id');
        const occurrence = executionProgramOccurrences.get(executionProgramOccurrenceKey(
          tenantId,
          programDigest,
          occurrenceId,
        ));
        return occurrence ? frozenCopy(occurrence) : null;
      });
    },

    read(input) {
      return atomic(() => records.get(admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id')))?.record ?? null);
    },
    readByOperation(input) {
      return atomic(() => {
        const head = operationHeads.get(operationKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.operation_id, 'operation_id')));
        return head ? records.get(head)?.record ?? null : null;
      });
    },
    readSnapshot(raw) { return atomic(() => snapshots.get(digest(raw, 'snapshot_digest')) ?? null); },
    journal(input) {
      return atomic(() => journals.get(admissionKey(identifier(input.tenant_id, 'tenant_id'), identifier(input.admission_id, 'admission_id'))) ?? []);
    },
    checkInvariants() {
      return atomic(() => {
        const violations = invariantViolations();
        return { ok: violations.length === 0, violations };
      });
    },
  };
  return store;
}

export default createMemoryAdmissionStore;
