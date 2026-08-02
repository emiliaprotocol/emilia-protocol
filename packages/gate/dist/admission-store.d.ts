/**
 * Gate Qualification v2 admission custody.
 *
 * The immutable snapshot is the complete input to one consequential operation.
 * Mutable lifecycle state lives in a separately CAS-owned record and every
 * accepted transition is chained into an append-only journal.  The in-memory
 * implementation is a linearizable reference for conformance and crash-model
 * tests; it is deliberately not a durability claim.
 */
import { type ExecutionProgramCharge, type VerifiedBoundedExecutionProgram } from './bounded-execution-program.js';
export declare const ADMISSION_SNAPSHOT_VERSION = "EP-GATE-ADMISSION-SNAPSHOT-v2";
export declare const ADMISSION_RECORD_VERSION = "EP-GATE-ADMISSION-RECORD-v2";
export declare const ADMISSION_JOURNAL_VERSION = "EP-GATE-ADMISSION-JOURNAL-v2";
export declare const ADMISSION_CURRENTNESS_VERSION = "EP-GATE-ADMISSION-CURRENTNESS-v2";
export declare const EXECUTION_PROGRAM_RUNTIME_VERSION = "EP-BOUNDED-EXECUTION-PROGRAM-RUNTIME-v1";
export declare const EXECUTION_PROGRAM_ADMISSION_BINDING_VERSION = "EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1";
export declare const EXECUTION_PROGRAM_STATUS_VERSION = "EP-BOUNDED-EXECUTION-PROGRAM-STATUS-v1";
export declare const EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION = "EP-BOUNDED-EXECUTION-PROGRAM-REPORT-SNAPSHOT-v1";
export declare const ADMISSION_LIMITS: Readonly<{
    inputs: 128;
    resources: 64;
    testResults: 64;
    agentEvidence: 32;
    identifierBytes: 512;
    currentnessMaxAgeMs: 5000;
}>;
export type AdmissionDigest = `sha256:${string}`;
export type AdmissionInputRole = 'candidate_manifest' | 'runtime_measurement' | 'test_result' | 'agent_evaluation_evidence' | 'qualification_statement' | 'qualification_status' | 'aeb' | 'aec' | 'local_policy' | 'authorization';
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
export type AdmissionResourceKind = 'replay' | 'capability' | 'budget' | 'qualification_use' | 'provider_operation' | 'external_lease' | 'monotonic_counter' | 'execution_program';
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
export interface AdmissionSnapshotBody extends Omit<AdmissionSnapshotInput, 'supersedes_admission_id' | 'remedy_for'> {
    '@version': typeof ADMISSION_SNAPSHOT_VERSION;
    supersedes_admission_id: string | null;
    remedy_for: Readonly<AdmissionRelation> | null;
}
export interface AdmissionSnapshot {
    body: Readonly<AdmissionSnapshotBody>;
    snapshot_digest: AdmissionDigest;
}
export type AdmissionState = 'RESERVED' | 'RELEASED' | 'EXPIRED' | 'SUPERSEDED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
export type AdmissionExecutionRight = 'RESERVED' | 'RELEASED' | 'CONSUMED';
export type AdmissionProviderAttempt = 'NOT_ENTERED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
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
export type AdmissionJournalEvent = 'RESERVED' | 'RELEASED' | 'EXPIRED' | 'ABANDONED_BEFORE_INVOCATION' | 'SUPERSEDED' | 'INVOKING' | 'RECOVERED_INDETERMINATE' | 'PROVIDER_OUTCOME' | 'EFFECT_RELATION';
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
export type AdmissionRefusalReason = 'admission_exists' | 'admission_not_found' | 'operation_exists' | 'operation_conflict' | 'revision_conflict' | 'owner_conflict' | 'resource_conflict' | 'admission_expired' | 'currentness_refused' | 'execution_right_consumed' | 'state_conflict' | 'relation_not_found' | 'relation_conflict' | 'outcome_conflict' | 'evidence_required' | 'invocation_token_conflict' | 'program_required' | 'program_not_found' | 'program_not_active' | 'program_expired' | 'program_suspended' | 'program_revoked' | 'program_status_indeterminate' | 'program_superseded' | 'program_budget_exhausted' | 'program_concurrency_exhausted';
export type AdmissionRefusal = {
    ok: false;
    reason: AdmissionRefusalReason;
};
export type AdmissionTransitionResult = {
    ok: true;
    record: Readonly<AdmissionRecord>;
} | AdmissionRefusal;
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
export interface AdmissionInvariantCheck {
    ok: boolean;
    violations: readonly string[];
}
export type ExecutionProgramRuntimeStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'SUPERSEDED';
export type ExecutionProgramAuthorizerKeyStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export type ExecutionProgramCurrentStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
export type ExecutionProgramOccurrenceState = 'RESERVED' | 'RELEASED' | 'INVOKING' | 'INDETERMINATE' | 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
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
    read(reference: Readonly<ExecutionProgramStatusReference>): Promise<ExecutionProgramStatusObservation | null>;
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
export interface ExecutionProgramActionMatchVerification extends ExecutionProgramActionMatchExpected {
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
export type ExecutionProgramRefusalReason = AdmissionRefusalReason | 'program_exists' | 'program_not_found' | 'program_inactive' | 'program_superseded' | 'program_binding_mismatch' | 'program_node_unreachable' | 'program_occurrence_exhausted' | 'program_total_occurrence_exhausted' | 'program_occurrence_conflict' | 'program_budget_exhausted' | 'program_concurrency_exhausted' | 'program_expiration_mismatch' | 'program_suspended' | 'program_revoked' | 'program_status_indeterminate' | 'program_reserved_work_exists' | 'program_supersession_invalid' | 'program_signature_invalid' | 'program_issuer_untrusted' | 'program_schema_invalid' | 'context_binding_required' | 'authorizer_mismatch' | 'program_id_mismatch' | 'tenant_mismatch' | 'authorization_mismatch' | 'audience_mismatch' | 'verification_time_invalid' | 'program_not_active' | 'program_expired';
export type ExecutionProgramRegistrationResult = {
    ok: true;
    program: Readonly<ExecutionProgramRuntimeState>;
} | {
    ok: false;
    reason: ExecutionProgramRefusalReason;
};
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
    registerExecutionProgram(artifact: unknown, context: ExecutionProgramRegistrationContext): Promise<ExecutionProgramRegistrationResult>;
    reserveExecutionProgramAdmission(input: ExecutionProgramReserveInput): Promise<ExecutionProgramReserveResult>;
    beginExecutionProgramInvocation(input: AdmissionCas): Promise<AdmissionBeginResult>;
    releaseExecutionProgramAdmission(input: AdmissionCas, reason?: string): Promise<AdmissionTransitionResult>;
    expireExecutionProgramAdmission(input: AdmissionCas): Promise<AdmissionTransitionResult>;
    supersedeExecutionProgram(artifact: unknown, context: ExecutionProgramRegistrationContext): Promise<ExecutionProgramRegistrationResult>;
    readExecutionProgram(input: ExecutionProgramReference): Promise<Readonly<ExecutionProgramRuntimeState> | null>;
    readExecutionProgramReportSnapshot(input: ExecutionProgramReference): Promise<Readonly<ExecutionProgramReportSnapshot> | null>;
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
export declare class AdmissionStoreValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/** Deterministic marker over the complete closed report-snapshot body. */
export declare function executionProgramReportSnapshotMarker(snapshot: Readonly<ExecutionProgramReportSnapshotBody>): AdmissionDigest;
export declare function createAdmissionSnapshot(raw: AdmissionSnapshotInput): Readonly<AdmissionSnapshot>;
export declare function createExecutionProgramAdmissionBinding(input: ExecutionProgramAdmissionBindingInput): AdmissionResourceReservationInput;
export declare function verifyAdmissionJournal(entries: readonly AdmissionJournalEntry[]): {
    ok: true;
} | {
    ok: false;
    at: number;
    reason: string;
};
/** Linearizable, explicitly test-only reference implementation. */
export declare function createMemoryAdmissionStore(options?: CreateMemoryAdmissionStoreOptions): ExecutionProgramAdmissionStore & {
    readonly testOnly: true;
};
export default createMemoryAdmissionStore;
//# sourceMappingURL=admission-store.d.ts.map