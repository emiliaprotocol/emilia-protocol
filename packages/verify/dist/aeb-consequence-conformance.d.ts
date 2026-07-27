/**
 * Format-neutral executable AEB consequence-admission conformance kernel.
 *
 * The kernel consumes closed, normalized verifier findings. It deliberately
 * keeps native verification, material-action matching, requirement
 * satisfaction, local authorization, local reservation/custody, provider
 * outcome, and observed-effect relation on separate axes.
 *
 * Its atomicity claim is intentionally narrow: `local_atomic` means one
 * linearizable local admission domain reserves operation/native replay and
 * consumes execution authority before provider entry. It makes no remote or
 * federated atomicity, provider truth, effect truth, or exactly-once claim.
 */
export declare const AEB_CONSEQUENCE_CONFORMANCE_VERSION = "AEB-CONSEQUENCE-CONFORMANCE-v1";
export declare const AEB_CONSEQUENCE_CASE_VERSION = "AEB-CONSEQUENCE-CASE-v1";
export declare const AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION = "AEB-CONSEQUENCE-CONFORMANCE-REPORT-v1";
export declare const AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE: Readonly<{
    readonly profile: "local_atomic";
    readonly guarantees: readonly string[];
    readonly exclusions: readonly string[];
}>;
export declare const AEB_CONSEQUENCE_LIMITS: Readonly<{
    max_string_bytes: 4096;
    max_depth: 32;
    max_nodes: 65536;
    max_document_bytes: 1048576;
    max_evidence: 16;
    max_requirements: 16;
    max_prior_operations: 64;
    max_replay_units: 128;
    max_vectors: 256;
    max_reasons: 32;
}>;
export type AebConsequenceDigest = `sha256:${string}`;
export type AebConsequenceNativeVerification = 'VERIFIED' | 'FAILED' | 'INDETERMINATE';
export type AebConsequenceAcceptance = 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
export type ActionMatch = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export type Satisfaction = 'SATISFIED' | 'UNSATISFIED' | 'INDETERMINATE';
export type Authorization = 'AUTHORIZED' | 'NOT_AUTHORIZED' | 'INDETERMINATE';
export type ReservationResult = 'NOT_ATTEMPTED' | 'RESERVED' | 'CONSUMED' | 'UNAVAILABLE' | 'OPERATION_REPLAY' | 'NATIVE_EVIDENCE_REPLAY';
export type CustodyState = 'UNRESERVED' | 'RESERVED' | 'INVOKING' | 'TERMINAL';
export type ProviderOutcome = 'NOT_INVOKED' | 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE';
export type EffectRelation = 'NOT_OBSERVED' | 'OBSERVED_AS_REQUESTED' | 'DIVERGED' | 'INDETERMINATE';
export declare const AEB_CONSEQUENCE_REASONS: readonly ["authenticated_reconciliation", "blind_retry_refused", "distinct_principal_quorum_unsatisfied", "evidence_revoked", "evidence_stale", "exact_action_mismatch", "executor_self_approval_refused", "initiator_self_approval_refused", "local_atomic_reservation_unavailable", "local_policy_denied", "native_evidence_replay", "native_verification_failed", "native_verification_indeterminate", "normalized_action_mismatch", "operation_binding_mismatch", "operation_replay", "provider_and_effect_indeterminate", "provider_committed_effect_diverged", "provider_committed_effect_observed", "provider_proven_not_committed", "reconciliation_binding_mismatch", "reconciliation_indeterminate", "required_role_unsatisfied", "status_authority_not_pinned", "status_unavailable", "timeout_after_dispatch", "unauthenticated_reconciliation"];
export type AebConsequenceReason = typeof AEB_CONSEQUENCE_REASONS[number];
export interface AebConsequenceRequirement {
    role: string;
    principal_kind: 'HUMAN' | 'MACHINE' | 'ORGANIZATION' | 'SYSTEM';
    minimum: number;
    distinct_principals: boolean;
    exclude_initiator: boolean;
    exclude_executor: boolean;
}
export interface AebConsequenceOperation {
    operation_id: string;
    provider_id: string;
    initiator_id: string;
    executor_id: string;
    caid: string;
    normalized_action_digest: AebConsequenceDigest;
    requirements: AebConsequenceRequirement[];
}
export interface AebConsequenceStatus {
    verdict: 'CURRENT' | 'REVOKED' | 'UNAVAILABLE';
    authority_pinned: boolean;
    checked_at: string;
    valid_until: string;
}
export interface AebConsequenceEvidence {
    wrapper_digest: AebConsequenceDigest;
    native_replay_unit: AebConsequenceDigest;
    native_verification: AebConsequenceNativeVerification;
    mapped_caid: string;
    mapped_action_digest: AebConsequenceDigest;
    role: string;
    principal_kind: AebConsequenceRequirement['principal_kind'];
    principal_id: string;
    status: AebConsequenceStatus;
}
export interface AebConsequencePriorOperation {
    operation_id: string;
    caid: string;
    normalized_action_digest: AebConsequenceDigest;
    custody: 'INVOKING' | 'TERMINAL';
    provider_outcome: ProviderOutcome;
    effect_relation: EffectRelation;
}
export interface AebConsequenceReservationInput {
    atomicity: 'local_atomic' | 'unavailable';
    prior_operations: AebConsequencePriorOperation[];
    consumed_native_replay_units: AebConsequenceDigest[];
}
export interface AebConsequenceObservation {
    source: 'TIMEOUT_AFTER_DISPATCH' | 'PROVIDER_EVIDENCE';
    provider_outcome: Exclude<ProviderOutcome, 'NOT_INVOKED'>;
    effect_relation: EffectRelation;
}
export interface AebConsequenceReconciliation {
    authenticated: boolean;
    provider_id: string;
    operation_id: string;
    caid: string;
    normalized_action_digest: AebConsequenceDigest;
    provider_outcome: Exclude<ProviderOutcome, 'NOT_INVOKED'>;
    effect_relation: EffectRelation;
}
export interface AebConsequenceCase {
    '@version': typeof AEB_CONSEQUENCE_CASE_VERSION;
    id: string;
    mode: 'ADMISSION' | 'INVOCATION_OBSERVATION' | 'RETRY' | 'RECONCILIATION';
    evaluated_at: string;
    operation: AebConsequenceOperation;
    evidence: AebConsequenceEvidence[];
    local_policy: 'PERMIT' | 'DENY';
    reservation: AebConsequenceReservationInput;
    observation: AebConsequenceObservation | null;
    reconciliation: AebConsequenceReconciliation | null;
}
export interface AebConsequenceResult {
    verification: AebConsequenceNativeVerification;
    acceptance: AebConsequenceAcceptance;
    action_match: ActionMatch;
    satisfaction: Satisfaction;
    authorization: Authorization;
    reservation: ReservationResult;
    custody: CustodyState;
    provider_outcome: ProviderOutcome;
    effect_relation: EffectRelation;
    retry: 'NOT_APPLICABLE' | 'REFUSED';
    reconciliation: 'NOT_APPLICABLE' | 'NOT_REQUIRED' | 'REQUIRED' | 'REFUSED' | 'ACCEPTED';
    decision: 'ADMIT' | 'REFUSE' | 'INDETERMINATE' | 'RECORDED' | 'RECONCILED';
    reasons: AebConsequenceReason[];
}
export interface AebConsequenceVector {
    id: string;
    input: AebConsequenceCase;
    expected: AebConsequenceResult;
}
export interface AebConsequenceClaimScope {
    profile: 'local_atomic';
    guarantees: string[];
    exclusions: string[];
}
export interface AebConsequenceSuite {
    '@version': typeof AEB_CONSEQUENCE_CONFORMANCE_VERSION;
    claim_scope: AebConsequenceClaimScope;
    vectors: AebConsequenceVector[];
}
export interface AebConsequenceImplementation {
    id: string;
    version: string;
    revision: string;
}
export interface AebConsequenceReportRow {
    id: string;
    case_digest: AebConsequenceDigest;
    expected: AebConsequenceResult;
    actual: AebConsequenceResult;
    pass: boolean;
}
export interface AebConsequenceConformanceReport {
    '@version': typeof AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION;
    suite_digest: AebConsequenceDigest;
    claim_scope: AebConsequenceClaimScope;
    implementation: AebConsequenceImplementation;
    rows: AebConsequenceReportRow[];
    summary: {
        total: number;
        passed: number;
        failed: number;
    };
    assurance: {
        self_attested: true;
        certification: false;
        statement: 'SELF_ATTESTED_NOT_CERTIFICATION';
    };
    report_digest: AebConsequenceDigest;
}
export type AebConsequenceErrorCode = 'invalid_object' | 'unknown_key' | 'missing_key' | 'invalid_string' | 'invalid_enum' | 'invalid_boolean' | 'invalid_integer' | 'invalid_array' | 'invalid_digest' | 'invalid_caid' | 'invalid_instant' | 'invalid_combination' | 'duplicate_value' | 'max_depth_exceeded' | 'max_nodes_exceeded' | 'max_document_bytes_exceeded' | 'cyclic_value' | 'non_canonical_value';
export declare class AebConsequenceConformanceError extends TypeError {
    readonly code: AebConsequenceErrorCode;
    readonly path: string;
    constructor(code: AebConsequenceErrorCode, path: string);
}
export type AebConsequenceValidation<T> = {
    valid: true;
    value: T;
    errors: [];
} | {
    valid: false;
    errors: string[];
};
export interface AebConsequenceSubmissionValidation {
    valid: boolean;
    conformant: boolean;
    errors: string[];
}
export declare function canonicalizeAebConsequenceConformance(value: unknown): string;
export declare function digestAebConsequenceConformance(value: unknown): AebConsequenceDigest;
export declare function digestAebConsequenceCase(value: unknown): AebConsequenceDigest;
export declare function parseAebConsequenceCase(value: unknown): AebConsequenceCase;
export declare function validateAebConsequenceResult(value: unknown): AebConsequenceValidation<AebConsequenceResult>;
export declare function evaluateAebConsequenceCase(value: unknown): AebConsequenceResult;
export declare function validateAebConsequenceConformanceSuite(value: unknown): AebConsequenceValidation<AebConsequenceSuite>;
export declare function evaluateAebConsequenceSuite(suiteValue: unknown, implementationValue: unknown): AebConsequenceConformanceReport;
export declare function validateAebConsequenceSubmission(suiteValue: unknown, submissionValue: unknown): AebConsequenceSubmissionValidation;
declare const _default: {
    AEB_CONSEQUENCE_CONFORMANCE_VERSION: string;
    AEB_CONSEQUENCE_CASE_VERSION: string;
    AEB_CONSEQUENCE_CONFORMANCE_REPORT_VERSION: string;
    AEB_CONSEQUENCE_LIMITS: Readonly<{
        max_string_bytes: 4096;
        max_depth: 32;
        max_nodes: 65536;
        max_document_bytes: 1048576;
        max_evidence: 16;
        max_requirements: 16;
        max_prior_operations: 64;
        max_replay_units: 128;
        max_vectors: 256;
        max_reasons: 32;
    }>;
    AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE: Readonly<{
        readonly profile: "local_atomic";
        readonly guarantees: readonly string[];
        readonly exclusions: readonly string[];
    }>;
    canonicalizeAebConsequenceConformance: typeof canonicalizeAebConsequenceConformance;
    digestAebConsequenceCase: typeof digestAebConsequenceCase;
    digestAebConsequenceConformance: typeof digestAebConsequenceConformance;
    evaluateAebConsequenceCase: typeof evaluateAebConsequenceCase;
    evaluateAebConsequenceSuite: typeof evaluateAebConsequenceSuite;
    parseAebConsequenceCase: typeof parseAebConsequenceCase;
    validateAebConsequenceConformanceSuite: typeof validateAebConsequenceConformanceSuite;
    validateAebConsequenceResult: typeof validateAebConsequenceResult;
    validateAebConsequenceSubmission: typeof validateAebConsequenceSubmission;
};
export default _default;
//# sourceMappingURL=aeb-consequence-conformance.d.ts.map