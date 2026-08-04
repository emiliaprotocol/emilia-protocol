/**
 * PostgreSQL reference scaffold for one LOCAL_ATOMIC recovery admission.
 *
 * A presenter-supplied recovery decision is deliberately absent from this API.
 * The scaffold evaluates the signed artifact itself, consumes an existing
 * ordinary AdmissionStore reservation, and only then enters the local
 * transaction. No authority or PostgreSQL operation is retried.
 *
 * This module deliberately has no `pg` dependency. Callback confinement to the
 * supplied transaction client is a deployment assertion, not sandbox
 * enforcement performed by this reference scaffold.
 */
import { type RecoveryAdmissionDecision, type RecoveryAdmissionDependencies, type RecoveryCapabilityVerificationContext, type VerifiedRecoveryCapability } from './recovery-admission.js';
import type { AdmissionRecord, AdmissionSnapshot, AdmissionStore } from './admission-store.js';
export declare const RECOVERY_ADMISSION_POSTGRES_BEGIN = "BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE";
export declare const RECOVERY_ADMISSION_POSTGRES_SET_TIMEOUT = "SELECT set_config('statement_timeout', $1, true)";
export interface RecoveryAdmissionPostgresQueryResult {
    readonly rowCount: number | null;
    readonly rows: readonly unknown[];
}
export interface RecoveryAdmissionPostgresClient {
    query(text: string, params?: readonly unknown[]): Promise<RecoveryAdmissionPostgresQueryResult>;
    /** Passing an error asks a compatible pool to discard the connection. */
    release(error?: Error): void;
}
/**
 * These markers describe the deployed credential, state domain, and adapter.
 * In particular, `externalEffectsForbidden` is an operator assertion about
 * callback confinement. It is not sandbox enforcement by this scaffold.
 */
export interface RecoveryAdmissionPostgresPool {
    readonly localAtomic: boolean;
    readonly policyBoundToSingleTransaction: boolean;
    readonly externalEffectsForbidden: boolean;
    readonly stateDomainDigest: string;
    readonly adapterDigest: string;
    connect(): Promise<RecoveryAdmissionPostgresClient>;
}
export interface RecoveryAdmissionPostgresInvocation {
    readonly decision: Readonly<RecoveryAdmissionDecision>;
    readonly capability: Readonly<VerifiedRecoveryCapability>;
    readonly snapshot: Readonly<AdmissionSnapshot>;
    readonly record: Readonly<AdmissionRecord>;
    readonly invocation_token: string;
}
export interface RecoveryAdmissionPostgresPerformance<TResult> {
    readonly result: TResult;
    /** Required before this scaffold can claim a committed or proven result. */
    readonly evidence_digest: string;
}
export interface RecoveryAdmissionPostgresExecutionOptions<TResult> {
    readonly artifact: unknown;
    readonly verificationContext: RecoveryCapabilityVerificationContext;
    readonly evaluatorDependencies: RecoveryAdmissionDependencies;
    readonly admissionStore: AdmissionStore;
    readonly ownerToken: string;
    /** Invocation token durably custodied before the AdmissionStore transition. */
    readonly invocationToken: string;
    readonly pool: RecoveryAdmissionPostgresPool;
    /**
     * The effect callback is expected to use only the supplied transaction
     * client. That confinement remains a deployment assertion, not sandbox
     * enforcement by this reference scaffold.
     */
    readonly perform: (client: RecoveryAdmissionPostgresClient, invocation: Readonly<RecoveryAdmissionPostgresInvocation>) => Promise<RecoveryAdmissionPostgresPerformance<TResult>> | RecoveryAdmissionPostgresPerformance<TResult>;
    readonly validatePrecommit: (client: RecoveryAdmissionPostgresClient, performed: Readonly<RecoveryAdmissionPostgresPerformance<TResult>>, invocation: Readonly<RecoveryAdmissionPostgresInvocation>) => Promise<boolean> | boolean;
    readonly recheckCurrent: (client: RecoveryAdmissionPostgresClient, invocation: Readonly<RecoveryAdmissionPostgresInvocation>) => Promise<boolean> | boolean;
    /** Injectable monotonic-enough wall clock for deterministic tests. */
    readonly now?: () => number;
}
export type RecoveryAdmissionPostgresFailureReason = 'evaluation_failed' | 'recovery_admission_refused' | 'route_mismatch' | 'recovery_binding_invalid' | 'pool_guarantee_mismatch' | 'state_domain_digest_mismatch' | 'adapter_digest_mismatch' | 'admission_store_guarantee_mismatch' | 'admission_read_failed' | 'admission_not_found' | 'admission_snapshot_read_failed' | 'admission_snapshot_not_found' | 'admission_binding_mismatch' | 'admission_not_reserved' | 'begin_invocation_refused' | 'begin_invocation_ambiguous' | 'deadline_expired' | 'transaction_timeout' | 'clock_invalid' | 'connection_failed' | 'begin_failed' | 'perform_failed' | 'evidence_required' | 'precommit_validation_failed' | 'currentness_recheck_failed' | 'rollback_failed' | 'commit_acknowledgement_failed' | 'provider_outcome_recording_failed';
type PreInvocationFailureReason = Extract<RecoveryAdmissionPostgresFailureReason, 'evaluation_failed' | 'recovery_admission_refused' | 'route_mismatch' | 'recovery_binding_invalid' | 'pool_guarantee_mismatch' | 'state_domain_digest_mismatch' | 'adapter_digest_mismatch' | 'admission_store_guarantee_mismatch' | 'admission_read_failed' | 'admission_not_found' | 'admission_snapshot_read_failed' | 'admission_snapshot_not_found' | 'admission_binding_mismatch' | 'admission_not_reserved' | 'begin_invocation_refused' | 'deadline_expired' | 'clock_invalid'>;
type ProvenNotCommittedReason = Extract<RecoveryAdmissionPostgresFailureReason, 'deadline_expired' | 'transaction_timeout' | 'clock_invalid' | 'perform_failed' | 'precommit_validation_failed' | 'currentness_recheck_failed'>;
type IndeterminateReason = Exclude<RecoveryAdmissionPostgresFailureReason, PreInvocationFailureReason | ProvenNotCommittedReason> | ProvenNotCommittedReason;
export type RecoveryAdmissionPostgresExecutionResult<TResult> = Readonly<{
    outcome: 'COMMITTED';
    invoked: true;
    result: TResult;
    evidence_digest: string;
}> | Readonly<{
    outcome: 'NOT_INVOKED';
    invoked: false;
    reason: PreInvocationFailureReason;
}> | Readonly<{
    outcome: 'PROVEN_NOT_COMMITTED';
    invoked: true;
    reason: ProvenNotCommittedReason;
    evidence_digest: string;
}> | Readonly<{
    outcome: 'INDETERMINATE';
    invoked: boolean;
    reason: IndeterminateReason;
    evidence_digest?: string;
}>;
/**
 * Execute at most once. The signed artifact is evaluated internally and the
 * ordinary RESERVED admission is consumed with the caller's durably custodied
 * prepared invocation token before BEGIN or `perform`. No SQLSTATE, callback,
 * outcome-recording, authority, or ambiguous COMMIT failure is retried, and
 * authority is never restored by this reference scaffold.
 */
export declare function executeRecoveryAdmissionPostgresLocalAtomic<TResult>(options: RecoveryAdmissionPostgresExecutionOptions<TResult>): Promise<RecoveryAdmissionPostgresExecutionResult<TResult>>;
export default executeRecoveryAdmissionPostgresLocalAtomic;
//# sourceMappingURL=recovery-admission-postgres.d.ts.map