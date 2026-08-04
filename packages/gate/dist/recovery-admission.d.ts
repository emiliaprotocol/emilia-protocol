/**
 * Relying-party-pinned recovery classification at the admission boundary.
 *
 * The signed artifact binds one exact action/provider/adapter tuple. Mutable
 * status and reservation evidence never comes from that presenter: the
 * evaluator obtains it from relying-party-injected callbacks immediately
 * before admission and treats every unavailable or malformed answer as a
 * refusal.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
import type { AdmissionSnapshotBody } from './admission-store.js';
export declare const RECOVERY_CAPABILITY_VERSION = "EP-RECOVERY-CAPABILITY-v1";
export declare const RECOVERY_CAPABILITY_STATUS_VERSION = "EP-RECOVERY-CAPABILITY-STATUS-v1";
export declare const RECOVERY_RESERVATION_STATUS_VERSION = "EP-RECOVERY-RESERVATION-STATUS-v1";
export declare const RECOVERY_ADMISSION_BINDINGS_VERSION = "EP-RECOVERY-ADMISSION-BINDINGS-v1";
export declare const RECOVERY_CAPABILITY_CLAIM_BOUNDARY = "signed_policy_bound_recovery_classification_and_current_reserved_capacity_only_local_atomic_intra_transaction_only_compensation_requires_fresh_separate_admission_not_guaranteed_reversal_not_retry_authority_not_external_effect_truth_not_complete_mediation";
export type RecoveryMode = 'LOCAL_ATOMIC' | 'RESERVED_COMPENSATION' | 'IRREVERSIBLE';
export type RecoveryAdmissionRoute = 'LOCAL_ATOMIC' | 'RESERVED_COMPENSATION' | 'AUTHORITY_REQUIRED' | 'REFUSED';
export interface LocalAtomicRecovery {
    scope: 'INTRA_TRANSACTION_ONLY';
    state_domain_digest: string;
    adapter_id: string;
    adapter_digest: string;
    max_transaction_ms: number;
}
export interface ReservedCompensationRecovery {
    scope: 'RESERVED_CAPACITY_ONLY';
    compensation_admission: 'FRESH_SEPARATE_ACTION_REQUIRED';
    remedy_caid: string;
    remedy_action_digest: string;
    destination_digest: string;
    authority_digest: string;
    reservation_digest: string;
    units: number;
    unit: string;
    available_until: string;
}
interface RecoveryCapabilityCommonInput {
    capability_id: string;
    admission_id: string;
    admission_snapshot_digest: string;
    tenant_id: string;
    audience: string;
    action_caid: string;
    action_digest: string;
    action_capability_expires_at: string;
    provider_id: string;
    account_digest: string;
    environment_digest: string;
    operation_id: string;
    issuer_digest: string;
    trust_epoch_digest: string;
    config_epoch_digest: string;
    adapter_id: string;
    adapter_digest: string;
    resource_set_digest: string;
    issued_at: string;
    valid_from: string;
    expires_at: string;
}
export type RecoveryCapabilityInput = RecoveryCapabilityCommonInput & ({
    mode: 'LOCAL_ATOMIC';
    recovery: LocalAtomicRecovery;
} | {
    mode: 'RESERVED_COMPENSATION';
    recovery: ReservedCompensationRecovery;
} | {
    mode: 'IRREVERSIBLE';
    recovery: null;
});
export type VerifiedRecoveryCapability = Readonly<RecoveryCapabilityInput & {
    '@version': typeof RECOVERY_CAPABILITY_VERSION;
    retry_permitted: false;
    claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}>;
interface RecoveryExpectedPolicyCommonSnapshot {
    capability_id: string;
    admission_id: string;
    admission_snapshot_digest: string;
    tenant_id: string;
    audience: string;
    action_caid: string;
    action_digest: string;
    action_capability_expires_at: string;
    provider_id: string;
    account_digest: string;
    environment_digest: string;
    operation_id: string;
    issuer_id: string;
    issuer_digest: string;
    trust_epoch_digest: string;
    config_epoch_digest: string;
    adapter_id: string;
    adapter_digest: string;
    resource_set_digest: string;
}
export type RecoveryExpectedPolicySnapshot = RecoveryExpectedPolicyCommonSnapshot & ({
    mode: 'LOCAL_ATOMIC';
    recovery: LocalAtomicRecovery;
} | {
    mode: 'RESERVED_COMPENSATION';
    recovery: ReservedCompensationRecovery;
} | {
    mode: 'IRREVERSIBLE';
    recovery: null;
});
export interface RecoveryCapabilityVerificationContext {
    trusted_keys: TrustedRiskKeys;
    expected_policy: RecoveryExpectedPolicySnapshot;
    now: string;
}
export interface RecoveryAdmissionSnapshotBindings {
    provider_id: string;
    account_digest: string;
    environment_digest: string;
    adapter_digest: string;
    trust_epoch_digest: string;
    config_epoch_digest: string;
    resource_set_digest: string;
}
export interface RecoveryCapabilityVerification {
    accepted: boolean;
    verified: boolean;
    reason: string | null;
    capability_digest: string | null;
    capability: VerifiedRecoveryCapability | null;
    issuer_id: string | null;
    claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}
export interface RecoveryStatusResolverInput {
    capability: VerifiedRecoveryCapability;
    capability_digest: string;
    issuer_id: string;
    admission_at: string;
    action_capability_expires_at: string;
}
export type RecoveryCurrentStatusResolver = (input: Readonly<RecoveryStatusResolverInput>) => unknown | Promise<unknown>;
export type RecoveryReservationVerifier = (input: Readonly<RecoveryStatusResolverInput>) => unknown | Promise<unknown>;
export interface RecoveryAdmissionDependencies {
    current_status_resolver: RecoveryCurrentStatusResolver;
    reservation_verifier?: RecoveryReservationVerifier;
}
export interface RecoveryAdmissionDecision {
    recovery_route_accepted: boolean;
    route: RecoveryAdmissionRoute;
    reason: string | null;
    scope: 'INTRA_TRANSACTION_ONLY' | 'RESERVED_CAPACITY_ONLY' | 'FRESH_AUTHORITY_REQUIRED' | 'NONE';
    retry_permitted: false;
    fresh_action_admission_required: boolean;
    capability_digest: string | null;
    capability: VerifiedRecoveryCapability | null;
    status: Readonly<RiskRecord> | null;
    reservation: Readonly<RiskRecord> | null;
    claim_boundary: typeof RECOVERY_CAPABILITY_CLAIM_BOUNDARY;
}
export declare class RecoveryCapabilityValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/**
 * Derive the privacy-preserving execution-context bindings carried by a
 * recovery capability from the exact ordinary admission snapshot. Issuers and
 * executors use this same derivation so a valid recovery signature cannot be
 * replayed onto a different provider account, environment, trust/configuration
 * epoch, adapter, or reserved resource set.
 */
export declare function deriveRecoveryAdmissionSnapshotBindings(snapshot: Readonly<AdmissionSnapshotBody>): Readonly<RecoveryAdmissionSnapshotBindings>;
/** Sign the closed v1 body with Ed25519 over reliance-risk-crypto JCS bytes. */
export declare function signRecoveryCapability(rawInput: RecoveryCapabilityInput | RiskRecord, rawSigner: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
/** Digest of the complete signed artifact, including its Ed25519 proof. */
export declare function recoveryCapabilityDigest(artifact: unknown): string;
/** Verify signature, closed schema, complete expected tuple, and active time. */
export declare function verifyRecoveryCapability(artifact: unknown, rawContext?: RecoveryCapabilityVerificationContext): RecoveryCapabilityVerification;
/**
 * Resolve current status from relying-party code and return the only four v1
 * routes. Presenter-supplied mutable state is outside this API by design.
 */
export declare function evaluateRecoveryAdmission(artifact: unknown, rawContext: RecoveryCapabilityVerificationContext, dependencies: RecoveryAdmissionDependencies): Promise<RecoveryAdmissionDecision>;
declare const _default: {
    RECOVERY_CAPABILITY_VERSION: string;
    RECOVERY_CAPABILITY_STATUS_VERSION: string;
    RECOVERY_RESERVATION_STATUS_VERSION: string;
    RECOVERY_CAPABILITY_CLAIM_BOUNDARY: string;
    signRecoveryCapability: typeof signRecoveryCapability;
    recoveryCapabilityDigest: typeof recoveryCapabilityDigest;
    verifyRecoveryCapability: typeof verifyRecoveryCapability;
    evaluateRecoveryAdmission: typeof evaluateRecoveryAdmission;
};
export default _default;
//# sourceMappingURL=recovery-admission.d.ts.map