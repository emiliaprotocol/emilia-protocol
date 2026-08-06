/**
 * Relying-party-owned, content-addressed acceptance bar for AEB evidence.
 *
 * One immutable profile governs both deployment modes. Monitor mode is
 * deliberately non-authorizing and non-consuming. Enforce mode delegates the
 * final decision to the AEB execution boundary, including exact-record-bound
 * verification, local authority, and atomic native replay consumption.
 */
import { type AebConsumptionStore, type AebDigest, type AebEvaluationRecord, type AebEvaluationVerification } from './aeb-adapter-contract.js';
export declare const AEB_ACCEPTANCE_PROFILE_VERSION = "EP-AEB-ACCEPTANCE-PROFILE-v1";
export interface AebAcceptedInput {
    adapter_id: string;
    adapter_version: string;
    profile_id: string;
    profile_digest: AebDigest;
    evidence_role: string;
}
export interface AebAcceptanceProfile {
    '@version': typeof AEB_ACCEPTANCE_PROFILE_VERSION;
    profile_id: string;
    version: number;
    authored_by: string;
    relying_party_id: string;
    action_type: string;
    pinned_config_digest: AebDigest;
    requirement_ref: string;
    requirement_digest: AebDigest;
    registry_digest: AebDigest;
    required_roles: readonly string[];
    /** Allowlist. The AEB requirement determines which roles must be present. */
    accepted_inputs: readonly AebAcceptedInput[];
    modes: {
        monitor: {
            authorizes_execution: false;
            consumes_evidence: false;
        };
        enforce: {
            requires_execution_verification: true;
            requires_local_authorization: true;
            requires_one_time_consumption: true;
        };
    };
    profile_digest: AebDigest;
}
export type AebAcceptanceProfileInput = Omit<AebAcceptanceProfile, 'modes' | 'profile_digest'>;
export interface AebAcceptanceProfileVerification {
    valid: boolean;
    profile_digest: AebDigest | null;
    reasons: string[];
}
export interface AebAcceptanceDecision {
    state: 'MONITOR_WOULD_ACCEPT' | 'MONITOR_WOULD_REFUSE' | 'AUTHORIZED' | 'REFUSED' | 'RECONCILIATION_REQUIRED';
    allowed: boolean;
    invoke_allowed: boolean;
    would_enforce: boolean;
    reason: string;
    acceptance_profile_digest: AebDigest | null;
    program_digest: AebDigest | null;
    reservation_key?: string;
}
export declare function computeAebAcceptanceProfileDigest(profile: AebAcceptanceProfile): AebDigest;
export declare function defineAebAcceptanceProfile(input: AebAcceptanceProfileInput): AebAcceptanceProfile;
export declare function verifyAebAcceptanceProfile(profile: unknown, expectedDigest?: AebDigest): AebAcceptanceProfileVerification;
export declare function applyAebAcceptanceProfile(profile: unknown, record: AebEvaluationRecord, options: {
    mode: 'monitor' | 'enforce';
    expected_profile_digest: AebDigest;
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
    local_authorization: boolean;
    store?: AebConsumptionStore;
}): AebAcceptanceDecision;
/** Stable key useful for monitoring diagnostics without reserving it. */
export declare function aebAcceptanceReservationKey(record: AebEvaluationRecord): string;
//# sourceMappingURL=aeb-acceptance-profile.d.ts.map