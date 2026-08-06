/**
 * AEB-EXECUTION-CONDITIONS-v1 — execution-boundary condition evaluation.
 *
 * This is an internal AEB profile, not a policy language and not a new receipt
 * format. It compares opaque, human-approved commitments with normalized
 * resolver results under a relying-party-owned resolver profile. Native
 * resolver authentication happens outside this module; this evaluator refuses
 * any source, trust digest, freshness rule, or enforcement strength that the
 * relying party did not pin.
 *
 * MATCH means only that an accepted resolver reported a match. It does not
 * establish physical or world truth. `observed` and `leased` results can satisfy
 * a condition profile but cannot claim prevention. Only a compare-and-set or
 * provider-enforced result carrying enforcement evidence can support that
 * narrower claim. An ADMIT result covers this conditions axis only; it is not a
 * substitute for AEB evidence verification, local authorization, or atomic
 * authority consumption.
 */
import { type AebDigest } from './aeb-adapter-contract.js';
export declare const AEB_EXECUTION_CONDITIONS_VERSION = "AEB-EXECUTION-CONDITIONS-v1";
export declare const AEB_EXECUTION_RESOLVER_PROFILE_VERSION = "AEB-EXECUTION-RESOLVER-PROFILE-v1";
export declare const AEB_EXECUTION_CONDITION_RESOLUTION_VERSION = "AEB-EXECUTION-CONDITION-RESOLUTION-v1";
export declare const AEB_EXECUTION_CONDITIONS_SCOPE: Readonly<{
    readonly decision_scope: "execution_conditions_only";
    readonly authorization_established: false;
    readonly physical_truth_established: false;
    readonly prevention_capable_strengths: readonly string[];
}>;
export type AebExecutionConditionOutcome = 'ADMIT' | 'PREDICATE_FAILED' | 'INDETERMINATE' | 'INVALID';
export type AebExecutionEnforcementStrength = 'observed' | 'leased' | 'compare-and-set' | 'provider-enforced';
export type AebExecutionResolutionVerdict = 'MATCH' | 'MISMATCH' | 'UNAVAILABLE' | 'CONFLICTING';
export type AebExecutionBasisVerdict = 'CURRENT' | 'EXPIRED' | 'REVOKED' | 'UNAVAILABLE';
export interface AebExecutionResolverSourcePin {
    source_id: string;
    trust_digest: AebDigest;
    required_strength: AebExecutionEnforcementStrength;
}
export interface AebExecutionResolverProfile {
    '@version': typeof AEB_EXECUTION_RESOLVER_PROFILE_VERSION;
    profile_id: string;
    version: number;
    relying_party_id: string;
    max_resolution_age_seconds: number;
    max_future_skew_seconds: number;
    sources: AebExecutionResolverSourcePin[];
    profile_digest: AebDigest;
}
export type AebExecutionResolverProfileInput = Omit<AebExecutionResolverProfile, 'profile_digest'>;
export interface AebExecutionApprovedBasis {
    /** Digest of the independently verified human-authorization artifact. */
    authorization_evidence_digest: AebDigest;
    /** Opaque approved rationale/basis commitment; this module never interprets it. */
    basis_digest: AebDigest;
    /** Opaque approved predicate-set commitment; this module defines no predicate language. */
    predicate_set_digest: AebDigest;
    presentation_method: string;
    /** Digest of the exact presentation bound into the human authorization. */
    presentation_digest: AebDigest;
}
export interface AebExecutionConditionsProfile {
    '@version': typeof AEB_EXECUTION_CONDITIONS_VERSION;
    profile_id: string;
    version: number;
    relying_party_id: string;
    action_digest: AebDigest;
    approved_basis: AebExecutionApprovedBasis;
    resolver_profile_id: string;
    resolver_profile_digest: AebDigest;
    profile_digest: AebDigest;
}
export type AebExecutionConditionsProfileInput = Omit<AebExecutionConditionsProfile, 'profile_digest'>;
export interface AebExecutionBasisStatus {
    verdict: AebExecutionBasisVerdict;
    checked_at: string;
    /** Currency of this status lookup, not an extension of the approval itself. */
    status_valid_until: string;
}
export interface AebExecutionConditionResolution {
    '@version': typeof AEB_EXECUTION_CONDITION_RESOLUTION_VERSION;
    source_id: string;
    source_trust_digest: AebDigest;
    source_record_digest: AebDigest;
    resolver_profile_digest: AebDigest;
    action_digest: AebDigest;
    authorization_evidence_digest: AebDigest;
    basis_digest: AebDigest;
    predicate_set_digest: AebDigest;
    presentation_method: string;
    presentation_digest: AebDigest;
    verdict: AebExecutionResolutionVerdict;
    strength: AebExecutionEnforcementStrength;
    resolved_at: string;
    valid_until: string;
    lease_expires_at: string | null;
    enforcement_evidence_digest: AebDigest | null;
    prevention_claimed: boolean;
}
export interface AebExecutionConditionsEvaluationOptions {
    /** Relying-party-pinned digest; the presented profile is never self-authorizing. */
    expected_profile_digest: AebDigest;
    resolver_profile: AebExecutionResolverProfile;
    action_digest: AebDigest;
    approved_basis: AebExecutionApprovedBasis;
    basis_status: AebExecutionBasisStatus;
    resolutions: readonly AebExecutionConditionResolution[];
    evaluated_at: string;
}
export type AebExecutionConditionReason = 'profile_invalid' | 'profile_digest_mismatch' | 'resolver_profile_invalid' | 'resolver_profile_digest_mismatch' | 'resolver_profile_id_mismatch' | 'relying_party_mismatch' | 'exact_action_mismatch' | 'authorization_evidence_mismatch' | 'basis_digest_mismatch' | 'predicate_set_digest_mismatch' | 'presentation_method_mismatch' | 'presentation_digest_mismatch' | 'basis_status_invalid' | 'basis_status_stale' | 'basis_status_unavailable' | 'basis_expired' | 'basis_revoked' | 'resolution_invalid' | 'resolution_missing' | 'resolution_conflicting' | 'resolution_unavailable' | 'resolution_stale' | 'resolution_from_future' | 'resolution_source_unpinned' | 'resolution_source_trust_mismatch' | 'resolution_resolver_mismatch' | 'resolution_action_mismatch' | 'resolution_authorization_mismatch' | 'resolution_basis_mismatch' | 'resolution_predicate_set_mismatch' | 'resolution_presentation_mismatch' | 'resolution_strength_mismatch' | 'lease_expired' | 'prevention_claim_not_supported' | 'enforcement_evidence_missing' | 'predicate_failed';
export interface AebExecutionConditionsResult {
    outcome: AebExecutionConditionOutcome;
    binding: 'MATCH' | 'MISMATCH' | 'INVALID';
    basis_status: 'CURRENT' | 'EXPIRED' | 'REVOKED' | 'INDETERMINATE' | 'INVALID';
    resolution_status: 'MATCH' | 'MISMATCH' | 'INDETERMINATE' | 'INVALID';
    conditions_satisfied: boolean;
    prevention_established: boolean;
    authorization_established: false;
    physical_truth_established: false;
    decision_scope: 'execution_conditions_only';
    profile_digest: AebDigest | null;
    resolver_profile_digest: AebDigest | null;
    reasons: AebExecutionConditionReason[];
}
export interface AebExecutionProfileVerification {
    valid: boolean;
    profile_digest: AebDigest | null;
    reasons: ('profile_invalid' | 'profile_digest_mismatch')[];
}
export interface AebExecutionResolverProfileVerification {
    valid: boolean;
    profile_digest: AebDigest | null;
    reasons: ('resolver_profile_invalid' | 'resolver_profile_digest_mismatch')[];
}
export declare function computeAebExecutionResolverProfileDigest(profile: AebExecutionResolverProfile): AebDigest;
export declare function verifyAebExecutionResolverProfile(profile: unknown, expectedDigest?: AebDigest): AebExecutionResolverProfileVerification;
export declare function defineAebExecutionResolverProfile(input: AebExecutionResolverProfileInput): AebExecutionResolverProfile;
export declare function computeAebExecutionConditionsProfileDigest(profile: AebExecutionConditionsProfile): AebDigest;
export declare function verifyAebExecutionConditionsProfile(profile: unknown, expectedDigest?: AebDigest): AebExecutionProfileVerification;
export declare function defineAebExecutionConditionsProfile(input: AebExecutionConditionsProfileInput): AebExecutionConditionsProfile;
export declare function evaluateAebExecutionConditions(profile: unknown, options: AebExecutionConditionsEvaluationOptions): AebExecutionConditionsResult;
//# sourceMappingURL=aeb-execution-conditions.d.ts.map