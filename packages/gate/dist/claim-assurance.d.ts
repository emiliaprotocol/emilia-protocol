export declare const CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION: "EP-CLAIM-ASSURANCE-GATE-PRESENTATION-v1";
export declare const CLAIM_ASSURANCE_ADMISSIBILITY_VERSION: "EP-CLAIM-ASSURANCE-ADMISSIBILITY-v1";
/**
 * Structural Claim Assurance contracts keep this optional Gate bridge from
 * importing a verifier release that may not yet expose the experimental
 * subpath. Deployments inject the exact evaluator they reviewed instead.
 */
export type Sha256Digest = `sha256:${string}`;
export type ClaimAssuranceVerdict = 'VERIFIED' | 'UNVERIFIED' | 'DIVERGED' | 'INDETERMINATE';
export interface ClaimAssuranceVerifierDescriptor {
    verifier_id: string;
    verifier_version: string;
    implementation_digest: Sha256Digest;
}
export interface ClaimAssuranceRequirement {
    requirement_id: string;
    evidence_role: string;
    verifier: ClaimAssuranceVerifierDescriptor;
    minimum_distinct_sources: number;
    max_age_seconds: number;
}
export interface ClaimAssuranceProfile {
    '@type': 'EP-CLAIM-ASSURANCE-PROFILE-v1';
    profile_id: string;
    claim_type: string;
    predicate: string;
    requirements: ClaimAssuranceRequirement[];
}
export interface ClaimAssuranceClaimStatement {
    claim_id: string;
    claim_type: string;
    predicate: string;
    value: unknown;
}
export interface ClaimAssuranceEvidenceVerifierInput {
    evidence_id: string;
    role: string;
    verifier: Readonly<ClaimAssuranceVerifierDescriptor>;
    artifact: unknown;
    artifact_digest: Sha256Digest;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    action_digest: Sha256Digest | null;
    claim: Readonly<ClaimAssuranceClaimStatement>;
    as_of: string;
}
export interface ClaimAssuranceEvidenceVerifierResult {
    verdict: 'VERIFIED' | 'UNVERIFIED' | 'INDETERMINATE';
    relationship: 'SUPPORTS' | 'CONTRADICTS' | 'NEUTRAL';
    source_id: string;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    claim_id: string;
    observed_at: string;
    expires_at: string;
    artifact_digest: Sha256Digest;
    reasons: string[];
}
export interface ClaimAssuranceEvidenceVerifierRegistration extends ClaimAssuranceVerifierDescriptor {
    verify(input: Readonly<ClaimAssuranceEvidenceVerifierInput>): ClaimAssuranceEvidenceVerifierResult;
}
export interface ClaimAssuranceEvaluationRecord {
    verdict: ClaimAssuranceVerdict;
    profile_satisfied: boolean;
    authorizes_action: false;
    requirement_results: Array<{
        reasons: string[];
    }>;
    evidence_results: Array<{
        reasons: string[];
    }>;
    reasons: string[];
    replay_digest: Sha256Digest;
    record_digest: Sha256Digest;
    claim_case_digest: Sha256Digest;
    as_of: string;
    evaluated_at: string;
}
export interface ClaimAssuranceEvaluationOptions {
    pinned_profile: ClaimAssuranceProfile;
    pinned_profile_hash: Sha256Digest;
    verifier_registry: ClaimAssuranceEvidenceVerifierRegistration[];
    evaluated_at: string;
    expected_action_digest: Sha256Digest;
}
export type EvaluateClaimAssurance = (claimCase: unknown, options: Readonly<ClaimAssuranceEvaluationOptions>) => Readonly<ClaimAssuranceEvaluationRecord>;
export interface ClaimAssuranceGatePresentation {
    '@type': typeof CLAIM_ASSURANCE_GATE_PRESENTATION_VERSION;
    claim_case: unknown;
}
export interface ClaimAssuranceAdmissibilityOptions {
    pinnedProfile: ClaimAssuranceProfile;
    pinnedProfileHash: Sha256Digest;
    /**
     * Reviewed Claim Assurance kernel callback. This executable callback and the
     * verifier registry below are deployment trust inputs, not presenter data.
     */
    evaluateClaimAssurance: EvaluateClaimAssurance;
    /** Reviewed evidence-verifier callbacks pinned by id, version, and digest. */
    verifierRegistry: ClaimAssuranceEvidenceVerifierRegistration[];
    /** Maximum age of the whole Claim Case at the admission instant. */
    maxCaseAgeSec: number;
    now?: () => number;
}
export interface ClaimAssuranceGateVerifierInput {
    pinned_profile: {
        id?: unknown;
        profile_hash?: unknown;
    };
    presented: unknown;
    receipt?: unknown;
    selector?: unknown;
    observed_action: unknown;
}
export type ClaimAssuranceAdmissibilityVerdict = 'admissible' | 'missing_evidence' | 'stale' | 'conflicted' | 'unverifiable';
export interface ClaimAssuranceAdmissibilityBlock {
    '@type': typeof CLAIM_ASSURANCE_ADMISSIBILITY_VERSION;
    admissibility_profile: {
        id: string;
        version: '1';
    };
    profile_hash: Sha256Digest;
    verdict: ClaimAssuranceAdmissibilityVerdict;
    replay_digest: Sha256Digest;
    assurance_record_digest: Sha256Digest;
    claim_case_digest: Sha256Digest;
    action_digest: Sha256Digest;
    claim_assurance_verdict: ClaimAssuranceVerdict;
    profile_satisfied: boolean;
    authorizes_action: false;
    as_of: string;
    evaluated_at: string;
    reasons: string[];
}
/**
 * Construct the trusted callback accepted by createGate's
 * `verifyAdmissibilityPacket` option.
 */
export declare function createClaimAssuranceAdmissibilityVerifier({ pinnedProfile, pinnedProfileHash, evaluateClaimAssurance, verifierRegistry, maxCaseAgeSec, now, }: ClaimAssuranceAdmissibilityOptions): (input: ClaimAssuranceGateVerifierInput) => Promise<Readonly<ClaimAssuranceAdmissibilityBlock>>;
export { CLAIM_ASSURANCE_ADMISSIBILITY_RESULT_VERSION, claimAssuranceResultCandidate, validateClaimAssuranceAdmissibilityResult, type ClaimAssuranceResultValidation, type ClaimAssuranceResultValidationOptions, } from './claim-assurance-result.js';
//# sourceMappingURL=claim-assurance.d.ts.map