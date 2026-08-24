import { type StrictCanonicalJsonLimits } from './strict-json.js';
export declare const CLAIM_ASSURANCE_PROFILE_VERSION: "EP-CLAIM-ASSURANCE-PROFILE-v1";
export declare const CLAIM_CASE_VERSION: "EP-CLAIM-CASE-v1";
export declare const ASSURANCE_RECORD_VERSION: "EP-ASSURANCE-RECORD-v1";
export declare const CLAIM_ASSURANCE_VERDICTS: readonly ["VERIFIED", "UNVERIFIED", "DIVERGED", "INDETERMINATE"];
export declare const EVIDENCE_VERDICTS: readonly ["VERIFIED", "UNVERIFIED", "INDETERMINATE"];
export declare const EVIDENCE_RELATIONSHIPS: readonly ["SUPPORTS", "CONTRADICTS", "NEUTRAL"];
export declare const CLAIM_ASSURANCE_LIMITS: Readonly<{
    max_profile_requirements: 16;
    max_evidence_items: 32;
    max_verifier_registrations: 32;
    max_artifact_depth: 32;
    max_artifact_nodes: 10000;
    max_artifact_string_bytes: 262144;
    max_case_depth: 40;
    max_case_nodes: 330000;
    max_case_string_bytes: 8454144;
    max_identifier_bytes: 128;
    max_claim_label_bytes: 256;
    max_verifier_reasons: 16;
    max_verifier_reason_bytes: 256;
}>;
export type Sha256Digest = `sha256:${string}`;
export type ClaimAssuranceVerdict = typeof CLAIM_ASSURANCE_VERDICTS[number];
export type EvidenceVerdict = typeof EVIDENCE_VERDICTS[number];
export type EvidenceRelationship = typeof EVIDENCE_RELATIONSHIPS[number];
export type EvidenceDisposition = 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
export interface VerifierDescriptor {
    verifier_id: string;
    verifier_version: string;
    implementation_digest: Sha256Digest;
}
export interface ClaimAssuranceRequirement {
    requirement_id: string;
    evidence_role: string;
    verifier: VerifierDescriptor;
    minimum_distinct_sources: number;
    max_age_seconds: number;
}
export interface ClaimAssuranceProfile {
    '@type': typeof CLAIM_ASSURANCE_PROFILE_VERSION;
    profile_id: string;
    claim_type: string;
    predicate: string;
    requirements: ClaimAssuranceRequirement[];
}
export interface ClaimStatement {
    claim_id: string;
    claim_type: string;
    predicate: string;
    value: unknown;
}
export interface EvidenceBinding {
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    claim_id: string;
    action_digest?: Sha256Digest;
}
export interface ClaimEvidenceItem {
    evidence_id: string;
    role: string;
    verifier: VerifierDescriptor;
    binding: EvidenceBinding;
    artifact: unknown;
    artifact_digest: Sha256Digest;
}
export interface ClaimCase {
    '@type': typeof CLAIM_CASE_VERSION;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    claim: ClaimStatement;
    profile_id: string;
    profile_hash: Sha256Digest;
    action_digest?: Sha256Digest;
    as_of: string;
    evidence: ClaimEvidenceItem[];
}
export interface EvidenceVerifierInput {
    evidence_id: string;
    role: string;
    verifier: Readonly<VerifierDescriptor>;
    artifact: unknown;
    artifact_digest: Sha256Digest;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    action_digest: Sha256Digest | null;
    claim: Readonly<ClaimStatement>;
    as_of: string;
}
export interface EvidenceVerifierResult {
    verdict: EvidenceVerdict;
    relationship: EvidenceRelationship;
    source_id: string;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    claim_id: string;
    observed_at: string;
    expires_at: string;
    artifact_digest: Sha256Digest;
    reasons: string[];
}
export interface EvidenceVerifierRegistration extends VerifierDescriptor {
    /**
     * Live relying-party trust input. The kernel snapshots the callback
     * reference but cannot preempt synchronous code. Production callers must
     * isolate verifier implementations and enforce their own resource and time
     * limits before registering them.
     */
    verify(input: Readonly<EvidenceVerifierInput>): EvidenceVerifierResult;
}
export interface ClaimAssuranceOptions {
    pinned_profile: ClaimAssuranceProfile;
    pinned_profile_hash: Sha256Digest;
    verifier_registry: EvidenceVerifierRegistration[];
    evaluated_at: string;
    expected_action_digest?: Sha256Digest | null;
}
export interface AssuranceEvidenceResult {
    evidence_id: string;
    role: string;
    verifier: VerifierDescriptor;
    artifact_digest: Sha256Digest;
    disposition: EvidenceDisposition;
    verifier_verdict: EvidenceVerdict | null;
    relationship: EvidenceRelationship | null;
    source_id: string | null;
    observed_at: string | null;
    expires_at: string | null;
    reasons: string[];
}
export interface AssuranceRequirementResult {
    requirement_id: string;
    evidence_role: string;
    minimum_distinct_sources: number;
    accepted_supporting_sources: number;
    accepted_contradicting_sources: number;
    accepted_neutral_sources: number;
    disposition: 'SATISFIED' | 'UNVERIFIED' | 'DIVERGED' | 'INDETERMINATE';
    satisfied: boolean;
    reasons: string[];
}
export interface AssuranceRecord {
    '@type': typeof ASSURANCE_RECORD_VERSION;
    profile_id: string;
    profile_hash: Sha256Digest;
    claim_case_digest: Sha256Digest;
    subject_digest: Sha256Digest;
    scope_digest: Sha256Digest;
    claim: ClaimStatement;
    action_digest: Sha256Digest | null;
    as_of: string;
    evaluated_at: string;
    verdict: ClaimAssuranceVerdict;
    profile_satisfied: boolean;
    authorizes_action: false;
    requirement_results: AssuranceRequirementResult[];
    evidence_results: AssuranceEvidenceResult[];
    reasons: string[];
    replay_digest: Sha256Digest;
    record_digest: Sha256Digest;
}
export interface AssuranceRecordIntegrityOptions {
    /** Optional content address pinned independently of the presented record. */
    expected_record_digest?: Sha256Digest;
}
/**
 * Self-integrity inspection only. `reperformed` is deliberately always false:
 * this result does not rerun the Claim Case or establish that verifier outputs
 * were produced by the pinned implementations.
 */
export interface AssuranceRecordIntegrityResult {
    integrity_valid: boolean;
    semantics_valid: boolean;
    replay_digest_matches: boolean;
    digest_matches: boolean;
    expected_digest_matches: boolean | null;
    reperformed: false;
    record_digest: string | null;
    computed_record_digest: Sha256Digest | null;
    reason: string | null;
}
/** SHA-256 over strict canonical artifact bytes. */
export declare function claimAssuranceArtifactDigest(artifact: unknown, limits?: StrictCanonicalJsonLimits): Sha256Digest;
/** Digest of the exact pinned EP-CLAIM-ASSURANCE-PROFILE-v1 bytes. */
export declare function claimAssuranceProfileHash(profile: unknown): Sha256Digest;
/** Digest of the exact EP-CLAIM-CASE-v1 bytes supplied for replay. */
export declare function claimCaseDigest(claimCase: unknown): Sha256Digest;
/**
 * Evaluate a Claim Case using only caller-pinned profile bytes and exact
 * caller-registered verifier implementations.
 *
 * Malformed protocol inputs throw. Evidence rejection and operational
 * uncertainty are represented in the record. No path returns action authority.
 */
export declare function evaluateClaimAssurance(input: unknown, options: ClaimAssuranceOptions): Readonly<AssuranceRecord>;
/**
 * Inspect the strict shape, internal semantics, replay digest, record digest,
 * and optional independently pinned content address of an Assurance Record.
 *
 * This is not Claim Case re-performance. A presenter can recompute both
 * digests after fabricating a self-consistent record. Relying parties must call
 * `evaluateClaimAssurance` with the raw case and their own live verifier pins
 * before relying on the claim verdict.
 */
export declare function inspectAssuranceRecordIntegrity(value: unknown, options?: AssuranceRecordIntegrityOptions): Readonly<AssuranceRecordIntegrityResult>;
/**
 * Backward-compatible projection of `inspectAssuranceRecordIntegrity`.
 * `ok` means strict self-integrity only; it never means the Claim Case was
 * independently re-performed or the real-world claim is true.
 *
 * @deprecated Prefer `inspectAssuranceRecordIntegrity`, whose field names make
 * the digest and re-performance boundaries explicit.
 */
export declare function verifyAssuranceRecordDigest(value: unknown): {
    ok: boolean;
    record_digest: string | null;
    reason: string | null;
};
//# sourceMappingURL=claim-assurance.d.ts.map