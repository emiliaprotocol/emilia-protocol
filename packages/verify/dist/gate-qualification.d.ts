import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
export type QualificationDigest = `sha256:${string}`;
export declare const CANDIDATE_MANIFEST_VERSION = "EP-CANDIDATE-MANIFEST-v1";
export declare const EVALUATION_CAMPAIGN_PREDICATE = "https://emiliaprotocol.ai/attestation/evaluation-campaign/v1";
export declare const TEST_RESULT_PREDICATE = "https://in-toto.io/attestation/test-result/v0.1";
export declare const AGENT_EVALUATION_EVIDENCE_PREDICATE = "https://emiliaprotocol.ai/attestation/agent-evaluation-evidence/v1";
export declare const QUALIFICATION_STATEMENT_PREDICATE = "https://in-toto.io/attestation/svr/v0.2";
export declare const QUALIFICATION_STATUS_VERSION = "EP-QUALIFICATION-STATUS-v1";
export declare const RUNTIME_CANDIDATE_MEASUREMENT_VERSION = "EP-RUNTIME-CANDIDATE-MEASUREMENT-v1";
export declare const IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";
export declare const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export declare const QUALIFICATION_STATUS_PAYLOAD_TYPE = "application/vnd.emilia.qualification-status+json";
export declare const RUNTIME_MEASUREMENT_PAYLOAD_TYPE = "application/vnd.emilia.runtime-candidate-measurement+json";
export declare const QUALIFICATION_PROPERTY = "EMILIA_GATE_QUALIFICATION_V2";
export declare const TERMINAL_OUTCOMES: readonly ["PASS", "FAIL", "ABORTED", "EXPIRED"];
export declare const QUALIFICATION_DECISIONS: readonly ["QUALIFIED", "NOT_QUALIFIED", "INDETERMINATE"];
export declare const MODEL_PINNING_STRENGTHS: readonly ["UNPINNABLE", "MUTABLE_ALIAS", "VERSION_PINNED", "IMMUTABLE_DIGEST"];
export declare const GATE_QUALIFICATION_LIMITS: Readonly<{
    max_payload_bytes: 1048576;
    max_string_bytes: 4096;
    max_signatures: 8;
    max_campaigns: 32;
    max_status_entries: 256;
    max_test_results: 4096;
    max_agent_evidence: 32;
    max_terminal_outcomes: 4096;
    max_challenges: 512;
    max_batches: 128;
    max_attempts_per_challenge: 16;
    max_measurements: 256;
    max_test_names: 4096;
    max_configuration_refs: 32;
    max_properties: 128;
    max_object_depth: 32;
    max_object_nodes: 65536;
}>;
export interface SchemaResult<T = any> {
    valid: boolean;
    value?: T;
    reason?: string;
}
export interface DsseEnvelope {
    payloadType: string;
    payload: string;
    signatures: Array<{
        keyid: string;
        sig: string;
    }>;
}
export interface ArtifactTrustPolicy {
    keys: Record<string, string>;
    accepted_keyids: string[];
    threshold: number;
}
export interface QualificationTrustPolicies {
    campaign: ArtifactTrustPolicy;
    test_result: ArtifactTrustPolicy;
    agent_evidence: ArtifactTrustPolicy;
    qualification_statement: ArtifactTrustPolicy;
    qualification_status: ArtifactTrustPolicy;
    runtime_measurement: ArtifactTrustPolicy;
}
export interface QualificationEvaluationContext {
    now: string;
    expected_candidate_manifest_digest: QualificationDigest;
    expected_assignment_digest: QualificationDigest;
    expected_qualification_policy_digest: QualificationDigest;
    expected_protected_request_digest: QualificationDigest;
    expected_runtime_measurement_authority_id: string;
    expected_runtime_measurement_mechanism_digest: QualificationDigest;
    expected_status_authority_id: string;
    minimum_status_sequence: number;
    max_status_observation_age_seconds: number;
    max_runtime_measurement_age_seconds: number;
    minimum_model_pinning_strength: typeof MODEL_PINNING_STRENGTHS[number];
    trust: QualificationTrustPolicies;
}
export interface QualificationBundle {
    candidate_manifest: unknown;
    campaigns: unknown[];
    test_results: unknown[];
    agent_evaluation_evidence: unknown[];
    qualification_statement: unknown;
    qualification_status_chain: unknown[];
    qualification_status_observation: unknown;
    runtime_measurement: unknown;
}
export interface QualificationDecision {
    decision: typeof QUALIFICATION_DECISIONS[number];
    reason: string;
    verification: 'VERIFIED' | 'NOT_VERIFIED';
    acceptance: 'ACCEPTED' | 'NOT_ACCEPTED';
    candidate_match: 'EXACT_MATCH' | 'MISMATCH' | 'UNPINNABLE' | 'STALE' | 'UNKNOWN';
    assignment_scope: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNKNOWN';
    currentness: 'CURRENT_AS_OBSERVED' | 'STALE' | 'REVOKED' | 'SUSPENDED' | 'EXPIRED' | 'EQUIVOCATED' | 'UNKNOWN';
    campaign_graph: 'COMPLETE' | 'INCOMPLETE' | 'INVALID';
    remeasure_at_begin_invocation: boolean;
    checks: Record<string, boolean>;
    payload_digests: {
        candidate_manifest: string | null;
        campaign_head: string | null;
        qualification_graph: string | null;
        qualification_statement: string | null;
        qualification_status_head: string | null;
        runtime_measurement: string | null;
        protected_request_digest: QualificationDigest | null;
    };
}
export declare function canonicalizeQualification(value: unknown): string;
export declare function qualificationPayloadDigest(value: unknown): QualificationDigest;
export declare function dsseSigningBytes(payloadType: string, payload: Uint8Array): Buffer;
export declare function validateCandidateManifest(value: any): SchemaResult<Obj>;
export declare function validateEvaluationCampaign(value: any): SchemaResult<Obj>;
export declare function validateTestResultReference(value: any): SchemaResult<Obj>;
export declare function validateAgentEvaluationEvidence(value: any): SchemaResult<Obj>;
export declare function validateQualificationStatement(value: any): SchemaResult<Obj>;
export declare function validateQualificationStatus(value: any): SchemaResult<Obj>;
export declare function validateRuntimeCandidateMeasurement(value: any): SchemaResult<Obj>;
export declare function terminalOutcomesRoot(outcomes: unknown[]): QualificationDigest;
export declare function qualificationGraphDigest(graph: {
    campaign_payload_digests: string[];
    test_result_payload_digests: string[];
    agent_evaluation_evidence_payload_digests: string[];
}): QualificationDigest;
export declare function qualificationMerkleParent(left: QualificationDigest, right: QualificationDigest): QualificationDigest;
/** Verify and evaluate qualification without reserving, consuming, or mutating storage. */
export declare function evaluateQualification(bundle: unknown, context: unknown): QualificationDecision;
/** Alias emphasizing complete campaign-graph verification. */
export declare function verifyQualificationGraph(bundle: unknown, context: unknown): QualificationDecision;
export declare const CandidateManifestSchema: Readonly<{
    validate: typeof validateCandidateManifest;
}>;
export declare const EvaluationCampaignSchema: Readonly<{
    validate: typeof validateEvaluationCampaign;
}>;
export declare const TestResultReferenceSchema: Readonly<{
    validate: typeof validateTestResultReference;
}>;
export declare const AgentEvaluationEvidenceSchema: Readonly<{
    validate: typeof validateAgentEvaluationEvidence;
}>;
export declare const QualificationStatementSchema: Readonly<{
    validate: typeof validateQualificationStatement;
}>;
export declare const QualificationStatusSchema: Readonly<{
    validate: typeof validateQualificationStatus;
}>;
export declare const RuntimeCandidateMeasurementSchema: Readonly<{
    validate: typeof validateRuntimeCandidateMeasurement;
}>;
/**
 * THIS PATH NEVER ACCEPTS. It refuses with `alg_registration_pending`. Read
 * why before using it, because the reason is the deliverable.
 *
 * DSSE IS A FOREIGN-GOVERNED WIRE FORMAT AND IT CARRIES NO ALGORITHM
 * IDENTIFIER AT ALL. A DSSE signature is `{ keyid, sig }`. There is no `alg`
 * field to populate, so there is nothing for a relying party to check the
 * declared algorithm against, and algorithm choice is inferred entirely from
 * whatever key material the verifier's own policy has filed under that
 * `keyid`. That is workable for a single algorithm; it is exactly the
 * confusion EP-SIG-AGILITY-v1 exists to prevent once two are in play.
 *
 * WHAT IS ACTUALLY MISSING, named precisely (two things, both external):
 *
 *   1. A DSSE-LEVEL ALGORITHM IDENTIFIER, or a profile that binds `keyid` to
 *      an algorithm inside the signed bytes. There is no candidate to trace:
 *      the only ML-DSA-65 algorithm identifier anywhere in this repository is
 *      the COSE one (-49, RFC 9964, see
 *      packages/verify/src/aeb-mcgraw-delegation-adapter.ts), and COSE
 *      identifiers are not DSSE identifiers. Inventing a DSSE-side value from
 *      memory is precisely the failure this gate exists to prevent.
 *
 *   2. A SIGNED LOCATION FOR THE REQUIRED-ALGORITHM SET. DSSE's PAE covers
 *      exactly `payloadType` and `payload` and nothing else; the `signatures`
 *      array is outside the signature. So the required set must live inside the
 *      payload. But the payload of four of the six artifact classes this module
 *      verifies is an in-toto Statement, and two of its four predicate types
 *      are in-toto.io's, not EP's (TEST_RESULT_PREDICATE,
 *      QUALIFICATION_STATEMENT_PREDICATE). EP may not add a top-level member to
 *      an in-toto Statement, nor a field to a foreign predicate, without
 *      leaving the format it claims to speak. Changing `payloadType` to an
 *      EP-owned media type would put the set inside the PAE, but the artifact
 *      would then no longer be an in-toto attestation, which is the whole point
 *      of using DSSE here.
 *
 * Note that (2) is not solved by (1). Even with a registered DSSE algorithm
 * identifier, a set commitment with nowhere signed to live means leg-stripping
 * is caught only by relying-party policy, never by the bytes. The reference
 * migration (EP-REVOCATION-v2) is explicit that the byte-level commitment is
 * the point and that policy alone is the weaker property.
 *
 * WHAT IS IMPLEMENTED HERE ANYWAY. The complete STRUCTURAL v2, so that the day
 * both gaps close the only change is removing the gate: exact envelope and
 * signature-entry shapes, exact per-algorithm signature length pins (Ed25519
 * 64, ML-DSA-65 3309 -- note the v1 path's 512-byte signature cap cannot carry
 * an ML-DSA-65 signature at all), the required-algorithm set rebuilt from the
 * REGISTERED set and never narrowed to what an envelope presented, per-leg
 * verification through the unmodified EP-SIG-AGILITY-v1 module, and threshold
 * accounting over accepted keyids. The gate is applied LAST, after that work,
 * and `accepted` is false on every path.
 *
 * NOT GATED, AND UNCHANGED: everything above this line. `verifyEnvelope` and
 * the whole v1 qualification pipeline are untouched, synchronous, and
 * Ed25519-only. `packages/gate/src/gate-qualification-v2.ts` orchestrates
 * admission custody over a QualificationDecision and contains no signature
 * code of its own, so it needs no change and gets none.
 */
export declare const GATE_QUALIFICATION_HYBRID_PROFILE = "EP-GATE-QUALIFICATION-DSSE-HYBRID-v2";
/** The registered required algorithm set, in canonical order. */
export declare const GATE_QUALIFICATION_HYBRID_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** The single named refusal this gate returns until both gaps above close. */
export declare const GATE_QUALIFICATION_HYBRID_GATE_REASON = "alg_registration_pending";
export interface HybridArtifactTrustPolicy {
    /** keyid -> { alg, public_key }. Ed25519: SPKI base64url or PEM. ML-DSA-65: raw base64url. */
    keys: Record<string, {
        alg: string;
        public_key: string;
    }>;
    accepted_keyids: string[];
    threshold: number;
}
export interface HybridDsseResult {
    /** ALWAYS false while the gate stands. */
    accepted: boolean;
    reason: string;
    checks: {
        structure: boolean;
        algorithm_set: boolean;
        legs_present: boolean;
        signature_lengths: boolean;
        /** Verdict the leg checks reached; reported, never converted into acceptance. */
        signatures_would_verify: boolean;
        threshold_met: boolean;
        /** Always false: the gate below. */
        algorithm_registered: boolean;
    };
    errors: string[];
}
/**
 * Structural verification of a hybrid DSSE envelope, followed unconditionally
 * by the registration gate. `accepted` is false on every path; the checks
 * object reports how far the structure got so the eventual un-gating is a
 * one-line change and not a rewrite.
 *
 * Never throws on caller input.
 */
export declare function verifyHybridDsseEnvelope(envelope: unknown, expectedPayloadType: string, trust: HybridArtifactTrustPolicy | null | undefined, options?: AgilityOptions): Promise<HybridDsseResult>;
export {};
//# sourceMappingURL=gate-qualification.d.ts.map