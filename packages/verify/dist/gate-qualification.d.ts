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
export {};
//# sourceMappingURL=gate-qualification.d.ts.map