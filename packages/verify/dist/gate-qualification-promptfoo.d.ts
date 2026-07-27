export declare const PROMPTFOO_QUALIFICATION_ADAPTER_VERSION = "EP-GATE-QUALIFICATION-PROMPTFOO-ADAPTER-v1";
export declare const PROMPTFOO_QUALIFICATION_RUN_METADATA_VERSION = "EP-GATE-QUALIFICATION-PROMPTFOO-RUN-v1";
export declare const PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION = "EP-GATE-QUALIFICATION-EVALUATION-EVIDENCE-v2";
export declare const PROMPTFOO_QUALIFICATION_LIMITS: Readonly<{
    max_input_bytes: number;
    max_input_nodes: 65536;
    max_input_depth: 32;
    max_summary_results: 100000;
}>;
export type PromptfooQualificationDigest = `sha256:${string}`;
export type PromptfooQualificationStatus = 'PASS' | 'FAIL' | 'ERROR' | 'ABORTED' | 'EXPIRED';
export type PromptfooQualificationJson = null | boolean | string | number | PromptfooQualificationJson[] | {
    [key: string]: PromptfooQualificationJson;
};
export interface PromptfooQualificationManifestPin {
    id: string;
    immutable_ref: string;
    manifest: unknown;
    manifest_digest: PromptfooQualificationDigest;
}
export interface PromptfooQualificationCandidatePin extends PromptfooQualificationManifestPin {
    manifest: {
        provider_id: string;
        provider_revision: string;
        prompt_id: string;
        prompt_digest: PromptfooQualificationDigest;
    };
}
export interface PromptfooQualificationHarnessPin extends PromptfooQualificationManifestPin {
    config_digest: PromptfooQualificationDigest;
}
export interface PromptfooQualificationAttemptManifest {
    attempt_id: string;
    challenge_id: string;
    ordinal: number;
    challenge_digest: PromptfooQualificationDigest;
}
export interface PromptfooQualificationCampaignPin extends PromptfooQualificationManifestPin {
    manifest: {
        challenge_set_digest: PromptfooQualificationDigest;
        attempts: readonly PromptfooQualificationAttemptManifest[];
    };
}
export interface PromptfooQualificationVerifierPin {
    id: string;
    immutable_ref: string;
    trust_config: unknown;
    trust_config_digest: PromptfooQualificationDigest;
}
export interface PromptfooQualificationPins {
    '@version': typeof PROMPTFOO_QUALIFICATION_ADAPTER_VERSION;
    eval_id: string;
    artifact_ref: string;
    artifact_digest: PromptfooQualificationDigest;
    promptfoo_version: string;
    output_version: 3;
    candidate: PromptfooQualificationCandidatePin;
    assignment: PromptfooQualificationManifestPin;
    harness: PromptfooQualificationHarnessPin;
    environment: PromptfooQualificationManifestPin;
    challenge_campaign: PromptfooQualificationCampaignPin;
    verifier: PromptfooQualificationVerifierPin;
    quality_metrics: readonly string[];
    max_evidence_age_seconds: number;
}
export interface PromptfooQualificationAttemptEvidence {
    attempt_id: string;
    challenge_id: string;
    challenge_digest: PromptfooQualificationDigest;
    ordinal: number;
    status: PromptfooQualificationStatus;
    provider_id: string;
    prompt_id: string;
    started_at: string;
    completed_at: string;
    expired_at: string | null;
    failure: {
        reason: string;
        error: string | null;
    };
    payload_digests: {
        request: PromptfooQualificationDigest;
        response: PromptfooQualificationDigest | null;
        test_case: PromptfooQualificationDigest;
        grading: PromptfooQualificationDigest | null;
        result: PromptfooQualificationDigest;
    };
    measurements: {
        cost: number;
        latency_ms: number;
        score: number;
        named_scores: Record<string, number>;
        token_usage: PromptfooTokenUsage;
    };
}
export interface PromptfooTokenUsage {
    total: number;
    prompt: number;
    completion: number;
    cached: number;
}
export interface PromptfooQualificationEvidenceInput {
    '@version': typeof PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION;
    evidence_type: 'UPSTREAM_EVALUATION';
    authority: {
        classification: 'EVALUATION_ONLY';
        authorizes: false;
    };
    provider_identity: {
        provider_id: string;
        claimed_revision: string;
        authenticated_revision: null;
        pinning_strength: 'UNPINNABLE';
    };
    source: {
        system: 'promptfoo';
        adapter_version: typeof PROMPTFOO_QUALIFICATION_ADAPTER_VERSION;
        promptfoo_version: string;
        output_version: 3;
        eval_id: string;
        artifact_ref: string;
        artifact_digest: PromptfooQualificationDigest;
    };
    lineage: {
        candidate: FrozenManifestLineage;
        assignment: FrozenManifestLineage;
        harness: FrozenManifestLineage & {
            config_digest: PromptfooQualificationDigest;
        };
        environment: FrozenManifestLineage;
        challenge_campaign: FrozenManifestLineage;
    };
    timing: {
        started_at: string;
        completed_at: string;
        expires_at: string;
        evaluated_at: string;
    };
    coverage: {
        complete: true;
        expected: number;
        observed: number;
        passed: number;
        failed: number;
        errors: number;
        aborted: number;
        expired: number;
    };
    measurements: {
        cost_total: number;
        latency_ms_total: number;
        run_duration_ms: number | null;
        generation_duration_ms: number | null;
        evaluation_duration_ms: number | null;
        mean_score: number;
        named_score_means: Record<string, number>;
        token_usage: PromptfooTokenUsage;
    };
    attempts: readonly PromptfooQualificationAttemptEvidence[];
    verifier: {
        id: string;
        immutable_ref: string;
        trust_config: PromptfooQualificationJson;
        trust_config_digest: PromptfooQualificationDigest;
    };
}
export interface FrozenManifestLineage {
    id: string;
    immutable_ref: string;
    digest: PromptfooQualificationDigest;
    manifest: PromptfooQualificationJson;
}
export type PromptfooQualificationAdapterResult = {
    ok: true;
    evidence: PromptfooQualificationEvidenceInput;
} | {
    ok: false;
    reasons: string[];
};
export interface AdaptPromptfooQualificationOptions {
    artifact: unknown;
    pins: unknown;
    /** Trusted verifier time. Never taken from the artifact. */
    now: string;
}
/**
 * Canonical SHA-256 used for every adapter pin and derived payload binding.
 * It accepts finite JSON numbers because Promptfoo costs and quality scores are
 * commonly fractional.
 */
export declare function digestPromptfooQualification(value: unknown): PromptfooQualificationDigest;
/**
 * Re-derive the challenge digest represented by one Promptfoo result row.
 * The result's mutable outcome fields are intentionally excluded.
 */
export declare function promptfooQualificationChallengeDigest(row: unknown): PromptfooQualificationDigest;
/**
 * Convert a single content-pinned Promptfoo run into Qualification v2
 * evaluation evidence. Every refusal is fail-closed and no output of this
 * function is execution-authorizing.
 */
export declare function adaptPromptfooQualificationArtifact(options: AdaptPromptfooQualificationOptions): PromptfooQualificationAdapterResult;
//# sourceMappingURL=gate-qualification-promptfoo.d.ts.map