export declare const RELIANCE_COMPILATION_RECORD_VERSION = "EP-RELIANCE-PROGRAM-COMPILATION-RECORD-v1";
export declare const RELIANCE_COMPILER_PROFILE = "EP-RELIANCE-PROGRAM-COMPILER-v1";
export declare const RELIANCE_COMPILATION_LIMITATIONS: readonly ["source_signature_does_not_establish_policy_truth_or_legal_effect", "compilation_does_not_authorize_or_execute_the_action", "native_evidence_and_outcome_require_separate_verification"];
export declare const RELIANCE_COMPILATION_CLAIM_BOUNDARY = "This record identifies one deterministic mapping from a verified Reliance Program source to a Gate Trust Program. It does not establish policy truth, legal sufficiency, authorization, provider entry, execution, or outcome.";
type JsonRecord = Record<string, any>;
export interface RelianceCompilationRecord {
    '@version': typeof RELIANCE_COMPILATION_RECORD_VERSION;
    compiler: {
        profile: typeof RELIANCE_COMPILER_PROFILE;
        compiled_artifact_version: string;
        target_program_version: string;
    };
    source: {
        digest: string;
        relying_party_id: string;
    };
    output: {
        program_digest: string;
        root_caid: string;
        action_digest: string;
        valid_from: string;
        expires_at: string;
        stage_count: number;
        requirement_count: number;
        consequence_mode: string;
    };
    trace: Array<{
        stage_id: string;
        requirement_id: string;
        profile_id: string;
        profile_hash: string;
    }>;
    limitations: string[];
    claim_boundary: string;
    record_digest: string;
}
export declare class RelianceCompilationRecordError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/**
 * Build an immutable, content-addressed review record from a compiler result.
 * The caller obtains `compiled` from compileRelianceProgram or
 * compileRelianceProgramV2; this function revalidates the complete result.
 */
export declare function createRelianceProgramCompilationRecord(compiled: unknown): RelianceCompilationRecord;
/**
 * Verify a record against an independently obtained compiler result. A caller
 * can recompile the signed source and profile catalog, then pass that fresh
 * result here. The verifier never treats the record itself as authority.
 */
export declare function verifyRelianceProgramCompilationRecord(record: unknown, compiled: unknown): JsonRecord;
/** Render the closed record as deterministic, institution-readable Markdown. */
export declare function renderRelianceProgramCompilationRecord(record: unknown): string;
export {};
//# sourceMappingURL=reliance-compilation-record.d.ts.map