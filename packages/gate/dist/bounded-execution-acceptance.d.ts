/**
 * Relying-party acceptance over one signed bounded-execution report.
 *
 * A bounded execution program says what MAY execute. This profile says which
 * Gate-recorded terminal outcomes a relying party requires before it accepts
 * the recorded process as complete. It never concludes legal compliance,
 * external effect truth, process safety, or complete mediation.
 */
import { type BoundedExecutionReportVerificationContext } from './bounded-execution-report.js';
import { type RiskHybridSigner, type RiskRecord, type RiskV2Options, type TrustedRiskKeys, type TrustedRiskKeysV2 } from './reliance-risk-crypto.js';
export declare const BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_VERSION = "EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1";
export declare const BOUNDED_EXECUTION_EVIDENCE_PACK_VERSION = "EP-BOUNDED-EXECUTION-EVIDENCE-PACK-v1";
export declare const BOUNDED_EXECUTION_ACCEPTANCE_CLAIM_BOUNDARY = "rp_acceptance_of_gate_recorded_program_outcomes_only_not_legal_compliance_not_external_effect_truth_not_program_safety_not_complete_mediation";
export type BoundedExecutionAcceptanceVerdict = 'RECORDED_PROCESS_ACCEPTED' | 'RECORDED_PROCESS_NOT_ACCEPTED' | 'INDETERMINATE';
export interface BoundedExecutionAcceptanceProfileInput {
    profile_id: string;
    relying_party_id: string;
    program_id: string;
    program_version: number;
    program_digest: string;
    valid_from: string;
    expires_at: string;
    accepted_program_statuses: string[];
    max_total_unresolved: number;
    max_total_reserved: number;
    required_nodes: Array<{
        node_id: string;
        min_terminal_occurrences: number;
        accepted_outcomes: string[];
        allow_additional_terminal_outcomes: boolean;
    }>;
}
export interface BoundedExecutionAcceptanceProfileContext {
    trusted_keys: TrustedRiskKeys;
    expected_profile_id: string;
    expected_relying_party_id: string;
    expected_program_id: string;
    expected_program_version: number;
    expected_program_digest: string;
    now: string;
}
export declare class BoundedExecutionAcceptanceValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
export interface BoundedExecutionAcceptanceProfileContextV2 extends RiskV2Options {
    trusted_keys: TrustedRiskKeysV2;
    expected_profile_id: string;
    expected_relying_party_id: string;
    expected_program_id: string;
    expected_program_version: number;
    expected_program_digest: string;
    now: string;
}
export declare function signBoundedExecutionAcceptanceProfile(input: unknown, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function verifyBoundedExecutionAcceptanceProfile(artifact: unknown, rawContext?: BoundedExecutionAcceptanceProfileContext): RiskRecord;
export declare const BOUNDED_EXECUTION_ACCEPTANCE_PROFILE_V2_VERSION = "EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v2";
export interface BoundedExecutionAcceptanceProfileSignerV2 extends RiskHybridSigner {
}
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of signBoundedExecutionAcceptanceProfile. */
export declare function signBoundedExecutionAcceptanceProfileV2(input: unknown, signer: BoundedExecutionAcceptanceProfileSignerV2, options?: RiskV2Options): Promise<RiskRecord>;
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of
 * verifyBoundedExecutionAcceptanceProfile. A v2 profile NEVER verifies on one
 * leg alone; an absent ML-DSA backend is a refusal, never a skipped check and
 * never a pass on the surviving classical leg.
 */
export declare function verifyBoundedExecutionAcceptanceProfileV2(artifact: unknown, rawContext?: BoundedExecutionAcceptanceProfileContextV2): Promise<RiskRecord>;
export declare function evaluateBoundedExecutionAcceptance(profileArtifact: unknown, profileContext: BoundedExecutionAcceptanceProfileContext | undefined, reportArtifact: unknown, reportContext?: BoundedExecutionReportVerificationContext): RiskRecord;
export declare function buildBoundedExecutionEvidencePack(input: unknown): RiskRecord;
export declare function verifyBoundedExecutionEvidencePack(artifact: unknown, context?: {
    profile_context: BoundedExecutionAcceptanceProfileContext;
    report_context: BoundedExecutionReportVerificationContext;
}): RiskRecord;
//# sourceMappingURL=bounded-execution-acceptance.d.ts.map