/**
 * Canonical relying-party report over one verified bounded execution program.
 *
 * The report authenticates a Gate runtime snapshot and a supplied inventory of
 * Gate-recorded program occurrences. It is not evidence of external effect
 * truth, program safety, complete mediation, or activity outside Gate.
 */
import { type ExecutionProgramReportSnapshot } from './admission-store.js';
import { EXECUTION_PROGRAM_CLAIM_BOUNDARY, type VerifiedBoundedExecutionProgram } from './bounded-execution-program.js';
import { type RiskRecord, type RiskV2Options, type TrustedRiskKeys, type TrustedRiskKeysV2 } from './reliance-risk-crypto.js';
export declare const BOUNDED_EXECUTION_REPORT_VERSION = "EP-BOUNDED-EXECUTION-REPORT-v1";
export declare const BOUNDED_EXECUTION_REPORT_V2_VERSION = "EP-BOUNDED-EXECUTION-REPORT-v2";
export declare const BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY = "gate_recorded_program_occurrences_only_not_external_effect_truth_not_program_safety_not_complete_mediation_not_absence_of_outside_gate_actions";
export declare const BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM = "EXECUTED_OUTSIDE_THE_PLAN_NOT_CLAIMED_REQUIRES_SEPARATELY_SIGNED_EXTERNAL_INVENTORY_ROOT";
export interface BoundedExecutionReportSigner {
    relying_party_id: string;
    key_id: string;
    private_key: any;
}
export interface VerifiedBoundedExecutionProgramResult {
    accepted: true;
    verified: true;
    reason: null;
    program_digest: string;
    program: Readonly<VerifiedBoundedExecutionProgram>;
    authorizer_id: string;
    claim_boundary: typeof EXECUTION_PROGRAM_CLAIM_BOUNDARY;
}
export interface BoundedExecutionReportInput {
    report_id: string;
    relying_party_id: string;
    report_interval: {
        start: string;
        end: string;
    };
    generated_at: string;
    verified_program: VerifiedBoundedExecutionProgramResult;
    report_snapshot: Readonly<ExecutionProgramReportSnapshot>;
}
export interface BoundedExecutionReportVerificationContext {
    trusted_keys: TrustedRiskKeys;
    expected_report_id: string;
    expected_relying_party_id: string;
    expected_tenant_id: string;
    expected_program_id: string;
    expected_program_version: number;
    expected_program_digest: string;
    expected_subject_id: string;
    expected_audience: string;
    expected_report_interval: {
        start: string;
        end: string;
    };
    expected_runtime_state_digest: string;
    expected_occurrence_inventory_digest: string;
    expected_report_snapshot_marker: string;
    now: string;
    max_report_age_ms: number;
}
export declare class BoundedExecutionReportValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/** Digest of the complete normalized ExecutionProgramRuntimeState. */
export declare function boundedExecutionRuntimeStateDigest(state: unknown): string;
/** Digest of every supplied full occurrence record in deterministic order. */
export declare function boundedExecutionOccurrenceInventoryDigest(occurrences: unknown): string;
/** Digest of the complete signed report, including its Ed25519 proof. */
export declare function boundedExecutionReportDigest(artifact: unknown): string;
export interface BoundedExecutionReportHybridSigner {
    relying_party_id: string;
    key_id: string;
    private_key: any;
    pq_private_key: Uint8Array | string;
}
/** Build and sign one closed report from an accepted program verification result. */
export declare function signBoundedExecutionReport(rawInput: BoundedExecutionReportInput | RiskRecord, rawSigner: BoundedExecutionReportSigner): RiskRecord;
/**
 * EP-BOUNDED-EXECUTION-REPORT-v2 -- the hybrid (Ed25519 + ML-DSA-65) report.
 *
 * Reference: "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2) in
 * docs/protocol/pq-hybrid-program.md. VERSION BUMP, not a field bump: the -v2
 * marker carries the set-committed hybrid proof through signRiskBodyV2, while
 * signBoundedExecutionReport keeps its flat single-Ed25519 proof unchanged. A
 * deployed v1 verifier handed a v2 report refuses on its version/envelope check
 * before inspecting any signature. ASYNC because ML-DSA signing is async.
 */
export declare function signBoundedExecutionReportV2(rawInput: BoundedExecutionReportInput | RiskRecord, rawSigner: BoundedExecutionReportHybridSigner, options?: RiskV2Options): Promise<RiskRecord>;
/** Verify signature, closed schema, RP pin, complete expected tuple, and freshness. */
export declare function verifyBoundedExecutionReport(artifact: unknown, rawContext?: BoundedExecutionReportVerificationContext): RiskRecord;
export interface BoundedExecutionReportV2VerificationContext extends Omit<BoundedExecutionReportVerificationContext, 'trusted_keys'> {
    trusted_keys: TrustedRiskKeysV2;
}
/**
 * EP-BOUNDED-EXECUTION-REPORT-v2 verifier. FAIL-CLOSED hybrid twin of
 * verifyBoundedExecutionReport: verifies the Ed25519 + ML-DSA-65 signature set,
 * then applies the identical closed schema, RP pin, expected-tuple, and
 * freshness checks. A v2 report NEVER verifies on one leg alone. ASYNC because
 * ML-DSA verification is async. See "PATTERN: the reference hybrid migration"
 * in docs/protocol/pq-hybrid-program.md.
 */
export declare function verifyBoundedExecutionReportV2(artifact: unknown, rawContext?: BoundedExecutionReportV2VerificationContext, options?: RiskV2Options): Promise<RiskRecord>;
//# sourceMappingURL=bounded-execution-report.d.ts.map