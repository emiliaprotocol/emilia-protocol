import { type RiskHybridSigner, type RiskRecord, type RiskV2Options, type TrustedRiskKeys, type TrustedRiskKeysV2 } from './reliance-risk-crypto.js';
export declare const LOSS_ALLOCATION_SCHEDULE_VERSION = "EP-LOSS-ALLOCATION-SCHEDULE-v1";
export declare const LOSS_ALLOCATION_SCHEDULE_CLAIM_BOUNDARY = "signed_terms_not_legal_liability_adjudication_enforceability_insurance_coverage_solvency_authorization_or_payment";
export interface LossAllocationProgramBinding {
    program_id: string;
    version: number;
    source_digest: string;
    program_digest: string;
}
export interface LossAllocationStatusResult {
    outcome: 'current_not_revoked' | 'revoked' | 'unavailable';
    target_digest: string;
}
export interface VerifyLossAllocationScheduleOptions {
    trusted_keys?: TrustedRiskKeys;
    expected_relying_party_id?: string;
    expected_program?: LossAllocationProgramBinding;
    status?: LossAllocationStatusResult;
    now?: string | number | Date;
}
export interface LossAllocationSigner {
    issuer_id: string;
    key_id: string;
    private_key: any;
}
export declare class LossAllocationScheduleValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/** Digest of the complete signed artifact, including its proof. */
export declare function lossAllocationScheduleDigest(artifact: unknown): string;
/** Digest of the exact versioned failure-class rules, excluding program pins. */
export declare function lossAllocationRulesDigest(artifact: unknown): string;
/**
 * Compact digest pin for an RP-owned Admissibility Profile. Status remains a
 * separate required input; this reference does not claim global freshness.
 */
export declare function lossAllocationScheduleProfileReference(artifact: unknown): RiskRecord;
/** Sign a closed schedule under the shared JCS/Ed25519 risk-artifact proof. */
export declare function signLossAllocationSchedule(input: unknown, signer: LossAllocationSigner): RiskRecord;
/** Verify signature, RP/program pins, external current status, and validity. */
export declare function verifyLossAllocationSchedule(artifact: unknown, options?: VerifyLossAllocationScheduleOptions): RiskRecord;
/**
 * Build a standard self-hashed Admissibility Profile and its unchanged
 * Reliance Program v1 profile reference. Only schedule identity, RP, issuer,
 * and exact rules are pinned here; final program digests are deliberately
 * excluded to avoid a profile/program/schedule digest cycle.
 */
export declare function createLossAllocationAdmissibilityProfilePin(artifact: unknown, { profileId, evaluationMaxAgeSec, }: {
    profileId: string;
    evaluationMaxAgeSec: number;
}, verification: VerifyLossAllocationScheduleOptions): RiskRecord;
export declare const LOSS_ALLOCATION_SCHEDULE_V2_VERSION = "EP-LOSS-ALLOCATION-SCHEDULE-v2";
export interface LossAllocationSignerV2 extends RiskHybridSigner {
}
export interface VerifyLossAllocationScheduleOptionsV2 extends RiskV2Options {
    trusted_keys?: TrustedRiskKeysV2;
    expected_relying_party_id?: string;
    expected_program?: LossAllocationProgramBinding;
    status?: LossAllocationStatusResult;
    now?: string | number | Date;
}
/** Mint the hybrid (Ed25519 + ML-DSA-65), set-committed twin of signLossAllocationSchedule. */
export declare function signLossAllocationScheduleV2(input: unknown, signer: LossAllocationSignerV2, options?: RiskV2Options): Promise<RiskRecord>;
/**
 * FAIL-CLOSED hybrid verify, the set-committed twin of verifyLossAllocationSchedule.
 * A v2 schedule NEVER verifies on one leg alone; an absent ML-DSA backend is a
 * refusal, never a skipped check and never a pass on the surviving classical leg.
 */
export declare function verifyLossAllocationScheduleV2(artifact: unknown, options?: VerifyLossAllocationScheduleOptionsV2): Promise<RiskRecord>;
//# sourceMappingURL=loss-allocation-schedule.d.ts.map