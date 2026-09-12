import { type RiskHybridSigner, type RiskRecord, type RiskV2Options, type TrustedRiskKeysV2 } from './reliance-risk-crypto.js';
export declare const ACTION_RISK_CONTROL_SCHEDULE_VERSION = "EP-ACTION-RISK-CONTROL-SCHEDULE-v1";
export declare const ACTION_RISK_QUALIFICATION_STATUS_VERSION = "EP-ACTION-RISK-QUALIFICATION-STATUS-v1";
export declare const ACTION_RISK_CONTROL_EVALUATION_VERSION = "EP-ACTION-RISK-CONTROL-EVALUATION-v1";
export declare const ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY = "technical_control_requirements_only_not_policy_coverage_premium_liability_action_authorization_or_effect_proof";
export declare const ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY = "technical_qualification_observation_only_not_policy_coverage_premium_liability_or_action_authorization";
export declare const ACTION_RISK_CONTROL_OUTCOMES: readonly ["ELIGIBLE", "NOT_ELIGIBLE", "INDETERMINATE"];
export type ActionRiskControlOutcome = typeof ACTION_RISK_CONTROL_OUTCOMES[number];
export declare const ACTION_RISK_INDETERMINATE_HANDLING = "REFUSE_RETRY_PRESERVE_OPEN_EXPOSURE_REQUIRE_RECONCILIATION";
export declare const ACTION_RISK_DIVERGENT_HANDLING = "REFUSE_CLOSEOUT_PRESERVE_OPEN_EXPOSURE_ESCALATE";
export interface ActionRiskControlScheduleSigner extends RiskHybridSigner {
}
export interface ActionRiskQualificationStatusSigner extends RiskHybridSigner {
}
export interface ActionRiskControlScheduleEvaluationOptions extends RiskV2Options {
    trusted_schedule_keys?: TrustedRiskKeysV2;
    trusted_status_keys?: TrustedRiskKeysV2;
    expected_schedule_id?: string;
    expected_issuer_id?: string;
    expected_relying_party_id?: string;
    expected_tenant_id?: string;
    observed_controls?: unknown;
    qualification_status?: unknown;
    /** Relying-party-owned durable last-seen status head. */
    qualification_status_head?: unknown;
    now?: string | number | Date;
}
export declare class ActionRiskControlScheduleValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
/** Canonical digest committed by a trust-pin reference for one hybrid key set. */
export declare function actionRiskHybridTrustPinDigest(keyId: string, pin: {
    issuer_id: string;
    public_key: string;
    pq_public_key: string;
}): string;
/** Digest of the complete hybrid-signed schedule, including both signatures. */
export declare function actionRiskControlScheduleDigest(artifact: unknown): string;
/** Digest of the complete hybrid-signed qualification status. */
export declare function actionRiskQualificationStatusDigest(artifact: unknown): string;
/** Mint the closed hybrid Ed25519 + ML-DSA-65 schedule. */
export declare function signActionRiskControlSchedule(input: unknown, signer: ActionRiskControlScheduleSigner, options?: RiskV2Options): Promise<RiskRecord>;
/** Mint an independently signed qualification observation for one schedule. */
export declare function signActionRiskQualificationStatus(input: unknown, signer: ActionRiskQualificationStatusSigner, options?: RiskV2Options): Promise<RiskRecord>;
/**
 * Verify and evaluate a schedule under caller-supplied trust roots and exact
 * runtime control observations. Only ELIGIBLE is a positive technical result.
 * Every result has authorizes_action=false: the caller's authorization check
 * remains a distinct step even when all scheduled controls are observed.
 */
export declare function evaluateActionRiskControlSchedule(artifact: unknown, options?: ActionRiskControlScheduleEvaluationOptions): Promise<RiskRecord>;
//# sourceMappingURL=action-risk-control-schedule.d.ts.map