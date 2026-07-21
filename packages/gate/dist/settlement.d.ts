export declare const SETTLEMENT_PROFILE_VERSION = "EP-GATE-SETTLEMENT-PROFILE-v1";
export declare const SETTLEMENT_RESULT_VERSION = "EP-GATE-SETTLEMENT-RESULT-v1";
export declare const SETTLEMENT_VERDICTS: readonly string[];
export declare function settlementProfileDigest(profile: any): string;
/**
 * Evaluate a raw evidence bundle. Authorization, execution, outcome, and
 * coverage are interpreted only by verifier functions pinned in code by the
 * relying party; no artifact may select its own verifier.
 */
export declare function evaluateSettlementEligibility(bundle?: {}, options?: {
    profile?: Record<string, any>;
    verifyAuthorization?: (...args: any[]) => any;
    verifyExecution?: (...args: any[]) => any;
    verifyOutcome?: (...args: any[]) => any;
    verifyCoverage?: (...args: any[]) => any;
    pinnedWitnesses?: any[];
    trustedWitnessAcceptance?: Record<string, any>;
    witnessSequenceStore?: Record<string, any>;
    allowEphemeralWitnessStore?: boolean;
    now?: number | (() => number);
    witnessMaxAgeSec?: number;
    maxFutureSkewSec?: number;
}): Promise<Readonly<{
    result_hash: `sha256:${string}`;
    '@version': string;
    verdict: any;
    eligible: boolean;
    reason: any;
    profile_hash: any;
    action_digest: null;
    checks: any;
    limitations: string[];
}> | Readonly<{
    result_hash: `sha256:${string}`;
    '@version': string;
    verdict: string;
    eligible: boolean;
    reason: null;
    profile_hash: string;
    action_digest: any;
    evidence: {
        coverage_report_hash?: any;
        surface_id?: any;
        outcome_digest?: any;
        witness_digest?: any;
        authorization_digest: any;
        execution_digest: any;
    };
    checks: {
        profile: boolean;
        authorization: boolean;
        execution: boolean;
        witness: boolean;
        outcome: boolean;
        coverage: boolean;
        digest_join: boolean;
    };
    limitations: string[];
}>>;
declare const _default: {
    SETTLEMENT_PROFILE_VERSION: string;
    SETTLEMENT_RESULT_VERSION: string;
    SETTLEMENT_VERDICTS: readonly string[];
    settlementProfileDigest: typeof settlementProfileDigest;
    evaluateSettlementEligibility: typeof evaluateSettlementEligibility;
};
export default _default;
//# sourceMappingURL=settlement.d.ts.map