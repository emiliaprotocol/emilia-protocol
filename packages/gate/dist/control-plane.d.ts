export declare const CONTROL_PLANE_REPORT_VERSION = "EP-GATE-CONTROL-PLANE-REPORT-v1";
export declare const CONTROL_PLANE_MAX_SETTLEMENTS = 10000;
/**
 * Produce one reproducible control-plane view. The signed/verified subartifacts
 * remain independently portable; this report joins only their digests and
 * closed verdicts.
 */
export declare function evaluateGateControlPlane(input?: {
    settlements?: any[];
    coverage?: Record<string, any>;
    usage?: any;
}, options?: {
    now?: number;
    coverageInventory?: any;
    settlementProfile?: any;
    pinnedProbes?: any;
    pinnedWitnesses?: any;
    expectedProbeNonces?: any;
    probeMaxAgeSec?: number;
    witnessMaxAgeSec?: number;
    maxFutureSkewSec?: number;
    allowEphemeralWitnessStore?: boolean;
    trustedWitnessAcceptances?: any[];
    attestationVerifiers?: any;
    witnessSequenceStore?: any;
    verifyAuthorization?: any;
    verifyExecution?: any;
    verifyOutcome?: any;
}): Promise<Readonly<{
    control_plane_digest: string;
    artifacts: Readonly<{
        coverage: {
            '@version': string;
            complete: boolean;
            reason: string;
            inventory_hash: string | null;
            surfaces: {
                surface_id: any;
                action_family: any;
                required: any;
                state: string;
                reason: string;
                deployment_attested: boolean;
                refusal_probe_verified: boolean;
                bypass_probe_verified: boolean;
                probe_nonce_verified: boolean;
                witness_required: boolean;
                witness_verified: boolean;
                witness_acceptance_reason: any;
                complete: boolean;
            }[];
            counts: Record<string, number>;
            report_hash?: undefined;
            generated_at?: undefined;
            inventory_id?: undefined;
            declared_required_surfaces?: undefined;
            complete_required_surfaces?: undefined;
            declared_coverage_bps?: undefined;
            limitations?: undefined;
        } | {
            '@version': string;
            generated_at: string;
            inventory_id: any;
            inventory_hash: string;
            complete: boolean;
            declared_required_surfaces: number;
            complete_required_surfaces: number;
            declared_coverage_bps: number;
            counts: Record<string, number>;
            surfaces: {
                surface_id: any;
                action_family: any;
                required: any;
                state: string;
                reason: string;
                deployment_attested: boolean;
                refusal_probe_verified: boolean;
                bypass_probe_verified: boolean;
                probe_nonce_verified: boolean;
                witness_required: boolean;
                witness_verified: boolean;
                witness_acceptance_reason: any;
                complete: boolean;
            }[];
            limitations: string[];
            report_hash: string;
            reason?: undefined;
        };
        settlements: any[];
        usage: {
            content_hash: string;
            '@version': string;
            kind: string;
            org: string;
            period: {
                start: any;
                end: any;
                bounds: string;
            };
            protected_actions: any;
            allows: any;
            denies: any;
            replays_blocked: any;
            by_action_type: {};
            by_tier: {};
            receipt_years: any;
            retention_years_default: any;
            integrity_warning_count: any;
            complete: boolean;
        } | null;
    }>;
    limitations: string[];
    usage_error?: string | undefined;
    settlement_error?: string | undefined;
    configuration_error?: string | undefined;
    '@version': string;
    generated_at: string;
    coverage_report_hash: string | null;
    coverage_complete: boolean;
    settlement_input_complete: boolean;
    settlement_results: {
        action_digest: any;
        verdict: any;
        eligible: boolean;
        result_hash: any;
    }[];
    usage_statement_hash: string | null;
    usage_complete: boolean;
}>>;
declare const _default: {
    CONTROL_PLANE_REPORT_VERSION: string;
    CONTROL_PLANE_MAX_SETTLEMENTS: number;
    evaluateGateControlPlane: typeof evaluateGateControlPlane;
};
export default _default;
//# sourceMappingURL=control-plane.d.ts.map