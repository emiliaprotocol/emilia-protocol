export declare const COVERAGE_INVENTORY_VERSION = "EP-GATE-COVERAGE-INVENTORY-v1";
export declare const COVERAGE_REPORT_VERSION = "EP-GATE-COVERAGE-REPORT-v1";
export declare const ENFORCEMENT_PROBE_VERSION = "EP-GATE-ENFORCEMENT-PROBE-v1";
export declare const COVERAGE_STATES: readonly string[];
export declare const PROBE_RESULTS: readonly string[];
export declare function coverageInventoryDigest(inventory: any): string;
export declare function signEnforcementProbe(input: any, privateKey: any): Readonly<{
    signature: Readonly<{
        algorithm: "Ed25519";
        key_id: any;
        statement_digest: string;
        signature_b64u: string;
    }>;
    '@version': string;
    probe: {
        id: any;
        key_id: any;
    };
    test: {
        surface_id: any;
        gate_id: any;
        environment_id: any;
        action_family: any;
        action_digest: any;
        tested_at: any;
        nonce: any;
        result: any;
        response_status: any;
    };
}>;
/** Duplicate-key-safe parser for an untrusted serialized probe artifact. */
export declare function parseEnforcementProbeStatement(raw: any, { maxBytes }?: {
    maxBytes?: number | undefined;
}): any;
type ProbeRefusal = {
    accepted: false;
    verified: false;
    reason: string;
    statement_digest?: undefined;
    tested_at?: undefined;
    result?: undefined;
    response_status?: undefined;
    nonce?: undefined;
    surface_id?: undefined;
    action_digest?: undefined;
    gate_id?: undefined;
    environment_id?: undefined;
    action_family?: undefined;
    probe_id?: undefined;
};
type ProbeAcceptance = {
    accepted: true;
    verified: true;
    reason: null;
    statement_digest: string;
    tested_at: any;
    result: any;
    response_status: any;
    nonce: any;
    surface_id: any;
    action_digest: any;
    gate_id: any;
    environment_id: any;
    action_family: any;
    probe_id: any;
};
type ProbeVerificationResult = ProbeAcceptance | ProbeRefusal;
export declare function verifyEnforcementProbe(statement: any, options?: {
    pinnedProbes?: any;
    expectedSurface?: any;
    now?: number;
    maxAgeSec?: number;
    maxFutureSkewSec?: number;
}): ProbeVerificationResult;
type CoverageSurfaceRow = {
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
};
type CoverageFailureReport = {
    '@version': string;
    complete: boolean;
    reason: string;
    inventory_hash: string | null;
    surfaces: CoverageSurfaceRow[];
    counts: Record<string, number>;
    report_hash?: undefined;
    generated_at?: undefined;
    inventory_id?: undefined;
    declared_required_surfaces?: undefined;
    complete_required_surfaces?: undefined;
    declared_coverage_bps?: undefined;
    limitations?: undefined;
};
type CoverageSuccessReport = {
    '@version': string;
    generated_at: string;
    inventory_id: any;
    inventory_hash: string;
    complete: boolean;
    declared_required_surfaces: number;
    complete_required_surfaces: number;
    declared_coverage_bps: number;
    counts: Record<string, number>;
    surfaces: CoverageSurfaceRow[];
    limitations: string[];
    report_hash: string;
    reason?: undefined;
};
type CoverageReport = CoverageFailureReport | CoverageSuccessReport;
/**
 * Evaluate coverage of a relying-party-declared inventory. Inventory
 * completeness remains an explicit external assumption and is never inferred.
 */
export declare function evaluateGateCoverage(input?: {
    inventory?: any;
    deployments?: any[];
    probes?: any[];
    witnesses?: any[];
}, options?: {
    now?: number;
    attestationVerifiers?: any;
    pinnedProbes?: any;
    pinnedWitnesses?: any;
    expectedProbeNonces?: any;
    probeMaxAgeSec?: number;
    witnessMaxAgeSec?: number;
    maxFutureSkewSec?: number;
    witnessSequenceStore?: any;
    allowEphemeralWitnessStore?: boolean;
    trustedWitnessAcceptances?: any[];
}): Promise<CoverageReport>;
declare const _default: {
    COVERAGE_INVENTORY_VERSION: string;
    COVERAGE_REPORT_VERSION: string;
    ENFORCEMENT_PROBE_VERSION: string;
    COVERAGE_STATES: readonly string[];
    PROBE_RESULTS: readonly string[];
    coverageInventoryDigest: typeof coverageInventoryDigest;
    parseEnforcementProbeStatement: typeof parseEnforcementProbeStatement;
    signEnforcementProbe: typeof signEnforcementProbe;
    verifyEnforcementProbe: typeof verifyEnforcementProbe;
    evaluateGateCoverage: typeof evaluateGateCoverage;
};
export default _default;
//# sourceMappingURL=coverage.d.ts.map