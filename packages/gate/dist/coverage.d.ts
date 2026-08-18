import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the probe:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the proof, a wire-format change, so the probe takes a new `@version`
 *    (EP-GATE-ENFORCEMENT-PROBE-v1 -> -v2). verifyEnforcementProbe() above is
 *    untouched: validateProbeBody(body) still defaults to the v1 version, so
 *    it refuses a v2 body's `@version` with `probe_version_invalid` before any
 *    signature inspection, and never throws.
 * 2. SET SHAPE. `signature` is replaced by `proof`, carrying
 *    `required_algorithms` plus a `signatures` array shaped exactly like
 *    EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (probeV2Bytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 probes keep verifying, unchanged, through
 *    verifyEnforcementProbe. v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point; verifyEnforcementProbeAny()
 *    routes on `@version`. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure path returns a named reason; nothing
 *    throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable', never a skipped check and never a pass on the
 *    classical leg alone.
 *
 * The pinned-probe catalog entry (found via probe_id + key_id, exactly as v1)
 * carries BOTH `public_key` and `pq_public_key` for a v2 probe; a pin missing
 * either half confers nothing. Coverage evaluation (evaluateGateCoverage)
 * remains v1-only here; a v2 probe must be verified through
 * verifyEnforcementProbeV2 (or the Any router) before its acceptance result is
 * folded into a coverage report by the caller.
 */
export declare const ENFORCEMENT_PROBE_V2_VERSION = "EP-GATE-ENFORCEMENT-PROBE-v2";
/** The registered required algorithm set, in canonical order. */
export declare const ENFORCEMENT_PROBE_V2_REQUIRED_ALGORITHMS: readonly string[];
/**
 * The bytes BOTH legs sign: the same body v1 signs (`@version`, `probe`,
 * `test`) plus the committed `required_algorithms` set, under the v2 domain
 * tag. Recomputed independently by the verifier from the PRESENTED body and
 * the REGISTERED set.
 */
export declare function probeV2Bytes(body: any, requiredAlgorithms?: readonly string[]): Buffer<ArrayBuffer>;
/** Mint a real hybrid probe statement. Throws on issuer misuse (never on caller input; there is none). */
export declare function signEnforcementProbeV2(input: any, signers: any, options?: AgilityOptions): Promise<Readonly<{
    proof: Readonly<{
        profile: "EP-GATE-ENFORCEMENT-PROBE-v2";
        required_algorithms: string[];
        key_id: any;
        signatures: import("@emilia-protocol/verify/pq-signature-agility").AgileSignature[];
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
}>>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-GATE-ENFORCEMENT-PROBE-v2. Never
 * throws on caller input; a v2 probe NEVER verifies on one leg alone.
 */
export declare function verifyEnforcementProbeV2(statement: any, options?: {
    pinnedProbes?: any;
    expectedSurface?: any;
    now?: number;
    maxAgeSec?: number;
    maxFutureSkewSec?: number;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<ProbeVerificationResult>;
/** Route a probe statement of EITHER version to its own verifier. */
export declare function verifyEnforcementProbeAny(statement: any, options?: any): Promise<ProbeVerificationResult>;
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