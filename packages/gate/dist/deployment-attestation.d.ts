export declare const DEPLOYMENT_PROFILE_VERSION = "EP-GATE-DEPLOYMENT-PROFILE-v1";
export declare const DEPLOYMENT_ATTESTATION_VERDICTS: readonly string[];
type DeploymentAttestationOptions = {
    profile?: Record<string, any>;
    verifiers?: Map<string, (...args: any[]) => any> | Record<string, any>;
    now?: number;
};
export declare function deploymentProfileDigest(profile: any): string;
/**
 * Verify deployment evidence under a relying-party-pinned profile.
 *
 * The selected verifier is taken from `profile.verifier_id`, which is a trusted
 * input. A presenter cannot select its own verifier by labeling the evidence.
 * The verifier returns normalized claims; this kernel independently compares
 * every context and measurement claim with the profile.
 */
export declare function verifyDeploymentAttestation(evidence: any, options?: DeploymentAttestationOptions): Promise<{
    reason: any;
    accepted: boolean;
    verified: boolean;
    verdict: string;
    profile_hash: string | null;
    checks: {
        profile: boolean;
        verifier: boolean;
        evidence: boolean;
        context: boolean;
        freshness: boolean;
        measurements: boolean;
    };
    verifier_id?: undefined;
    evidence_type?: undefined;
    gate_id?: undefined;
    environment_id?: undefined;
    issued_at?: undefined;
    expires_at?: undefined;
    measurements?: undefined;
    limitation?: undefined;
} | {
    reason: string;
    missing_measurements: string[];
    mismatched_measurements: string[];
    accepted: boolean;
    verified: boolean;
    verdict: string;
    profile_hash: string | null;
    checks: {
        profile: boolean;
        verifier: boolean;
        evidence: boolean;
        context: boolean;
        freshness: boolean;
        measurements: boolean;
    };
    verifier_id?: undefined;
    evidence_type?: undefined;
    gate_id?: undefined;
    environment_id?: undefined;
    issued_at?: undefined;
    expires_at?: undefined;
    measurements?: undefined;
    limitation?: undefined;
} | {
    accepted: boolean;
    verified: boolean;
    verdict: string;
    reason: null;
    profile_hash: string;
    verifier_id: any;
    evidence_type: any;
    gate_id: any;
    environment_id: any;
    issued_at: any;
    expires_at: any;
    measurements: any;
    checks: {
        profile: boolean;
        verifier: boolean;
        evidence: boolean;
        context: boolean;
        freshness: boolean;
        measurements: boolean;
    };
    limitation: string;
}>;
declare const _default: {
    DEPLOYMENT_PROFILE_VERSION: string;
    DEPLOYMENT_ATTESTATION_VERDICTS: readonly string[];
    deploymentProfileDigest: typeof deploymentProfileDigest;
    verifyDeploymentAttestation: typeof verifyDeploymentAttestation;
};
export default _default;
//# sourceMappingURL=deployment-attestation.d.ts.map