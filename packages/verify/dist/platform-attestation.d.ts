export declare const EP_PLATFORM_ATTESTATION_VERSION = "EP-PLATFORM-ATTESTATION-v1";
export declare const EP_PLATFORM_ATTESTATION_PROFILE = "tag:emiliaprotocol.ai,2026:platform-attestation/eat-jwt/v1";
export declare const EP_PLATFORM_ATTESTATION_COMPONENT = "ep-platform-attestation";
export interface PlatformAttestationOptions {
    trustedAttesters: Record<string, Record<string, string>>;
    expectedProfile: string;
    expectedAudience: string;
    expectedNonce: string;
    expectedActionDigest: string;
    referenceMeasurements: string[];
    verificationTime: string;
    maxAgeSeconds: number;
}
export interface PlatformAttestationResult {
    valid: boolean;
    action_digest: string | null;
    detail: {
        reason: string | null;
        profile?: string;
        issuer?: string;
        key_id?: string;
        build_measurement?: string;
        profile_alignment?: 'RFC9334-attestation-result/RFC9711-EAT-JWT';
        hardware_verified?: false;
    };
}
/**
 * Verify one EP platform-attestation component. This is a fail-closed boundary:
 * malformed objects, hostile accessors, invalid policy, or crypto errors all
 * return a denial result and never escape as an exception.
 */
export declare function verifyPlatformAttestation(evidence: unknown, options: PlatformAttestationOptions): PlatformAttestationResult;
//# sourceMappingURL=platform-attestation.d.ts.map