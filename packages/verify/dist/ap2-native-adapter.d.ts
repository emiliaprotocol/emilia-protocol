/**
 * Experimental AP2 Agent Authorization adapter for AEB.
 *
 * The AP2 mandate remains the native artifact. This adapter does not mint an
 * EMILIA receipt or claim that EMILIA originated the authorization. A
 * relying-party-pinned AP2 implementation verifies the native artifact and
 * returns its native replay identity plus an exact normalized action. AEB
 * then records the verification result and joins it to the executor's CAID.
 */
import { type AebAdapter, type AebDigest, type AebEvidenceSubject } from './aeb-adapter-contract.js';
export declare const AP2_NATIVE_AEB_ADAPTER_ID = "native:ap2-agent-authorization";
export declare const AP2_NATIVE_AEB_ADAPTER_VERSION = "experimental-1";
export declare const AP2_NATIVE_AEB_CONFIG_VERSION = "EP-AP2-NATIVE-AEB-CONFIG-v1";
export interface Ap2NativeVerifierDescriptor {
    id: string;
    version: string;
    implementation_digest: AebDigest;
}
export interface Ap2NativeVerificationResult {
    verified: boolean;
    accepted: boolean;
    native_artifact_digest: AebDigest;
    replay_unit: AebDigest;
    evidence_role: string;
    subject: AebEvidenceSubject;
    normalized_action: unknown;
    action_digest: AebDigest;
    reasons: string[];
}
export interface Ap2NativeVerifier extends Ap2NativeVerifierDescriptor {
    /** Pure native AP2 verification. No network or ambient trust is permitted. */
    verify(input: Readonly<{
        artifact: unknown;
        artifact_ref: string;
        trust_roots: readonly unknown[];
        expected_action: unknown;
        now: string;
    }>): Ap2NativeVerificationResult;
}
export declare function createAp2NativeAebAdapter(verifier: Ap2NativeVerifier): AebAdapter;
//# sourceMappingURL=ap2-native-adapter.d.ts.map