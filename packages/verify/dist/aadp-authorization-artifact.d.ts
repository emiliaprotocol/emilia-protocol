/**
 * Profile-neutral authorization-artifact hook for AADP compositions.
 *
 * The hook records what an AADP deployment natively verified. It is evidence,
 * not an AADP approval, permit, obligation, provider key, or authorization
 * decision. The EP helper below is one profile that derives the hook from a
 * verified Authorization Bundle and a relying-party-pinned action mapping.
 */
import { type AuthorizationBundleVerificationOptions } from './authorization-bundle.js';
import { type AebDigest } from './aeb-adapter-contract.js';
export declare const AADP_AUTHORIZATION_ARTIFACT_VERSION = "AADP-AUTHORIZATION-ARTIFACT-v1";
export declare const AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE = "EP-AADP-AUTHORIZATION-ARTIFACT-v1";
export interface AadpAuthorizationArtifact {
    profile: typeof AADP_AUTHORIZATION_ARTIFACT_VERSION;
    artifact_profile: string;
    artifact_digest: AebDigest;
    verification_outcome: 'verified' | 'not_satisfying' | 'not_reachable';
    action_mapping_profile: string;
    action_digest: AebDigest;
}
export type AadpAuthorizationArtifactMatchVerdict = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export interface AadpAuthorizationArtifactMatchResult {
    verdict: AadpAuthorizationArtifactMatchVerdict;
    artifact: AadpAuthorizationArtifact | null;
    reason: string | null;
}
export interface AadpAction {
    action_type: string;
    params: Record<string, unknown>;
}
export interface DeriveAadpEpAuthorizationArtifactInput {
    bundle: unknown;
    artifactReferenceDigest?: AebDigest;
    aadpAction: unknown;
    actionMappingProfile: string;
    mapAction: (action: AadpAction) => unknown;
    bundleOptions: Omit<AuthorizationBundleVerificationOptions, 'expectedAction'>;
}
export interface AadpEpAuthorizationArtifactResult {
    verdict: 'VERIFIED' | 'REFUSE' | 'INDETERMINATE';
    artifact: AadpAuthorizationArtifact | null;
    mapped_action: unknown | null;
    authorization_decision: false;
    reasons: string[];
}
/** Return a safe normalized copy of the closed, profile-neutral hook. */
export declare function parseAadpAuthorizationArtifact(value: unknown): AadpAuthorizationArtifact | null;
/**
 * Compare a presented AADP hook with one independently derived by the PDP.
 * Missing native verification is indeterminate. Malformed or unequal
 * presenter input is a hard mismatch.
 */
export declare function matchAadpAuthorizationArtifact(presented: unknown, expected: unknown): AadpAuthorizationArtifactMatchResult;
/**
 * Derive the generic AADP hook from an EP Authorization Bundle.
 *
 * `mapAction` and `actionMappingProfile` are relying-party configuration. They
 * are never read from the presenter. The underlying Bundle verifier still
 * requires pinned approver keys, a local audience, current policy, a fresh
 * authorization instance, and every other native EP verification input.
 */
export declare function deriveAadpEpAuthorizationArtifact(input: DeriveAadpEpAuthorizationArtifactInput): AadpEpAuthorizationArtifactResult;
/** Derive the native EP hook and compare it to a presenter-supplied AADP hook. */
export declare function verifyAadpEpAuthorizationArtifact(presented: unknown, input: DeriveAadpEpAuthorizationArtifactInput): AadpEpAuthorizationArtifactResult;
declare const _default: Readonly<{
    AADP_AUTHORIZATION_ARTIFACT_VERSION: "AADP-AUTHORIZATION-ARTIFACT-v1";
    AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE: "EP-AADP-AUTHORIZATION-ARTIFACT-v1";
    parseAadpAuthorizationArtifact: typeof parseAadpAuthorizationArtifact;
    matchAadpAuthorizationArtifact: typeof matchAadpAuthorizationArtifact;
    deriveAadpEpAuthorizationArtifact: typeof deriveAadpEpAuthorizationArtifact;
    verifyAadpEpAuthorizationArtifact: typeof verifyAadpEpAuthorizationArtifact;
}>;
export default _default;
//# sourceMappingURL=aadp-authorization-artifact.d.ts.map