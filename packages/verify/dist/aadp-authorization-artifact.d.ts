/**
 * Profile-neutral authorization-artifact hook for AADP compositions.
 *
 * This module records independently verified evidence. It never issues an
 * AADP wire verdict, consumes an AADP approval, or authorizes execution.
 */
import { AUTHORIZATION_BUNDLE_VERSION, type AuthorizationBundleVerificationOptions } from './authorization-bundle.js';
import { type AebDigest } from './aeb-adapter-contract.js';
export declare const AADP_AUTHORIZATION_ARTIFACT_VERSION = "AADP-AUTHORIZATION-ARTIFACT-v1";
export declare const AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE = "EP-AADP-AUTHORIZATION-ARTIFACT-v1";
export declare const AADP_ACTION_MAPPING_CONFIG_VERSION = "AADP-ACTION-MAPPING-CONFIG-v1";
export declare const AADP_ACTION_MAPPING_RECORD_VERSION = "AADP-ACTION-MAPPING-RECORD-v1";
export declare const AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION = "AADP-NATIVE-VERIFIER-DESCRIPTOR-v1";
export declare const AADP_NATIVE_VERIFICATION_RECORD_VERSION = "AADP-NATIVE-VERIFICATION-RECORD-v1";
export type AadpNativeVerificationOutcome = 'VERIFIED' | 'REFUSED' | 'UNAVAILABLE' | 'NOT_RUN';
export type AadpEvidenceSatisfaction = 'SATISFIED' | 'REFUSE' | 'INDETERMINATE' | 'NOT_EVALUATED';
export interface AadpPinnedImplementation {
    id: string;
    version: string;
    digest: AebDigest;
}
export interface AadpMappingResolver {
    id: string;
    version: string;
    digest: AebDigest;
}
export interface AadpMaterialFieldMap {
    source_param: string;
    mapped_path: string;
}
export interface AadpActionMappingConfiguration {
    profile: typeof AADP_ACTION_MAPPING_CONFIG_VERSION;
    mapping_profile: string;
    source_action_type: string;
    mapped_action_type: string;
    implementation: AadpPinnedImplementation;
    resolver: AadpMappingResolver;
    material_field_map: AadpMaterialFieldMap[];
    no_material_field_loss: true;
}
export interface AadpActionMappingRecord {
    profile: typeof AADP_ACTION_MAPPING_RECORD_VERSION;
    mapping_profile: string;
    implementation: AadpPinnedImplementation;
    resolver: AadpMappingResolver & {
        configuration_digest: AebDigest;
    };
    source_action_digest: AebDigest;
    mapped_action_digest: AebDigest;
    no_material_field_loss: true;
}
export interface AadpNativeVerifierDescriptor {
    profile: typeof AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION;
    artifact_profile: typeof AUTHORIZATION_BUNDLE_VERSION;
    implementation: AadpPinnedImplementation;
}
export interface AadpNativeVerificationRecord {
    profile: typeof AADP_NATIVE_VERIFICATION_RECORD_VERSION;
    artifact_profile: typeof AUTHORIZATION_BUNDLE_VERSION;
    artifact_digest: AebDigest | null;
    native_verification: Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'>;
    evidence_satisfaction: Exclude<AadpEvidenceSatisfaction, 'NOT_EVALUATED'>;
    verifier: AadpPinnedImplementation;
    trust_configuration_digest: AebDigest;
    status_policy_digest: AebDigest;
    source_action_digest: AebDigest;
    mapped_action_digest: AebDigest;
    verification_result_digest: AebDigest;
    record_digest: AebDigest;
}
export interface AadpAuthorizationArtifact {
    profile: typeof AADP_AUTHORIZATION_ARTIFACT_VERSION;
    artifact_profile: string;
    artifact_digest: AebDigest;
    native_verification: Exclude<AadpNativeVerificationOutcome, 'NOT_RUN'>;
    evidence_satisfaction: Exclude<AadpEvidenceSatisfaction, 'NOT_EVALUATED'>;
    verification_record_digest: AebDigest;
    action_mapping: AadpActionMappingRecord;
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
    mapping: unknown;
    verifier: unknown;
    bundleOptions: Omit<AuthorizationBundleVerificationOptions, 'expectedAction'>;
}
export interface AadpEpAuthorizationArtifactResult {
    verdict: 'VERIFIED' | 'REFUSE' | 'INDETERMINATE';
    native_verification: AadpNativeVerificationOutcome;
    evidence_satisfaction: AadpEvidenceSatisfaction;
    artifact: AadpAuthorizationArtifact | null;
    verification_record: AadpNativeVerificationRecord | null;
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
 * Mapping and verifier descriptors are relying-party configuration, never
 * presenter input. Source material parameters are closed and every declared
 * value must survive at its exact mapped path before EP verification runs.
 */
export declare function deriveAadpEpAuthorizationArtifact(input: DeriveAadpEpAuthorizationArtifactInput): AadpEpAuthorizationArtifactResult;
/** Derive the native EP hook and compare it to a presenter-supplied AADP hook. */
export declare function verifyAadpEpAuthorizationArtifact(presented: unknown, input: DeriveAadpEpAuthorizationArtifactInput): AadpEpAuthorizationArtifactResult;
declare const _default: Readonly<{
    AADP_AUTHORIZATION_ARTIFACT_VERSION: "AADP-AUTHORIZATION-ARTIFACT-v1";
    AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE: "EP-AADP-AUTHORIZATION-ARTIFACT-v1";
    AADP_ACTION_MAPPING_CONFIG_VERSION: "AADP-ACTION-MAPPING-CONFIG-v1";
    AADP_ACTION_MAPPING_RECORD_VERSION: "AADP-ACTION-MAPPING-RECORD-v1";
    AADP_NATIVE_VERIFIER_DESCRIPTOR_VERSION: "AADP-NATIVE-VERIFIER-DESCRIPTOR-v1";
    AADP_NATIVE_VERIFICATION_RECORD_VERSION: "AADP-NATIVE-VERIFICATION-RECORD-v1";
    parseAadpAuthorizationArtifact: typeof parseAadpAuthorizationArtifact;
    matchAadpAuthorizationArtifact: typeof matchAadpAuthorizationArtifact;
    deriveAadpEpAuthorizationArtifact: typeof deriveAadpEpAuthorizationArtifact;
    verifyAadpEpAuthorizationArtifact: typeof verifyAadpEpAuthorizationArtifact;
}>;
export default _default;
//# sourceMappingURL=aadp-authorization-artifact.d.ts.map