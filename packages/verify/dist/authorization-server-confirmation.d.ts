/**
 * Authorization Server confirmation evidence for AEB/AEC.
 *
 * This profile consumes an independently signed AS grant. It never turns that
 * grant into a relying-party authorization verdict. The adapter verifies the
 * AS signature under relying-party-pinned trust, binds it to one exact action,
 * one exact human-evidence artifact, one human subject, and one resource-server
 * audience, then emits an ordinary AEB evidence leg. A separate AEB
 * `evidence-binding` requirement joins it to the natively verified human leg.
 *
 * The profile is deliberately an implementation surface, not a new wire-format
 * standards claim. It is shaped to compose with AS confirmation records such
 * as draft-liu-agent-operation-authorization and with the AS-owned decision
 * boundary in draft-klrc-aiagent-auth.
 */
import { type KeyObject } from 'node:crypto';
import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-CONFIG-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-ROOT-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID = "native:authorization-server-confirmation";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION = "1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-CAID-MAPPING-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID = "mapper:authorization-server-confirmation-exact-action-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TYP = "ep-as-confirmation+jwt";
export interface AuthorizationServerConfirmationClaims {
    ep_version: typeof AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION;
    iss: string;
    /** Human principal vouched for by the enterprise Authorization Server. */
    sub: string;
    /** Exact Resource Server / Gate audience. */
    aud: string;
    iat: number;
    nbf: number;
    exp: number;
    jti: string;
    authorization_server_decision: 'AUTHORIZED';
    /** Closed exact-action projection: { action_type, parameters }. */
    action: Obj;
    action_digest: AebDigest;
    /** Digest of the exact human artifact included in the adapter envelope. */
    human_evidence_digest: AebDigest;
    policy_digest: AebDigest;
    /** Customer-owned identity-directory state used for this decision. */
    directory_digest: AebDigest;
    /** What the timestamp below actually means; it is not instantaneous HR truth. */
    directory_observation_basis: 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT';
    /** Unix time when the AS observed the directory snapshot it used. */
    directory_observed_at: number;
    /** Pins the intended resource-server verification key or KMS identity. */
    resource_server_key_id: string;
    resource_server_key_digest: AebDigest;
}
export interface AuthorizationServerConfirmationArtifact {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION;
    grant: string;
    human_evidence: unknown;
}
export interface AuthorizationServerConfirmationAdapterConfig {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION;
    evidence_role: 'authorization-server-confirmation';
    human_evidence_role: 'human-authorization';
    issuer: string;
    audience: string;
    resource_server_key_id: string;
    resource_server_key_digest: AebDigest;
    action_type: string;
    clock_skew_seconds: number;
    max_token_age_seconds: number;
    max_directory_snapshot_age_seconds: number;
}
export interface AuthorizationServerConfirmationTrustRoot {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION;
    use: 'authorization-server';
    issuer: string;
    key_id: string;
    algorithm: 'EdDSA';
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface AuthorizationServerConfirmationSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AuthorizationServerConfirmationConstructorPins {
    config: AuthorizationServerConfirmationAdapterConfig;
    trust_roots: readonly AuthorizationServerConfirmationTrustRoot[];
}
export declare function createAuthorizationServerConfirmationActionDefinition(actionType: string): Obj;
export declare function signAuthorizationServerConfirmation(claims: AuthorizationServerConfirmationClaims, signer: AuthorizationServerConfirmationSigner): string;
export declare function createAuthorizationServerConfirmationAdapter(constructorPins: AuthorizationServerConfirmationConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=authorization-server-confirmation.d.ts.map