import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
type SupportedAlgorithm = 'ES256' | 'EdDSA';
export declare const OAUTH_TXN_CHALLENGE_DRAFT_REVISION = "draft-rosomakho-oauth-txn-challenge-00";
export declare const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID = "native:oauth-transaction-challenge";
export declare const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION = "1";
export declare const OAUTH_TXN_CHALLENGE_CONFIG_VERSION = "AEB-OAUTH-TXN-CHALLENGE-CONFIG-v1";
export declare const OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION = "AEB-OAUTH-TXN-CHALLENGE-ROOT-v1";
export declare const OAUTH_TXN_CHALLENGE_MAPPING_VERSION = "AEB-OAUTH-TXN-CHALLENGE-CAID-MAPPING-v1";
export declare const OAUTH_TXN_CHALLENGE_MAPPER_ID = "mapper:oauth-transaction-exact-action-v1";
export interface OAuthTransactionChallengeDetailsVerifierDescriptor {
    id: string;
    version: string;
    implementation_digest: AebDigest;
}
export interface OAuthTransactionChallengeDetailsVerifier extends OAuthTransactionChallengeDetailsVerifierDescriptor {
    verify(input: {
        requested: unknown;
        granted: unknown;
        expected: unknown;
    }): {
        verified: boolean;
        reason: string | null;
    };
}
export interface OAuthTransactionChallengeAdapterConfig {
    '@version': typeof OAUTH_TXN_CHALLENGE_CONFIG_VERSION;
    evidence_role: 'transaction-authorization';
    /** The signer of the authorization result; no human identity is inferred. */
    subject: {
        id: string;
        kind: 'organization' | 'system';
        native_id: string;
    };
    action_type: string;
    protected_resource: string;
    authorization_server: string;
    oauth_client_id: string;
    oauth_subject: string;
    require_actor_context: boolean;
    clock_skew_seconds: number;
    max_challenge_lifetime_seconds: number;
    max_access_token_lifetime_seconds: number;
    max_status_age_seconds: number;
    details_verifier: OAuthTransactionChallengeDetailsVerifierDescriptor;
}
export type OAuthTransactionChallengeTrustUse = 'protected-resource-challenge' | 'authorization-server-access-token';
export interface OAuthTransactionChallengeTrustRoot {
    '@version': typeof OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION;
    use: OAuthTransactionChallengeTrustUse;
    issuer: string;
    key_id: string;
    algorithm: SupportedAlgorithm;
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface OAuthTransactionChallengeConstructorPins {
    config: OAuthTransactionChallengeAdapterConfig;
    trust_roots: readonly OAuthTransactionChallengeTrustRoot[];
    details_verifier: OAuthTransactionChallengeDetailsVerifier;
}
export declare function createOAuthTransactionChallengeActionDefinition(actionType: string, requireActor: boolean): Obj;
export declare function createOAuthTransactionChallengeAebAdapter(constructorPins: OAuthTransactionChallengeConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-oauth-transaction-challenge-adapter.d.ts.map