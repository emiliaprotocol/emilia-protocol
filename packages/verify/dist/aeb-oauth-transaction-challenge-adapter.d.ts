import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
type SupportedAlgorithm = 'ES256' | 'EdDSA';
export declare const OAUTH_TXN_CHALLENGE_DRAFT_REVISION = "draft-rosomakho-oauth-txn-challenge-00";
export declare const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID = "native:oauth-transaction-challenge";
export declare const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION = "3";
export declare const OAUTH_TXN_CHALLENGE_CONFIG_VERSION = "AEB-OAUTH-TXN-CHALLENGE-CONFIG-v1";
export declare const OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION = "AEB-OAUTH-TXN-CHALLENGE-ROOT-v1";
export declare const OAUTH_TXN_CHALLENGE_MAPPING_VERSION = "AEB-OAUTH-TXN-CHALLENGE-CAID-MAPPING-v2";
export declare const OAUTH_TXN_CHALLENGE_MAPPER_ID = "mapper:oauth-transaction-exact-action-v2";
/** Stable across OAuth token reissuance, AEB wrapper changes, and profile revisions. */
export declare const OAUTH_TXN_CHALLENGE_REPLAY_NAMESPACE = "emilia:oauth-txn-challenge:protected-resource-transaction:v1";
export declare const OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS: readonly ["challenge.header.alg", "challenge.header.kid", "challenge.header.typ", "challenge.iat", "challenge.exp", "challenge.jti", "challenge.reason", "challenge.reason_uri", "access_token.header.alg", "access_token.header.kid", "access_token.header.typ", "access_token.iat", "access_token.exp", "access_token.jti"];
export declare const OAUTH_TXN_CHALLENGE_SEMANTIC_OMISSION_BASIS: readonly Readonly<{
    path: "challenge.header.alg" | "challenge.header.kid" | "challenge.header.typ" | "challenge.iat" | "challenge.exp" | "challenge.jti" | "challenge.reason" | "challenge.reason_uri" | "access_token.header.alg" | "access_token.header.kid" | "access_token.header.typ" | "access_token.iat" | "access_token.exp" | "access_token.jti";
    relying_party_basis: "signature_and_type_verification_input_not_executed_action_semantics" | "freshness_verification_input_not_executed_action_semantics" | "artifact_instance_identifier_superseded_by_transaction_scoped_replay_identity" | "protected_resource_explanation_not_executed_action_semantics";
}>[];
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
    /** Profile rule: a protected-resource transaction identifier is never reusable. */
    replay_equivalence: 'nonreusable-protected-resource-transaction';
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