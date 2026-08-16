import { type AebAdapter } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const WAG_DRAFT_REVISION = "draft-carleton-workload-authz-grant-00";
export declare const WAG_DRAFT_SOURCE_COMMIT = "13f516a5e458b89ca30f7ea47a802091dd9d4154";
export declare const WAG_DRAFT_TXT_SHA256 = "sha256:4b92283fefdce2093e11f70bbfce5aa00af9191f7b278d498f30f2b34a78f798";
export declare const WAG_DRAFT_SOURCE_SHA256 = "sha256:195fa249380052324d78c8dbfbdeb4ff7b7c5b3bd5d9a9f4d9abf110e944e4e2";
export declare const WAG_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export declare const WAG_TOKEN_ISSUANCE_ACTION_TYPE = "oauth.access-token.issue.1";
export declare const WAG_AEB_ADAPTER_ID = "native:workload-authorization-grant";
export declare const WAG_AEB_ADAPTER_VERSION = "1";
export declare const WAG_AEB_CONFIG_VERSION = "AEB-WAG-CONFIG-v1";
export declare const WAG_TRUST_ROOT_VERSION = "AEB-WAG-PER-TENANCY-ROOT-v1";
export declare const WAG_CAID_MAPPING_VERSION = "AEB-WAG-TOKEN-ISSUANCE-CAID-MAPPING-v1";
export declare const WAG_CAID_MAPPER_ID = "mapper:wag-token-issuance-v1";
export interface WagAdapterConfig {
    '@version': typeof WAG_AEB_CONFIG_VERSION;
    evidence_role: string;
    /** Exact per-tenancy issuer allowlisted by the authorization server. */
    issuer: string;
    tenancy: string;
    /** Exact authority component accepted for a URI-form Workload Identifier. */
    wimse_authority: string;
    authorization_server_issuer: string;
    token_endpoint: string;
    resource: string;
    action_type: typeof WAG_TOKEN_ISSUANCE_ACTION_TYPE;
    /** Signed properties that are material to this relying party's token request. */
    property_claims: string[];
    require_wimse_identifier: boolean;
    clock_skew_seconds: number;
    max_grant_lifetime_seconds: number;
    max_status_age_seconds: number;
}
export interface WagTrustRoot {
    '@version': typeof WAG_TRUST_ROOT_VERSION;
    use: 'wag-per-tenancy-issuer-key';
    issuer: string;
    tenancy: string;
    key_id: string;
    algorithm: 'ES256';
    public_jwk: {
        kty: 'EC';
        crv: 'P-256';
        x: string;
        y: string;
    };
}
export interface WagConstructorPins {
    config: WagAdapterConfig;
    trust_roots: readonly WagTrustRoot[];
}
export interface WagArtifact {
    grant_type: typeof WAG_GRANT_TYPE;
    assertion: string;
    resource: string;
}
export declare function createWagActionDefinition(actionType: string): Obj;
export declare function createWagAebAdapter(constructorPins: WagConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-wag-adapter.d.ts.map