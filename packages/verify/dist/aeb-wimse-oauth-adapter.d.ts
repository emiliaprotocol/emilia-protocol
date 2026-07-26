import { type AebAdapter } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const WIMSE_OAUTH_SPT_AEB_ADAPTER_ID = "native:wimse-http-signature-oauth-txn-spt-intent";
export declare const WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION = "1";
export declare const WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION = "AEB-WIMSE-OAUTH-SPT-CONFIG-v1";
export declare const WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION = "AEB-WIMSE-OAUTH-SPT-ED25519-ROOT-v1";
export declare const WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION = "AEB-WIMSE-OAUTH-SPT-CAID-MAPPING-v1";
export declare const WIMSE_OAUTH_SPT_CAID_MAPPER_ID = "mapper:wimse-oauth-spt-exact-request-v1";
export declare const WIMSE_HTTP_SIGNATURE_REVISION = "draft-ietf-wimse-http-signature-03";
export declare const WIMSE_WORKLOAD_CREDS_REVISION = "draft-ietf-wimse-workload-creds-01";
export declare const WIMSE_WPT_REVISION = "draft-ietf-wimse-wpt-01";
export declare const OAUTH_TRANSACTION_TOKENS_REVISION = "draft-ietf-oauth-transaction-tokens-08";
export declare const SPT_TRANSACTION_TOKENS_REVISION = "draft-coetzee-oauth-spt-txn-tokens-03";
export type WimseOAuthSptTrustUse = 'wit-issuer' | 'oauth-transaction-token-issuer' | 'spt-transaction-token-issuer' | 'workload-holder';
export interface WimseOAuthSptIssuerTrustRoot {
    '@version': typeof WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION;
    use: Exclude<WimseOAuthSptTrustUse, 'workload-holder'>;
    issuer: string;
    key_id: string;
    algorithm: 'EdDSA';
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface WimseOAuthSptHolderTrustRoot {
    '@version': typeof WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION;
    use: 'workload-holder';
    subject: string;
    key_id: string;
    algorithm: 'EdDSA';
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export type WimseOAuthSptTrustRoot = WimseOAuthSptIssuerTrustRoot | WimseOAuthSptHolderTrustRoot;
export interface WimseOAuthSptAdapterConfig {
    '@version': typeof WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION;
    /**
     * Deliberately not configurable to a human role. The adapter can fill only
     * this workload/delegation role.
     */
    evidence_role: 'delegated-workload';
    subject: {
        id: string;
        kind: 'workload';
        native_id: string;
    };
    trust_domain: string;
    /** Exact -03 `wimse-aud` signature parameter and WPT audience. */
    wimse_audience: string;
    /** Exact OAuth Txn-Token trust-domain audience. */
    oauth_audience: string;
    oauth_subject: string;
    oauth_scope: string;
    /** Exact optional SPT TXN relying-party audience. */
    spt_audience: string;
    spt_subject: string;
    /** Opaque -03 holder_key value pinned to the workload-holder key. */
    spt_holder_key: string;
    action_type: string;
    clock_skew_seconds: number;
    max_age_seconds: {
        wit: number;
        wpt: number;
        oauth_txn: number;
        spt_txn: number;
        http_signature: number;
        status: number;
    };
}
export interface WimseOAuthSptConstructorPins {
    config: WimseOAuthSptAdapterConfig;
    trust_roots: readonly WimseOAuthSptTrustRoot[];
}
export declare function createWimseOAuthSptActionDefinition(actionType: string): Obj;
/**
 * Construct an immutable adapter whose trust and policy inputs are pinned
 * twice: first here, then by exact digest equality on every AEB invocation.
 */
export declare function createWimseOAuthSptAebAdapter(constructorPins: WimseOAuthSptConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-wimse-oauth-adapter.d.ts.map