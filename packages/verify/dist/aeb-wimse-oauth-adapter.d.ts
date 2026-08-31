import type { AebAdapter, AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const WIMSE_OAUTH_SPT_AEB_ADAPTER_ID = "native:wimse-http-signature-oauth-txn-spt-intent";
export declare const WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION = "2";
export declare const WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION = "AEB-WIMSE-OAUTH-SPT-CONFIG-v2";
export declare const WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION = "AEB-WIMSE-OAUTH-SPT-ED25519-ROOT-v1";
export declare const WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION = "AEB-WIMSE-OAUTH-SPT-CAID-MAPPING-v2";
export declare const WIMSE_OAUTH_SPT_CAID_MAPPER_ID = "mapper:wimse-oauth-spt-exact-request-v2";
export declare const WIMSE_HTTP_SIGNATURE_REVISION = "draft-ietf-wimse-http-signature-06";
export declare const WIMSE_WORKLOAD_CREDS_REVISION = "draft-ietf-wimse-workload-creds-02";
export declare const WIMSE_WPT_REVISION = "draft-ietf-wimse-wpt-02";
export declare const OAUTH_TRANSACTION_TOKENS_REVISION = "draft-ietf-oauth-transaction-tokens-11";
export declare const SPT_TRANSACTION_TOKENS_REVISION = "draft-coetzee-oauth-spt-txn-tokens-03";
export declare const OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE = "oauth-transaction-token:trust-domain-txn";
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
    /** Exact -06 `wimse-aud` signature parameter and WPT audience. */
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
    /**
     * Exact lower-case, single-occurrence request header fields whose token
     * values this relying party understands and requires the WPT `oth` claim to
     * bind. WPT remains a proof-of-possession and token-binding artifact; this
     * list does not make any listed token authoritative.
     */
    other_token_headers: string[];
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
export interface WimseWpt02TokenBindingResult {
    verification: 'VERIFIED' | 'FAILED';
    /** Whether the request contains a Txn-Token header. */
    transaction_token: 'PRESENT' | 'ABSENT';
    /** Exact understood `oth` header set, sorted independently of JSON order. */
    other_token_headers: string[];
    reason: string | null;
}
/**
 * Stable single-spend identity for a native Txn-Token transaction.
 * Transaction Tokens -11 defines `aud` as the Trust Domain and says `txn`
 * should be unique within that domain. The draft revision and optional `iss`
 * are verification metadata, not replay-key material.
 */
export declare function deriveOAuthTransactionTokenReplayUnit(trustDomain: unknown, transactionId: unknown): AebDigest;
/**
 * Reperform only the `tth` and `oth` byte-binding rules from WPT-02.
 * This function does not verify a WPT signature, authenticate a workload,
 * authorize a request, reserve an operation, or establish an external effect.
 */
export declare function verifyWimseWpt02TokenBindingClaims(wptClaims: unknown, requestHeaders: unknown, understoodOtherTokenHeaders: readonly string[]): WimseWpt02TokenBindingResult;
export declare function createWimseOAuthSptActionDefinition(actionType: string): Obj;
/**
 * Construct an immutable adapter whose trust and policy inputs are pinned
 * twice: first here, then by exact digest equality on every AEB invocation.
 */
export declare function createWimseOAuthSptAebAdapter(constructorPins: WimseOAuthSptConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-wimse-oauth-adapter.d.ts.map