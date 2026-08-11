import { type AebAdapter } from './aeb-adapter-contract.js';
import { type WimseOAuthSptAdapterConfig, type WimseOAuthSptTrustRoot } from './aeb-wimse-oauth-adapter.js';
export declare const WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_ID = "native:wimse-oauth-principal-separation";
export declare const WIMSE_OAUTH_PRINCIPAL_AEB_ADAPTER_VERSION = "2";
export declare const WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION = "AEB-WIMSE-OAUTH-PRINCIPAL-CONFIG-v2";
export declare const WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION = "EP-WIMSE-OAUTH-PRINCIPAL-BINDING-v2";
export declare const WIMSE_OAUTH_PRINCIPAL_BINDING_CLAIM = "https://emiliaprotocol.ai/claims/wimse-principal-binding-v2";
export type WimseSubjectSemantics = 'logical-agent' | 'workload-instance';
export type OAuthSubSemantics = 'delegating-principal' | 'oauth-client' | 'workload-instance';
export interface WimseOAuthPrincipalBinding {
    '@version': typeof WIMSE_OAUTH_PRINCIPAL_BINDING_VERSION;
    logical_agent_id: string;
    workload_instance_id: string;
    /** Declares whether the WIT `sub` names the logical agent or live instance. */
    wimse_subject_semantics: WimseSubjectSemantics;
    /** RFC 7638 SHA-256 JWK thumbprint of the live instance confirmation key. */
    workload_confirmation_jkt: string;
    oauth_client_id: string;
    /** Exact grant semantics selected by the relying party; no inference. */
    oauth_grant_type: string;
    /** Exact meaning assigned to OAuth `sub` for this grant. */
    oauth_sub_semantics: OAuthSubSemantics;
    delegating_principal: {
        id: string;
        kind: 'human' | 'organization' | 'system';
    };
    executor_id: string;
    tool_id: string;
}
export interface WimseOAuthPrincipalAdapterConfig {
    '@version': typeof WIMSE_OAUTH_PRINCIPAL_CONFIG_VERSION;
    /** Frozen v1 cryptographic and action-mapping pins. */
    base: WimseOAuthSptAdapterConfig;
    /** Exact relationship values accepted by this relying party. */
    principal_binding: WimseOAuthPrincipalBinding;
}
export interface WimseOAuthPrincipalConstructorPins {
    config: WimseOAuthPrincipalAdapterConfig;
    trust_roots: readonly WimseOAuthSptTrustRoot[];
}
export declare function createWimseOAuthPrincipalAebAdapter(constructorPins: WimseOAuthPrincipalConstructorPins): AebAdapter;
//# sourceMappingURL=aeb-wimse-oauth-principal-adapter.d.ts.map