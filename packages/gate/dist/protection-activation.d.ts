import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const PROTECTION_ACTIVATION_VERSION = "EP-PROTECTION-ACTIVATION-v1";
export declare const PROTECTION_ACTIVATION_CLAIM_BOUNDARY = "customer_pinned_gateway_configuration_not_per_action_authority_connector_coverage_deployment_or_effect_truth";
export type ProtectionActivationExpected = Readonly<{
    activation_id: string;
    tenant_id: string;
    gateway_id: string;
    minimum_epoch?: number;
    plan_digest?: string;
    manifest_digest?: string;
    authorizer_id: string;
}>;
export declare function signProtectionActivation(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: import('node:crypto').KeyLike;
}): RiskRecord;
export declare function verifyProtectionActivation(artifact: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    expected?: ProtectionActivationExpected;
    now?: number | string | (() => number | string);
}): RiskRecord;
declare const _default: {
    PROTECTION_ACTIVATION_VERSION: string;
    PROTECTION_ACTIVATION_CLAIM_BOUNDARY: string;
    signProtectionActivation: typeof signProtectionActivation;
    verifyProtectionActivation: typeof verifyProtectionActivation;
};
export default _default;
//# sourceMappingURL=protection-activation.d.ts.map