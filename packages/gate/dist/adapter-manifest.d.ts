import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const ADAPTER_MANIFEST_VERSION = "EP-ADAPTER-MANIFEST-v1";
export declare const ADAPTER_MANIFEST_CLAIM_BOUNDARY = "signed_adapter_revision_and_receipt_references_not_external_system_behavior_deployment_or_conformance_truth";
export declare function signAdapterManifest(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: import('node:crypto').KeyLike;
}): RiskRecord;
export declare function loadAdapterManifestRegistry({ manifests, trusted_keys, now, }: {
    manifests: unknown[];
    trusted_keys: TrustedRiskKeys;
    now?: number | string | (() => number | string);
}): RiskRecord;
declare const _default: {
    ADAPTER_MANIFEST_VERSION: string;
    ADAPTER_MANIFEST_CLAIM_BOUNDARY: string;
    signAdapterManifest: typeof signAdapterManifest;
    loadAdapterManifestRegistry: typeof loadAdapterManifestRegistry;
};
export default _default;
//# sourceMappingURL=adapter-manifest.d.ts.map