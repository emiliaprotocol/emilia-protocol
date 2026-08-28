import { type AebAdapter, type AebDigest, type AebEvidenceSubject } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const CCS_V14_VECTOR_REPOSITORY = "https://github.com/DSHCorrectover/ccs-conformance-vectors";
export declare const CCS_V14_VECTOR_COMMIT = "a3503b2bc48922f92a28c372003885a0831da02b";
export declare const CCS_V14_VECTOR_MANIFEST_SHA256 = "3e77eae3045eb2bc824c52b8d022b75029beaf56623841ce7c035a99e65a2ddd";
export declare const CCS_V14_SOURCE_LOCK = "ccs-v1.4.0-conformance-github@a3503b2bc48922f92a28c372003885a0831da02b";
export declare const CCS_V14_AEB_ADAPTER_ID = "native:ccs-v1.4.0-conformance-ed25519";
export declare const CCS_V14_AEB_ADAPTER_VERSION = "1";
export declare const CCS_V14_AEB_CONFIG_VERSION = "AEB-CCS-V1.4.0-CONFORMANCE-CONFIG-v1";
export declare const CCS_V14_AEB_TRUST_ROOT_VERSION = "AEB-CCS-V1.4.0-CONFORMANCE-ROOT-v1";
export declare const CCS_V14_CAID_MAPPING_VERSION = "AEB-CCS-V1.4.0-GITHUB-ACTION-MAPPING-v1";
export declare const CCS_V14_CAID_MAPPER_ID = "mapper:ccs-v1.4.0-github-action-v1";
export interface CcsV14Receipt {
    trace_id: string;
    receipt_version: '1.4';
    verdict: 'allow' | 'block';
    timestamp: number;
    tool: string;
    tool_call_id: string;
    params_hash: string;
    args_digest: string;
    rule_summary: string;
    rule_version: string;
    request_hash: string;
    response_hash: string;
    runtime_context_hash: string;
    config_hash: string;
    verifier_source_class: string;
    deployment_mode: string;
    issuer: string;
    audience: string;
    nonce: string;
    sequence: number;
    issued_at: number;
    expires_at: number;
    max_clock_skew: number;
    action: string;
    signature: string;
    signing_algorithm: 'Ed25519';
    public_key_fingerprint: string;
    public_key: string;
    verified_at: number;
    latency_us: number;
}
export interface CcsV14Artifact {
    receipt: CcsV14Receipt;
    tool_args: Obj;
    response_body: unknown;
}
export interface CcsV14AebAdapterConfig {
    '@version': typeof CCS_V14_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: AebEvidenceSubject;
    issuer: string;
    audience: string;
    action_type: string;
    allowed_actions: string[];
    allowed_tools: string[];
    required_rule_version: string;
    max_receipt_age_seconds: number;
    max_status_age_seconds: number;
    max_clock_skew_seconds: number;
    deployment_scope: 'pinned-ed25519-issuer';
}
export interface CcsV14Ed25519TrustRoot {
    '@version': typeof CCS_V14_AEB_TRUST_ROOT_VERSION;
    issuer: string;
    key_id: string;
    algorithm: 'Ed25519';
    public_key_raw_base64: string;
    public_key_fingerprint_sha256_16: string;
}
export declare function createCcsV14AebActionDefinition(actionType: string): Obj;
export declare function createCcsV14AebAdapter(constructorPins: {
    config: CcsV14AebAdapterConfig;
    trust_roots: readonly CcsV14Ed25519TrustRoot[];
}): AebAdapter;
export declare function ccsV14ArtifactDigest(artifact: CcsV14Artifact): AebDigest;
export {};
//# sourceMappingURL=aeb-ccs-v14-adapter.d.ts.map