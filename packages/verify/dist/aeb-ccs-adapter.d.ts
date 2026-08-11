import { type AebAdapter, type AebEvidenceSubject } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const CCS_PYPI_DISTRIBUTION_VERSION = "1.1.0";
export declare const CCS_PYPI_RUNTIME_VERSION = "0.4.1";
export declare const CCS_PYPI_SOURCE_LOCK = "ccs-verifier-pypi-1.1.0-runtime-0.4.1";
export declare const CCS_PYPI_ARTIFACT_VERSION = "CCS-PYPI-0.4.1-RESULT-v1";
export declare const CCS_AEB_ADAPTER_ID = "native:ccs-pypi-hmac-0.4.1";
export declare const CCS_AEB_ADAPTER_VERSION = "1";
export declare const CCS_AEB_CONFIG_VERSION = "AEB-CCS-PYPI-HMAC-CONFIG-v1";
export declare const CCS_AEB_TRUST_ROOT_VERSION = "AEB-CCS-PYPI-HMAC-ROOT-v1";
export declare const CCS_CAID_MAPPING_VERSION = "AEB-CCS-TOOL-ACTION-MAPPING-v1";
export declare const CCS_CAID_MAPPER_ID = "mapper:ccs-pypi-tool-action-v1";
export interface CcsPyPiCommand {
    agent_id: string;
    tool: string;
    params: Obj;
    timestamp: number;
    trace_id: string;
}
export interface CcsPyPiRuleResult {
    rule_name: string;
    verdict: 'allow' | 'deny' | 'escalate';
    reason: string;
    latency_us: number;
    error_code: number;
}
export interface CcsPyPiVerificationResult {
    trace_id: string;
    verdict: 'allow' | 'deny' | 'escalate';
    block_reason: string;
    rule_results: CcsPyPiRuleResult[];
    receipt: string;
    verified_at: number;
    tool: string;
    params_hash: string;
    error_code: number;
}
export interface CcsPyPiArtifact {
    '@version': typeof CCS_PYPI_ARTIFACT_VERSION;
    command: CcsPyPiCommand;
    result: CcsPyPiVerificationResult;
}
export interface CcsAebAdapterConfig {
    '@version': typeof CCS_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: AebEvidenceSubject;
    issuer: string;
    audience: string;
    action_type: string;
    allowed_tools: string[];
    required_rules: string[];
    max_receipt_age_seconds: number;
    params_hash_bits: 64;
    deployment_scope: 'single-relying-party-local-hmac';
}
export interface CcsAebHmacTrustRoot {
    '@version': typeof CCS_AEB_TRUST_ROOT_VERSION;
    issuer: string;
    audience: string;
    key_id: string;
    algorithm: 'HMAC-SHA256-TRUNC128';
    secret_base64url: string;
}
export declare function createCcsAebActionDefinition(actionType: string): Obj;
/** Build a local-HMAC CCS adapter from relying-party-owned pins. */
export declare function createCcsPyPiHmacAebAdapter(constructorPins: {
    config: CcsAebAdapterConfig;
    trust_roots: readonly CcsAebHmacTrustRoot[];
}): AebAdapter;
export {};
//# sourceMappingURL=aeb-ccs-adapter.d.ts.map