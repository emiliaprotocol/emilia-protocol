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
export declare const CCS_L1_PYPI_DISTRIBUTION_VERSION = "1.1.14";
export declare const CCS_L1_PYPI_SDIST_SHA256 = "9f75676e5b3d6ace8e91742d8b78b6d15b2d4250414326c17cc9e1aa361ec318";
export declare const CCS_L1_PYPI_WHEEL_SHA256 = "04a7857253bac2fca25611d17280cebf92fd0a7a2987a4d7ece973d492b17c83";
export declare const CCS_L1_REFERENCE_VECTOR_SHA256 = "5260e619c010d36729c57c5e8814613215e65e09abfba8a6a1d93f07e919762f";
export declare const CCS_L1_PYPI_SOURCE_LOCK = "ccs-verifier-pypi-1.1.14-ed25519-l1";
export declare const CCS_L1_AEB_ADAPTER_ID = "native:ccs-pypi-ed25519-l1-1.1.14";
export declare const CCS_L1_AEB_ADAPTER_VERSION = "1";
export declare const CCS_L1_AEB_CONFIG_VERSION = "AEB-CCS-PYPI-ED25519-CONFIG-v1";
export declare const CCS_L1_AEB_TRUST_ROOT_VERSION = "AEB-CCS-PYPI-ED25519-ROOT-v1";
export declare const CCS_L1_CAID_MAPPING_VERSION = "AEB-CCS-L1-TOOL-ACTION-MAPPING-v1";
export declare const CCS_L1_CAID_MAPPER_ID = "mapper:ccs-pypi-l1-tool-action-v1";
export interface CcsL1Receipt {
    trace_id: string;
    receipt_version: '1.1';
    verdict: 'allow' | 'deny' | 'escalate';
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
export interface CcsL1AebAdapterConfig {
    '@version': typeof CCS_L1_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: AebEvidenceSubject;
    issuer: string;
    audience: string;
    action_type: string;
    allowed_actions: string[];
    allowed_tools: string[];
    required_rule_version: string;
    max_receipt_age_seconds: number;
    max_clock_skew_seconds: number;
    deployment_scope: 'pinned-ed25519-issuer';
}
export interface CcsL1Ed25519TrustRoot {
    '@version': typeof CCS_L1_AEB_TRUST_ROOT_VERSION;
    issuer: string;
    key_id: string;
    algorithm: 'Ed25519';
    public_key_raw_base64: string;
    public_key_fingerprint_sha256_16: string;
}
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
/**
 * Define the shared native-action projection used when CCS policy evidence is
 * joined with another independently verified evidence leg for the same action.
 */
export declare function createCcsNativeActionDefinition(actionType: string): Obj;
/** Build a local-HMAC CCS adapter from relying-party-owned pins. */
export declare function createCcsPyPiHmacAebAdapter(constructorPins: {
    config: CcsAebAdapterConfig;
    trust_roots: readonly CcsAebHmacTrustRoot[];
}): AebAdapter;
export declare function createCcsL1AebActionDefinition(actionType: string): Obj;
/** Build a source-locked CCS 1.1.14 Ed25519 L1 adapter from relying-party pins. */
export declare function createCcsPyPiL1AebAdapter(constructorPins: {
    config: CcsL1AebAdapterConfig;
    trust_roots: readonly CcsL1Ed25519TrustRoot[];
}): AebAdapter;
/**
 * CCS-05 calls the extended receipt shape "v1.3", while the latest public
 * ccs-verifier package (1.1.14) still emits its distinct receipt_version 1.1
 * shape. This profile is therefore source-locked to the Internet-Draft bytes
 * and intentionally does not relabel the package-backed adapter above.
 */
export declare const CCS_V13_DRAFT_URL = "https://www.ietf.org/archive/id/draft-correctover-ccs-05.txt";
export declare const CCS_V13_DRAFT_SHA256 = "c91f0fa31b1b9e5e2dfe79b99f3b554075d3a44d5309406e748b728f86767cb9";
export declare const CCS_V13_REFERENCE_CODEBERG_COMMIT = "a5cddf5093724ab149059ce1f2d507b5d0aeb36d";
export declare const CCS_V13_REFERENCE_PYPI_VERSION = "1.1.14";
export declare const CCS_V13_SOURCE_LOCK = "draft-correctover-ccs-05-v1.3-c91f0fa31b1b9e5";
export declare const CCS_V13_AEB_ADAPTER_ID = "native:ccs-05-v1.3-ed25519";
export declare const CCS_V13_AEB_ADAPTER_VERSION = "1";
export declare const CCS_V13_AEB_CONFIG_VERSION = "AEB-CCS-05-V1.3-CONFIG-v1";
export declare const CCS_V13_AEB_TRUST_ROOT_VERSION = "AEB-CCS-05-V1.3-ROOT-v1";
export declare const CCS_V13_CAID_MAPPING_VERSION = "AEB-CCS-05-V1.3-TOOL-ACTION-MAPPING-v1";
export declare const CCS_V13_CAID_MAPPER_ID = "mapper:ccs-05-v1.3-tool-action-v1";
export interface CcsV13Receipt {
    trace_id: string;
    verdict: 'allow' | 'deny' | 'escalate';
    timestamp: number;
    tool: string;
    params_hash: string;
    rule_summary: string;
    receipt: string;
    verified_at: number;
    block_reason: string;
    request_hash: string;
    response_hash: string;
    runtime_context_hash: string;
    action: string;
    config_hash: string;
    issuer: string;
    audience: string;
    nonce: string;
    sequence: number;
    issued_at: number;
    expires_at: number;
    max_clock_skew: number;
    signature: string;
}
export interface CcsV13AebAdapterConfig {
    '@version': typeof CCS_V13_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: AebEvidenceSubject;
    issuer: string;
    audience: string;
    action_type: string;
    allowed_tools: string[];
    max_receipt_age_seconds: number;
    max_clock_skew_seconds: number;
    deployment_scope: 'pinned-ed25519-issuer';
}
export interface CcsV13Ed25519TrustRoot {
    '@version': typeof CCS_V13_AEB_TRUST_ROOT_VERSION;
    issuer: string;
    key_id: string;
    algorithm: 'Ed25519';
    public_key_raw_base64: string;
    public_key_fingerprint_sha256_16: string;
}
export declare function createCcsV13AebActionDefinition(actionType: string): Obj;
/** Build the source-locked CCS-05 v1.3 Ed25519 enforcement adapter. */
export declare function createCcsV13AebAdapter(constructorPins: {
    config: CcsV13AebAdapterConfig;
    trust_roots: readonly CcsV13Ed25519TrustRoot[];
}): AebAdapter;
export {};
//# sourceMappingURL=aeb-ccs-adapter.d.ts.map