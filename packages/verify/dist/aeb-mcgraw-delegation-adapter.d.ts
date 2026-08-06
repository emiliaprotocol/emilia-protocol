import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const MCGRAW_BUDGET_DRAFT_REVISION = "draft-mcgraw-httpapi-agent-budget-03";
export declare const MCGRAW_BUDGET_AEB_ADAPTER_ID = "native:mcgraw-budget-cose-ml-dsa";
export declare const MCGRAW_BUDGET_AEB_ADAPTER_VERSION = "1";
export declare const MCGRAW_BUDGET_CONFIG_VERSION = "AEB-MCGRAW-BUDGET-CONFIG-v1";
export declare const MCGRAW_BUDGET_TRUST_ROOT_VERSION = "AEB-MCGRAW-BUDGET-ML-DSA-ROOT-v1";
export declare const MCGRAW_BUDGET_MAPPING_VERSION = "AEB-MCGRAW-BUDGET-CAID-MAPPING-v1";
export declare const MCGRAW_BUDGET_MAPPER_ID = "mapper:mcgraw-budget-exact-request-v1";
/** RFC 9964 COSE Algorithms registry value for ML-DSA-65. */
export declare const MCGRAW_BUDGET_COSE_ALGORITHM = -49;
export interface McGrawBudgetVerifierDescriptor {
    id: string;
    version: string;
    implementation_digest: AebDigest;
}
export interface McGrawBudgetMldsaVerifier extends McGrawBudgetVerifierDescriptor {
    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}
export interface McGrawBudgetChainVerifier extends McGrawBudgetVerifierDescriptor {
    verify(input: {
        chain: Uint8Array;
        issuer: string;
        delegated_requester: string;
        issued_at_ms: number;
        expires_at_ms: number;
        now: string;
    }): {
        verified: boolean;
        reason: string | null;
    };
}
export interface McGrawBudgetAdapterConfig {
    '@version': typeof MCGRAW_BUDGET_CONFIG_VERSION;
    evidence_role: 'delegated-authority';
    subject: {
        id: string;
        kind: 'workload';
        native_id: string;
    };
    action_type: string;
    issuer: string;
    verifier_binding: string;
    required_authority: string;
    budget_unit: string;
    minimum_remaining_budget: string;
    challenge_nonce: string;
    content_type: 'application/delegation-proof+cose';
    representation_digest_semantics: 'http-request-content-sha256';
    require_request_binding: boolean;
    clock_skew_seconds: number;
    max_lifetime_seconds: number;
    max_status_age_seconds: number;
    chain_verifier: McGrawBudgetVerifierDescriptor;
    mldsa_verifier: McGrawBudgetVerifierDescriptor;
}
export interface McGrawBudgetTrustRoot {
    '@version': typeof MCGRAW_BUDGET_TRUST_ROOT_VERSION;
    issuer: string;
    /** Raw COSE kid bytes encoded as canonical base64url. */
    key_id: string;
    algorithm: 'ML-DSA-65';
    /** Raw FIPS 204 public key bytes encoded as canonical base64url. */
    public_key: string;
}
export interface McGrawBudgetConstructorPins {
    config: McGrawBudgetAdapterConfig;
    trust_roots: readonly McGrawBudgetTrustRoot[];
    chain_verifier: McGrawBudgetChainVerifier;
    mldsa_verifier: McGrawBudgetMldsaVerifier;
}
interface TaggedCbor {
    readonly cbor_tag: number;
    readonly value: unknown;
}
export declare function tagDeterministicCbor(tag: number, value: unknown): TaggedCbor;
export declare function encodeDeterministicCbor(value: unknown): Buffer;
export declare function createMcGrawBudgetActionDefinition(actionType: string): Obj;
export declare function createMcGrawBudgetAebAdapter(constructorPins: McGrawBudgetConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-mcgraw-delegation-adapter.d.ts.map