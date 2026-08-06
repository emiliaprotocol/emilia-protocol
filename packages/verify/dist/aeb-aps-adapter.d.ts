import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const APS_DRAFT_REVISION = "draft-pidlisnyi-aps-03";
export declare const APS_AEB_ADAPTER_ID = "native:aps-policy-decision";
export declare const APS_AEB_ADAPTER_VERSION = "1";
export declare const APS_AEB_CONFIG_VERSION = "AEB-APS-CONFIG-v1";
export declare const APS_TRUST_ROOT_VERSION = "AEB-APS-ED25519-ROOT-v1";
export declare const APS_CAID_MAPPING_VERSION = "AEB-APS-CAID-MAPPING-v1";
export declare const APS_CAID_MAPPER_ID = "mapper:aps-exact-action-v1";
export interface ApsAuthorityVerifierDescriptor {
    id: string;
    version: string;
    implementation_digest: AebDigest;
}
export interface ApsAuthorityVerificationInput {
    authority_state: unknown;
    delegation_ref: string;
    effective_authority_ref: string;
    subject_agent: string;
    issued_at: string;
    now: string;
}
export interface ApsAuthorityVerifier extends ApsAuthorityVerifierDescriptor {
    verify(input: ApsAuthorityVerificationInput): {
        verified: boolean;
        reason: string | null;
    };
}
export interface ApsAdapterConfig {
    '@version': typeof APS_AEB_CONFIG_VERSION;
    evidence_role: string;
    subject: {
        id: string;
        kind: 'organization' | 'system';
        native_id: string;
    };
    action_type: string;
    authority_verifier: ApsAuthorityVerifierDescriptor;
    clock_skew_seconds: number;
    max_receipt_age_seconds: number;
    max_status_age_seconds: number;
}
export interface ApsTrustRoot {
    '@version': typeof APS_TRUST_ROOT_VERSION;
    signer: string;
    key_id: string;
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface ApsConstructorPins {
    config: ApsAdapterConfig;
    trust_roots: readonly ApsTrustRoot[];
    authority_verifier: ApsAuthorityVerifier;
}
export declare function computeApsPayloadRef(payload: unknown): string;
export declare function computeApsActionRef(inputObject: unknown): string;
export declare function computeApsReceiptId(receipt: unknown): string;
export declare function computeApsDecisionRef(input: {
    action_ref: string;
    authority_state: unknown;
    policy_input: unknown;
    decision_context: unknown;
    decision_output: unknown;
}): string;
export declare function createApsActionDefinition(actionType: string): Obj;
export declare function createApsAebAdapter(constructorPins: ApsConstructorPins): AebAdapter;
export {};
//# sourceMappingURL=aeb-aps-adapter.d.ts.map