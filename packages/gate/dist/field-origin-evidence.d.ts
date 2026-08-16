import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const FIELD_ORIGIN_EVIDENCE_VERSION = "EP-FIELD-ORIGIN-v0.1";
export declare const FIELD_ORIGIN_CLAIM_BOUNDARY = "pinned_issuer_asserted_field_provenance_bound_to_exact_action_at_admission_not_source_truth_not_prompt_injection_detection_not_authorization_not_effect_truth";
export interface FieldOriginVerificationContext {
    trusted_keys: TrustedRiskKeys;
    pinned_profile: RiskRecord;
    expected_relying_party_id: string;
    observed_action: RiskRecord;
    now: string;
}
export declare class FieldOriginValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
export declare function pinFieldOriginProfile(profile: unknown): RiskRecord;
export declare function pinFieldOriginTrustedKeys(keys: unknown): TrustedRiskKeys;
export declare function fieldOriginProfileDigest(profile: unknown): string;
export declare function signFieldOriginEvidence(input: unknown, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function verifyFieldOriginEvidence(artifact: unknown, rawContext?: FieldOriginVerificationContext): RiskRecord;
//# sourceMappingURL=field-origin-evidence.d.ts.map