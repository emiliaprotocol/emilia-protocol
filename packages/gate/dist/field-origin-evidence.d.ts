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
export declare const ORIGIN_LABELS_VERSION = "EP-ORIGIN-LABELS-v1";
export declare const ORIGIN_LABELS_CLAIM_BOUNDARY = "producer_asserted_origin_labels_checked_for_closed_vocabulary_internal_consistency_and_policy_trust_floor_at_admission_not_source_truth_not_producer_honesty";
/**
 * Most-trusted first. "derived" carries no rank of its own: its effective
 * floor is computed from derived_from under rule 3 above.
 */
export declare const ORIGIN_LABEL_TRUST_ORDER: readonly ["operator-config", "user-stated", "counterparty-document", "model-generated", "retrieved-untrusted"];
export declare const ORIGIN_LABELS: readonly ["operator-config", "user-stated", "counterparty-document", "model-generated", "retrieved-untrusted", "derived"];
export declare const ORIGIN_LABEL_DEFINITIONS: Readonly<{
    readonly 'user-stated': "The exact value was entered or spoken for this action by the accountable human principal, over a channel the producer attributes to that principal.";
    readonly 'operator-config': "The exact value was read from configuration pinned by the operating organization before this action was proposed, not from any per-action input.";
    readonly 'counterparty-document': "The exact value was taken from a document or message authored by an identified external counterparty to this transaction, such as an invoice or contract.";
    readonly 'retrieved-untrusted': "The exact value was obtained from content the producer retrieved from a source it neither controls nor treats as an identified counterparty, such as a web page, search result, inbound message body, or output of an uncontrolled tool.";
    readonly 'model-generated': "The exact value was produced by model inference from the model parameters alone; a value produced from any per-action source material is derived, not model-generated.";
    readonly derived: "The exact value was computed, summarized, extracted, reformatted, or otherwise produced from one or more source values, and the assertion carries derived_from naming the base label class of every contributing source.";
}>;
/**
 * Informative only: how the shipped EP-FIELD-ORIGIN-v0.1 origin classes map
 * onto this vocabulary when v0.1 is read as one implementation profile of a
 * generic origin-label input. This map does not change v0.1 verification.
 * v0.1 "unknown" has no target on purpose: it never admits there either.
 */
export declare const ORIGIN_LABELS_V01_PROFILE_MAP: Readonly<{
    readonly operator_pinned: "operator-config";
    readonly approver_supplied: "user-stated";
    readonly untrusted_bounded: "retrieved-untrusted";
    readonly derived_via_versioned_transform: "derived";
}>;
/**
 * Computes the effective trust floor of one label under the taint-preserving
 * propagation rule. Pure and non-throwing: an invalid combination returns a
 * null floor with a named reason instead of admitting or crashing.
 */
export declare function originLabelTrustFloor(label: unknown, derivedFrom?: unknown): {
    floor: string | null;
    reason: string | null;
};
/**
 * Evaluates one producer-asserted origin-label assertion set against a
 * relying-party policy of per-path minimum labels.
 *
 * Input (closed): { assertions, policy } where assertions is a bounded array
 * of closed { path, label, derived_from, value_digest } objects and policy is
 * a closed { rules } object of { path, minimum_label } entries. value_digest
 * is null or a sha256 digest of the exact value bytes; supplying digests opts
 * the producer into cross-path value-consistency checking.
 *
 * Fail-closed: every outcome is a frozen structured result; this function
 * never throws on hostile input, and INDETERMINATE never admits.
 */
export declare function evaluateOriginLabelAssertions(rawInput: unknown): RiskRecord;
//# sourceMappingURL=field-origin-evidence.d.ts.map