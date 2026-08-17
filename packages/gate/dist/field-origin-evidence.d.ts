import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference hybrid
 * migration in docs/protocol/pq-hybrid-program.md, section "PATTERN: the
 * reference hybrid migration" (EP-REVOCATION-v2, packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of the
 *    proof, a wire-format change, so the artifact takes a new @version
 *    (EP-FIELD-ORIGIN-v0.2). verifyFieldOriginEvidence (v1) is untouched and
 *    refuses a v0.2 artifact on the version marker (verifyRiskBody's @version
 *    check) before inspecting any signature; it never throws.
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures` array
 *    shaped exactly like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }),
 *    one per algorithm in the registered order. Ed25519 keeps its base64url SPKI
 *    DER public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (fieldOriginV2SignedPayload below), under the same
 *    domain-separated `version\0canonicalize(body)` form the v1 risk-crypto signer
 *    uses. Drop the ML-DSA leg and narrow `required_algorithms` and the surviving
 *    Ed25519 signature no longer verifies. The verifier rebuilds the bytes from the
 *    REGISTERED set.
 * 4. V1 COMPATIBILITY. v1 artifacts keep verifying through the unchanged
 *    synchronous verifyFieldOriginEvidence; v0.2 verification is ASYNC (ML-DSA is
 *    async), so it is a SEPARATE entry point, with verifyFieldOriginEvidenceAny()
 *    routing on @version. Both verifiers share ONE policy body
 *    (evaluateFieldOriginBody) so they cannot drift.
 * 5. NAMED REFUSALS. Every failure returns a named reason; nothing throws on caller
 *    input, and INDETERMINATE never admits. An absent ML-DSA backend is
 *    'field_origin_pq_backend_unavailable', never a skipped check and never a pass
 *    on the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: this authenticates a pinned issuer's
 * assertions about field provenance bound to an exact action at admission; it does
 * not prove the asserted origin is true, detect prompt injection, authorize the
 * action, or prove an external effect. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently audited
 * and not a FIPS validated module. v0.2 does NOT retroactively protect v0.1 artifacts.
 */
export declare const FIELD_ORIGIN_EVIDENCE_V2_VERSION = "EP-FIELD-ORIGIN-v0.2";
export declare const FIELD_ORIGIN_EVIDENCE_V2_DOMAIN = "EP-FIELD-ORIGIN-v0.2\0";
/** The registered required algorithm set, in canonical order. */
export declare const FIELD_ORIGIN_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface FieldOriginV2TrustedKeys {
    [key_id: string]: {
        issuer_id: string;
        public_key: string;
        pq_public_key: string;
    };
}
export interface FieldOriginV2VerificationContext {
    trusted_keys: FieldOriginV2TrustedKeys;
    pinned_profile: RiskRecord;
    expected_relying_party_id: string;
    observed_action: RiskRecord;
    now: string;
}
/**
 * The bytes BOTH legs sign: the same domain-separated `version\0canonicalize(body)`
 * form as the v1 risk-crypto signer, plus the committed `required_algorithms` set.
 * `body` is the full v0.2 body (with @version and issuer) and WITHOUT proof.
 * Recomputed independently by the verifier from the PRESENTED body and the
 * REGISTERED set. See PATTERN move 3.
 */
export declare function fieldOriginV2SignedPayload(body: RiskRecord, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Mint a real hybrid v0.2 field-origin evidence artifact. Reuses the entire v1
 * body construction (signFieldOriginEvidence) so a v0.2 artifact carries an
 * identical, fully-validated body; only the proof shape and @version differ.
 * Issuance may throw on invalid local input; verification below never throws.
 */
export declare function signFieldOriginEvidenceV2(input: unknown, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
    pq_public_key: string;
    pq_private_key: string | Uint8Array;
}, options?: AgilityOptions): Promise<RiskRecord>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-FIELD-ORIGIN-v0.2 artifact. Never throws
 * on caller input; a v0.2 artifact NEVER verifies on one leg alone. After the
 * hybrid signature and structural checks pass, the SAME body-vs-context policy the
 * v1 verifier runs is applied via evaluateFieldOriginBody.
 */
export declare function verifyFieldOriginEvidenceV2(artifact: unknown, rawContext?: FieldOriginV2VerificationContext, options?: {
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<RiskRecord>;
/**
 * Route an artifact of EITHER version to its verifier. v1 artifacts keep the exact
 * v1 verdict; v0.2 artifacts get the hybrid check. An artifact whose @version is
 * neither refuses through the v1 verifier, which is fail-closed.
 */
export declare function verifyFieldOriginEvidenceAny(artifact: unknown, rawContext?: any, options?: any): Promise<RiskRecord>;
//# sourceMappingURL=field-origin-evidence.d.ts.map