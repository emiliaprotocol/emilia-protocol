/**
 * EP-AEB-CROSSING-RECORD-v1
 *
 * A carrier-neutral, offline-verifiable record that one relying-party boundary
 * evaluated one exact action under one native authority instance. The record
 * is evidence only: verification never authorizes a later crossing.
 *
 * Native authority is an open set behind one closed projection contract. The
 * two reference mappings below demonstrate an authorization-server grant and
 * a bounded-capability receipt without claiming that the native systems are
 * equivalent. They share the record schema and verifier, not record bytes.
 */
import { AEB_EVALUATION_VERSION, AEB_EVALUATION_V2_VERSION, type AebDigest } from "./aeb-adapter-contract.js";
import { SIGNATURE_AGILITY_VERSION, type AgileSignature, type AgileSigningKey, type AgileVerificationKey, type AgilityOptions } from "./pq-signature-agility.js";
export declare const AEB_CROSSING_RECORD_VERSION = "EP-AEB-CROSSING-RECORD-v1";
export declare const AEB_CROSSING_RECORD_DOMAIN = "EP-AEB-CROSSING-RECORD-v1\0";
export declare const AEB_CROSSING_RECORD_V2_VERSION = "EP-AEB-CROSSING-RECORD-v2";
export declare const AEB_CROSSING_RECORD_V2_DOMAIN = "EP-AEB-CROSSING-RECORD-v2\0";
/**
 * A separate, derived lifecycle index.  This MUST NOT be confused with or
 * relabeled as the already shipped EP-AEB-CROSSING-RECORD-v2 profile above.
 */
export declare const AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION = "EP-AEB-CROSSING-LIFECYCLE-INDEX-v2";
export declare const AEB_CROSSING_LIFECYCLE_INDEX_V2_DOMAIN = "EP-AEB-CROSSING-LIFECYCLE-INDEX-v2\0";
export declare const AEB_CROSSING_RECORD_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export declare const WIMSE_OAUTH_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-WIMSE-OAUTH-v1";
export declare const BCR_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-BCR-v1";
export type CrossingNativeVerification = "VERIFIED" | "FAILED" | "INDETERMINATE";
export type CrossingRpAcceptance = "ACCEPTED" | "REJECTED" | "INDETERMINATE";
export type CrossingActionRelation = "EXACT_MATCH" | "MISMATCH" | "INDETERMINATE";
export type CrossingStatus = "CURRENT" | "STALE" | "UNAVAILABLE" | "REVOKED" | "INDETERMINATE";
export type CrossingReplay = "FRESH" | "REPLAY" | "INDETERMINATE";
export type CrossingAdmission = "ADMIT" | "REFUSE" | "INDETERMINATE" | "NOT_APPLICABLE";
export type CrossingCustody = "UNRESERVED" | "RESERVED" | "INVOKING" | "INDETERMINATE" | "TERMINAL";
export type CrossingProviderCommitment = "NOT_INVOKED" | "COMMITTED" | "PROVEN_NOT_COMMITTED" | "INDETERMINATE";
export type CrossingObservedEffect = "NOT_OBSERVED" | "OBSERVED_AS_REQUESTED" | "DIVERGED" | "INDETERMINATE";
export type CrossingRetry = "NOT_APPLICABLE" | "REFUSE" | "REQUIRES_NEW_ADMISSION";
export type CrossingReconciliation = "NOT_APPLICABLE" | "REQUIRED" | "REFUSED" | "APPLIED";
export type AdmissionReferenceState = "PRESENT" | "MISSING" | "NOT_APPLICABLE" | "INDETERMINATE";
export interface CrossingNativeStatus {
    value: CrossingStatus;
    checked_at: string;
    source_head_digest: AebDigest;
}
export interface CrossingValidity {
    not_before: string;
    not_after: string;
}
export interface CrossingNativeAuthority {
    adapter_id: string;
    adapter_version: string;
    mapping_profile_id: string;
    mapping_profile_digest: AebDigest;
    native_profile: string;
    issuer: string;
    subject: string;
    authority_instance_digest: AebDigest;
    evidence_digest: AebDigest;
    replay_unit: AebDigest;
    native_verification: CrossingNativeVerification;
    rp_acceptance: CrossingRpAcceptance;
    status: CrossingNativeStatus;
    constraints_digest: AebDigest;
    validity: CrossingValidity;
}
export interface CrossingRefereeAxes {
    native_verification: CrossingNativeVerification;
    rp_acceptance: CrossingRpAcceptance;
    action_relation: CrossingActionRelation;
    status: CrossingStatus;
    replay: CrossingReplay;
    admission: CrossingAdmission;
    custody: CrossingCustody;
    provider_commitment: CrossingProviderCommitment;
    observed_effect: CrossingObservedEffect;
    retry: CrossingRetry;
    reconciliation: CrossingReconciliation;
    reason_codes: string[];
}
export interface CrossingAdmissionReference {
    state: AdmissionReferenceState;
    digest: AebDigest | null;
}
export interface AebCrossingRecordBody {
    record_id: string;
    operation_id: string;
    issued_at: string;
    signature_profile: {
        id: typeof SIGNATURE_AGILITY_VERSION;
        required_algorithms: string[];
    };
    native_authority: CrossingNativeAuthority;
    action: {
        caid: string;
        action_digest: AebDigest;
    };
    boundary: {
        relying_party_id: string;
        audience: string;
        executor_id: string;
        state_domain_id: string;
    };
    requirements: {
        admission_digest: AebDigest;
        review_digest: AebDigest;
    };
    contract_digest: AebDigest;
    admission_reference: CrossingAdmissionReference;
    lifecycle_records: {
        evaluation_digest: AebDigest;
        consumption_digest: AebDigest | null;
        provider_entry_digest: AebDigest | null;
    };
    evaluated_evidence_digests: AebDigest[];
    configuration_digests: AebDigest[];
    referee: CrossingRefereeAxes;
}
export interface AebCrossingRecord {
    "@version": typeof AEB_CROSSING_RECORD_VERSION;
    body: AebCrossingRecordBody;
    signatures: AgileSignature[];
}
export interface CrossingAdmissionDomain {
    relying_party_id: string;
    audience: string;
    executor_id: string;
    state_domain_id: string;
}
export interface AebCrossingRecordV2Body extends AebCrossingRecordBody {
    admission_domain_digest: AebDigest;
}
export interface AebCrossingRecordV2 {
    "@version": typeof AEB_CROSSING_RECORD_V2_VERSION;
    body: AebCrossingRecordV2Body;
    signatures: AgileSignature[];
}
export type AebCrossingEvaluationProfile = typeof AEB_EVALUATION_VERSION | typeof AEB_EVALUATION_V2_VERSION;
export type AebCrossingCustodyReferencePhase = "NOT_APPLICABLE" | "RESERVATION" | "CONSUMPTION" | "INDETERMINATE";
export interface AebCrossingCustodyReference {
    phase: AebCrossingCustodyReferencePhase;
    digest: AebDigest | null;
}
export type AebCrossingLifecycleIndexConversionStatus = "NATIVE" | "COMPLETE" | "INDETERMINATE";
export interface AebCrossingLifecycleIndexV2Body {
    record_id: string;
    operation_id: string;
    issued_at: string;
    signature_profile: {
        id: typeof SIGNATURE_AGILITY_VERSION;
        required_algorithms: string[];
    };
    action: {
        caid: string;
        action_digest: AebDigest;
    };
    admission_domain_digest: AebDigest;
    lifecycle: {
        evaluation: {
            profile: AebCrossingEvaluationProfile;
            digest: AebDigest;
        };
        /** Reference only. The native/local decision remains authoritative. */
        local_admission_digest: AebDigest | null;
        authority_custody: AebCrossingCustodyReference;
        provider_entry_digest: AebDigest | null;
        effect_observation_digest: AebDigest | null;
        provider_outcome_digest: AebDigest | null;
        reconciliation_digest: AebDigest | null;
    };
    source_crossing_record: {
        version: typeof AEB_CROSSING_RECORD_VERSION | typeof AEB_CROSSING_RECORD_V2_VERSION | null;
        digest: AebDigest | null;
    };
    conversion: {
        status: AebCrossingLifecycleIndexConversionStatus;
        reason_codes: string[];
    };
    contract_digest: AebDigest;
    /** A lifecycle index is evidence and never a bearer authorization. */
    execution_authorizing: false;
}
export interface AebCrossingLifecycleIndexV2 {
    "@version": typeof AEB_CROSSING_LIFECYCLE_INDEX_V2_VERSION;
    body: AebCrossingLifecycleIndexV2Body;
    signatures: AgileSignature[];
}
export type AebCrossingLifecycleIndexV2Draft = Omit<AebCrossingLifecycleIndexV2Body, "signature_profile" | "admission_domain_digest" | "contract_digest">;
export interface AebCrossingLifecycleIndexV2Context {
    action: AebCrossingRecordBody["action"];
    admission_domain: CrossingAdmissionDomain;
    evaluation: AebCrossingLifecycleIndexV2Body["lifecycle"]["evaluation"];
}
export interface AebCrossingLifecycleIndexV2VerifyOptions extends AebCrossingRecordVerifyOptions {
    expected_action: AebCrossingRecordBody["action"];
    admission_domain: CrossingAdmissionDomain;
    expected_evaluation: AebCrossingLifecycleIndexV2Body["lifecycle"]["evaluation"];
}
export interface AebCrossingLifecycleIndexV2VerifyResult {
    verified: boolean;
    reason: string | null;
    execution_authorizing: false;
    record_digest: AebDigest | null;
    conversion_status: AebCrossingLifecycleIndexConversionStatus | null;
    checks: {
        schema: boolean;
        algorithm_set: boolean | null;
        action: boolean | null;
        admission_domain: boolean | null;
        evaluation: boolean | null;
        contract_digest: boolean | null;
        lifecycle_order: boolean | null;
        signature_set: boolean | null;
    };
}
export type AebCrossingRecordV2Draft = Omit<AebCrossingRecordV2Body, "signature_profile" | "admission_domain_digest" | "contract_digest">;
export interface AebCrossingRecordV2IssuanceContext {
    action: AebCrossingRecordBody["action"];
    admission_domain: CrossingAdmissionDomain;
}
export type AebCrossingRecordDraft = Omit<AebCrossingRecordBody, "signature_profile" | "contract_digest">;
export interface AebCrossingRecordIssueOptions extends AgilityOptions {
    signing_keys: AgileSigningKey[];
}
export interface AebCrossingRecordVerifyOptions extends AgilityOptions {
    verification_keys: AgileVerificationKey[];
}
export interface AebCrossingRecordV1UpgradeOptions extends AebCrossingRecordIssueOptions {
    /** Pinned keys used to verify the source before a converted index is signed. */
    source_verification_keys: AgileVerificationKey[];
}
export interface AebCrossingRecordVerifyResult {
    verified: boolean;
    reason: string | null;
    execution_authorizing: false;
    record_digest: AebDigest | null;
    checks: {
        schema: boolean;
        algorithm_set: boolean | null;
        authority: boolean | null;
        contract_digest: boolean | null;
        admission_reference: boolean | null;
        semantics: boolean | null;
        signature_set: boolean | null;
    };
}
export interface AebCrossingRecordV2VerifyResult extends AebCrossingRecordVerifyResult {
    checks: AebCrossingRecordVerifyResult["checks"] & {
        admission_domain: boolean | null;
    };
}
export type CrossingAuthorityMappingResult = {
    ok: true;
    authority: CrossingNativeAuthority;
} | {
    ok: false;
    reason: string;
};
export interface WimseOAuthCrossingInput {
    native_verification: CrossingNativeVerification;
    rp_acceptance: CrossingRpAcceptance;
    authorization_server: string;
    subject: string;
    token_id: string;
    token_digest: AebDigest;
    mapping_profile_digest: AebDigest;
    constraints_digest: AebDigest;
    status: CrossingNativeStatus;
    validity: CrossingValidity;
}
export interface BcrCrossingInput {
    native_verification: CrossingNativeVerification;
    rp_acceptance: CrossingRpAcceptance;
    issuer: string;
    subject: string;
    capability_id: string;
    generation: number;
    receipt_digest: AebDigest;
    mapping_profile_digest: AebDigest;
    constraints_digest: AebDigest;
    status: CrossingNativeStatus;
    validity: CrossingValidity;
}
export interface AebCrossingAuthorityAdapter<T> {
    id: string;
    version: string;
    mapping_profile_id: string;
    map(input: T): CrossingAuthorityMappingResult;
}
export declare function crossingRecordContractDigest(body: Pick<AebCrossingRecordBody, "native_authority" | "action" | "boundary" | "requirements">): AebDigest;
export declare function crossingRecordV2AdmissionDomainDigest(boundary: CrossingAdmissionDomain): AebDigest;
export declare function crossingRecordV2ContractDigest(body: Pick<AebCrossingRecordV2Body, "native_authority" | "action" | "requirements" | "admission_domain_digest">): AebDigest;
export declare function crossingRecordSignedBytes(body: AebCrossingRecordBody): Uint8Array;
export declare function crossingRecordDigest(body: AebCrossingRecordBody): AebDigest;
export declare function crossingRecordV2SignedBytes(body: AebCrossingRecordV2Body): Uint8Array;
export declare function crossingRecordV2Digest(body: AebCrossingRecordV2Body): AebDigest;
export declare function crossingLifecycleIndexV2AdmissionDomainDigest(boundary: CrossingAdmissionDomain): AebDigest;
export declare function crossingLifecycleIndexV2ContractDigest(body: Pick<AebCrossingLifecycleIndexV2Body, "operation_id" | "action" | "admission_domain_digest" | "lifecycle">): AebDigest;
export declare function crossingLifecycleIndexV2SignedBytes(body: AebCrossingLifecycleIndexV2Body): Uint8Array;
export declare function crossingLifecycleIndexV2Digest(body: AebCrossingLifecycleIndexV2Body): AebDigest;
export declare function mapWimseOAuthCrossingAuthority(input: WimseOAuthCrossingInput): CrossingAuthorityMappingResult;
export declare function mapBcrCrossingAuthority(input: BcrCrossingInput): CrossingAuthorityMappingResult;
export declare const WIMSE_OAUTH_CROSSING_ADAPTER: AebCrossingAuthorityAdapter<WimseOAuthCrossingInput>;
export declare const BCR_CROSSING_ADAPTER: AebCrossingAuthorityAdapter<BcrCrossingInput>;
export declare function issueAebCrossingRecord(draft: AebCrossingRecordDraft, options: AebCrossingRecordIssueOptions): Promise<AebCrossingRecord>;
export declare function issueAebCrossingRecordV2(draft: AebCrossingRecordV2Draft, context: AebCrossingRecordV2IssuanceContext, options: AebCrossingRecordIssueOptions): Promise<AebCrossingRecordV2>;
/**
 * Issues the derived lifecycle index.  It references the native/local
 * admission and provider records by digest; it does not flatten or reproduce
 * their decisions.
 */
export declare function issueAebCrossingLifecycleIndexV2(draft: AebCrossingLifecycleIndexV2Draft, context: AebCrossingLifecycleIndexV2Context, options: AebCrossingRecordIssueOptions): Promise<AebCrossingLifecycleIndexV2>;
/**
 * Deterministically converts a structurally valid v1 crossing record into the
 * new lifecycle index.  Any v1 axis that asserted later lifecycle state
 * without a corresponding record digest is reported as INDETERMINATE rather
 * than copied as if it were independently verifiable.
 */
export declare function upgradeAebCrossingRecordV1ToLifecycleIndexV2(source: AebCrossingRecord, options: AebCrossingRecordV1UpgradeOptions): Promise<AebCrossingLifecycleIndexV2>;
export declare function verifyAebCrossingRecord(value: unknown, options: AebCrossingRecordVerifyOptions): Promise<AebCrossingRecordVerifyResult>;
export declare function verifyAebCrossingRecordV2(value: unknown, options: AebCrossingRecordVerifyOptions): Promise<AebCrossingRecordV2VerifyResult>;
export declare function verifyAebCrossingLifecycleIndexV2(value: unknown, options: AebCrossingLifecycleIndexV2VerifyOptions): Promise<AebCrossingLifecycleIndexV2VerifyResult>;
//# sourceMappingURL=aeb-crossing-record.d.ts.map