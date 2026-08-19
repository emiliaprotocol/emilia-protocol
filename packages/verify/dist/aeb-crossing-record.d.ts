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
import { type AebDigest } from "./aeb-adapter-contract.js";
import { SIGNATURE_AGILITY_VERSION, type AgileSignature, type AgileSigningKey, type AgileVerificationKey, type AgilityOptions } from "./pq-signature-agility.js";
export declare const AEB_CROSSING_RECORD_VERSION = "EP-AEB-CROSSING-RECORD-v1";
export declare const AEB_CROSSING_RECORD_DOMAIN = "EP-AEB-CROSSING-RECORD-v1\0";
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
export type AebCrossingRecordDraft = Omit<AebCrossingRecordBody, "signature_profile" | "contract_digest">;
export interface AebCrossingRecordIssueOptions extends AgilityOptions {
    signing_keys: AgileSigningKey[];
}
export interface AebCrossingRecordVerifyOptions extends AgilityOptions {
    verification_keys: AgileVerificationKey[];
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
export declare function crossingRecordSignedBytes(body: AebCrossingRecordBody): Uint8Array;
export declare function crossingRecordDigest(body: AebCrossingRecordBody): AebDigest;
export declare function mapWimseOAuthCrossingAuthority(input: WimseOAuthCrossingInput): CrossingAuthorityMappingResult;
export declare function mapBcrCrossingAuthority(input: BcrCrossingInput): CrossingAuthorityMappingResult;
export declare const WIMSE_OAUTH_CROSSING_ADAPTER: AebCrossingAuthorityAdapter<WimseOAuthCrossingInput>;
export declare const BCR_CROSSING_ADAPTER: AebCrossingAuthorityAdapter<BcrCrossingInput>;
export declare function issueAebCrossingRecord(draft: AebCrossingRecordDraft, options: AebCrossingRecordIssueOptions): Promise<AebCrossingRecord>;
export declare function verifyAebCrossingRecord(value: unknown, options: AebCrossingRecordVerifyOptions): Promise<AebCrossingRecordVerifyResult>;
//# sourceMappingURL=aeb-crossing-record.d.ts.map