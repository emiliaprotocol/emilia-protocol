import { type AebDigest } from './aeb-adapter-contract.js';
import { type CrossingAuthorityMappingResult, type CrossingNativeStatus, type CrossingNativeVerification, type CrossingValidity } from './aeb-crossing-record.js';
export declare const AIC_JWT_JKT_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-JWT-JKT-v1";
export declare const AIC_X509_SPKI_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-X509-SPKI-v1";
export declare const AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-JWT-JKT-BOUND-v2";
export declare const AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-X509-SPKI-BOUND-v2";
export declare const AIC_ADMISSION_DOMAIN_VERSION = "EP-AIC-ADMISSION-DOMAIN-v1";
export declare const AIC_JWT_SVID_PROJECTION_VERSION = "EP-AIC-JWT-SVID-PROJECTION-v1";
export declare const AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION = "EP-AIC-X509-CREDENTIAL-BUNDLE-v1";
export declare const AIC_CROSSING_MAX_STATUS_AGE_SECONDS = 60;
export type AicSpkiHashAlgorithm = 'sha-256';
export type AicJwtDownstreamRepresentation = 'DIRECT' | 'SYNTHESIZED-X509';
export type AicPrincipalPublicJwk = {
    kty: 'EC';
    crv: string;
    x: string;
    y: string;
} | {
    kty: 'RSA';
    n: string;
    e: string;
} | {
    kty: 'OKP';
    crv: string;
    x: string;
};
export interface AicNativeVerifierDescriptor {
    id: string;
    version: string;
    implementation_digest: AebDigest;
}
export interface AicCrossingRelyingPartyPolicy {
    mapping_profile_id: string;
    mapping_profile_digest: AebDigest;
    action_projection_profile_id: string;
    action_projection_profile_digest: AebDigest;
    trusted_issuer_trust_anchor_digests: AebDigest[];
    native_verifier: AicNativeVerifierDescriptor;
}
export interface AicJwtCarrierProvenance {
    source_carrier: 'AIC-JWT-COMPACT';
    compact_token: string;
    presented_principal_jwk: AicPrincipalPublicJwk;
    downstream_representation: AicJwtDownstreamRepresentation;
}
export interface AicX509CarrierProvenance {
    source_carrier: 'AIC-X509-CREDENTIAL-BUNDLE';
    agent_certificate_der: string;
    principal_certificate_der: string;
}
export interface AicRfc7638JktBinding {
    kind: 'RFC7638_JKT';
    hash_alg: 'jkt';
    claimed_key_hash: string;
    presented_key_hash: string;
}
export interface AicX509SpkiBinding {
    kind: 'X509_SPKI';
    hash_alg: AicSpkiHashAlgorithm;
    claimed_key_hash: string;
    presented_key_hash: string;
}
interface AicCrossingCommonInput {
    native_verification: CrossingNativeVerification;
    native_verifier: AicNativeVerifierDescriptor;
    native_verification_evidence_digest: AebDigest;
    issuer: string;
    subject: string;
    artifact_id: string;
    artifact_digest: AebDigest;
    issuer_trust_anchor_digest: AebDigest;
    constraints_digest: AebDigest;
    status: CrossingNativeStatus;
    validity: CrossingValidity;
}
export interface AicCrossingExactAction {
    caid: string;
    action_digest: AebDigest;
}
export interface AicCrossingAdmissionDomain {
    relying_party_id: string;
    audience: string;
    executor_id: string;
    state_domain_id: string;
}
export interface AicCrossingRequestBinding {
    action_projection_profile_id: string;
    action_projection_profile_digest: AebDigest;
    requested_capability_digest: AebDigest;
    projected_action: AicCrossingExactAction;
    projected_admission_domain_digest: AebDigest;
}
export interface AicCrossingRelyingPartyContext {
    action: AicCrossingExactAction;
    admission_domain: AicCrossingAdmissionDomain;
    requested_capability_digest: AebDigest;
    evaluated_at: string;
    max_status_age_seconds: number;
    policy: AicCrossingRelyingPartyPolicy;
}
export interface AicCrossingRelyingPartyTemporalContext {
    evaluated_at: string;
    max_status_age_seconds: number;
}
export interface AicJwtJktCrossingInput extends AicCrossingCommonInput {
    carrier_provenance: AicJwtCarrierProvenance;
    principal_binding: AicRfc7638JktBinding;
}
export interface AicX509SpkiCrossingInput extends AicCrossingCommonInput {
    carrier_provenance: AicX509CarrierProvenance;
    principal_binding: AicX509SpkiBinding;
}
export interface AicJwtJktBoundCrossingInput extends AicJwtJktCrossingInput {
    request_binding: AicCrossingRequestBinding;
}
export interface AicX509SpkiBoundCrossingInput extends AicX509SpkiCrossingInput {
    request_binding: AicCrossingRequestBinding;
}
export type AicJwtSvidProjectionPurpose = 'WORKLOAD_IDENTITY_ONLY' | 'AIC_AUTHORITY';
export interface AicJwtSvidProjectionInput {
    source: AicJwtJktCrossingInput;
    purpose: AicJwtSvidProjectionPurpose;
    audience: string[];
    issued_at: number;
    not_before: number | null;
    expires_at: number;
    token_id: string;
    projected_algorithm: 'ES256' | 'RS256';
    projected_key_id: string;
}
export interface AicJwtSvidProjectionRelyingPartyContext {
    relying_party_policy: AicCrossingRelyingPartyPolicy;
    evaluated_at: string;
    max_status_age_seconds: number;
}
export interface AicStrictJwtSvidProjection {
    '@version': typeof AIC_JWT_SVID_PROJECTION_VERSION;
    protected_header: {
        alg: 'ES256' | 'RS256';
        kid: string;
        typ: 'JWT';
    };
    payload: {
        sub: string;
        aud: string;
        iat: number;
        exp: number;
        nbf?: number;
        jti: string;
    };
    source: {
        typ: 'aic+jwt';
        issuer: string;
        token_digest: AebDigest;
        source_semantics_digest: AebDigest;
    };
    purpose: 'WORKLOAD_IDENTITY_ONLY';
    omitted_source_members: string[];
    authority_semantics_preserved: false;
    new_signature_required: true;
    compact_token: null;
    authorization_decision: false;
    projection_digest: AebDigest;
}
export type AicJwtSvidProjectionResult = {
    ok: true;
    projection: AicStrictJwtSvidProjection;
} | {
    ok: false;
    reason: string;
};
export declare function mapAicJwtJktCrossingAuthority(input: AicJwtJktCrossingInput, policy: AicCrossingRelyingPartyPolicy, temporalContext?: AicCrossingRelyingPartyTemporalContext): CrossingAuthorityMappingResult;
export declare function mapAicX509SpkiCrossingAuthority(input: AicX509SpkiCrossingInput, policy: AicCrossingRelyingPartyPolicy, temporalContext?: AicCrossingRelyingPartyTemporalContext): CrossingAuthorityMappingResult;
export declare function mapAicJwtJktBoundCrossingAuthority(input: AicJwtJktBoundCrossingInput, context: AicCrossingRelyingPartyContext): CrossingAuthorityMappingResult;
export declare function mapAicX509SpkiBoundCrossingAuthority(input: AicX509SpkiBoundCrossingInput, context: AicCrossingRelyingPartyContext): CrossingAuthorityMappingResult;
export declare function projectAicJwtToStrictJwtSvid(input: AicJwtSvidProjectionInput, context: AicJwtSvidProjectionRelyingPartyContext): AicJwtSvidProjectionResult;
export {};
//# sourceMappingURL=aeb-aic-crossing-adapter.d.ts.map