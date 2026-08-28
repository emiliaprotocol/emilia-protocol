/**
 * AIC native-authority mappings for EP-AEB-CROSSING-RECORD-v1.
 *
 * The adapter consumes the result of an AIC native verifier. It does not
 * reimplement AIC-JWT signature, delegation, capability, constraint, status,
 * or X.509 path validation. It keeps the RFC 7638 JWK-thumbprint and X.509
 * SPKI-hash paths separate and requires the relying party to pin the native
 * issuer trust anchor independently of the presented artifact.
 *
 * The JWT-SVID helper emits only a to-be-signed identity projection. Rewriting
 * the protected header would invalidate the AIC-JWT signature, so a deployment
 * must issue a new typ=JWT token under a key in its JWT-SVID bundle. The
 * projection is never an AIC authority decision.
 */
import { type AebDigest } from './aeb-adapter-contract.js';
import { type CrossingAuthorityMappingResult, type CrossingNativeStatus, type CrossingNativeVerification, type CrossingValidity } from './aeb-crossing-record.js';
export declare const AIC_JWT_JKT_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-JWT-JKT-v1";
export declare const AIC_X509_SPKI_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-X509-SPKI-v1";
export declare const AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-JWT-JKT-BOUND-v2";
export declare const AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE = "EP-AEB-CROSSING-AIC-X509-SPKI-BOUND-v2";
export declare const AIC_ADMISSION_DOMAIN_VERSION = "EP-AIC-ADMISSION-DOMAIN-v1";
export declare const AIC_JWT_SVID_PROJECTION_VERSION = "EP-AIC-JWT-SVID-PROJECTION-v1";
export type AicSpkiHashAlgorithm = 'sha-256' | 'sha-384' | 'sha-512';
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
    issuer: string;
    subject: string;
    artifact_id: string;
    artifact_digest: AebDigest;
    issuer_trust_anchor_digest: AebDigest;
    trusted_issuer_trust_anchor_digests: AebDigest[];
    mapping_profile_digest: AebDigest;
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
    evaluated_at: string;
    max_status_age_seconds: number;
}
export interface AicJwtJktCrossingInput extends AicCrossingCommonInput {
    native_typ: 'aic+jwt';
    principal_binding: AicRfc7638JktBinding;
}
export interface AicX509SpkiCrossingInput extends AicCrossingCommonInput {
    native_type: 'AIC-X509';
    certificate_serial: string;
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
    has_constraints: boolean;
    delegation_mode: 'authorized' | 'representative';
    has_delegation_assertion: boolean;
    confirmation_key_present: boolean;
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
export declare function mapAicJwtJktCrossingAuthority(input: AicJwtJktCrossingInput): CrossingAuthorityMappingResult;
export declare function mapAicX509SpkiCrossingAuthority(input: AicX509SpkiCrossingInput): CrossingAuthorityMappingResult;
export declare function mapAicJwtJktBoundCrossingAuthority(input: AicJwtJktBoundCrossingInput, context: AicCrossingRelyingPartyContext): CrossingAuthorityMappingResult;
export declare function mapAicX509SpkiBoundCrossingAuthority(input: AicX509SpkiBoundCrossingInput, context: AicCrossingRelyingPartyContext): CrossingAuthorityMappingResult;
export declare function projectAicJwtToStrictJwtSvid(input: AicJwtSvidProjectionInput): AicJwtSvidProjectionResult;
export {};
//# sourceMappingURL=aeb-aic-crossing-adapter.d.ts.map