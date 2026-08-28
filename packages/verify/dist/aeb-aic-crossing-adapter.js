// SPDX-License-Identifier: Apache-2.0
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
import { digestAebTyped, } from './aeb-adapter-contract.js';
export const AIC_JWT_JKT_CROSSING_MAPPING_PROFILE = 'EP-AEB-CROSSING-AIC-JWT-JKT-v1';
export const AIC_X509_SPKI_CROSSING_MAPPING_PROFILE = 'EP-AEB-CROSSING-AIC-X509-SPKI-v1';
export const AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE = 'EP-AEB-CROSSING-AIC-JWT-JKT-BOUND-v2';
export const AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE = 'EP-AEB-CROSSING-AIC-X509-SPKI-BOUND-v2';
export const AIC_ADMISSION_DOMAIN_VERSION = 'EP-AIC-ADMISSION-DOMAIN-v1';
export const AIC_JWT_SVID_PROJECTION_VERSION = 'EP-AIC-JWT-SVID-PROJECTION-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/#-]{0,511}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const CERTIFICATE_SERIAL_RE = /^[0-9A-F]{2,128}$/;
const COMMON_KEYS = new Set([
    'native_verification',
    'issuer',
    'subject',
    'artifact_id',
    'artifact_digest',
    'issuer_trust_anchor_digest',
    'trusted_issuer_trust_anchor_digests',
    'mapping_profile_digest',
    'constraints_digest',
    'status',
    'validity',
]);
const JWT_INPUT_KEYS = new Set([...COMMON_KEYS, 'native_typ', 'principal_binding']);
const X509_INPUT_KEYS = new Set([
    ...COMMON_KEYS,
    'native_type',
    'certificate_serial',
    'principal_binding',
]);
const BOUND_JWT_INPUT_KEYS = new Set([...JWT_INPUT_KEYS, 'request_binding']);
const BOUND_X509_INPUT_KEYS = new Set([...X509_INPUT_KEYS, 'request_binding']);
const REQUEST_BINDING_KEYS = new Set([
    'action_projection_profile_id',
    'action_projection_profile_digest',
    'requested_capability_digest',
    'projected_action',
    'projected_admission_domain_digest',
]);
const ACTION_KEYS = new Set(['caid', 'action_digest']);
const ADMISSION_DOMAIN_KEYS = new Set([
    'relying_party_id',
    'audience',
    'executor_id',
    'state_domain_id',
]);
const RP_CONTEXT_KEYS = new Set([
    'action',
    'admission_domain',
    'evaluated_at',
    'max_status_age_seconds',
]);
const BINDING_KEYS = new Set([
    'kind',
    'hash_alg',
    'claimed_key_hash',
    'presented_key_hash',
]);
const STATUS_KEYS = new Set(['value', 'checked_at', 'source_head_digest']);
const VALIDITY_KEYS = new Set(['not_before', 'not_after']);
const PROJECTION_INPUT_KEYS = new Set([
    'source',
    'purpose',
    'audience',
    'issued_at',
    'not_before',
    'expires_at',
    'token_id',
    'projected_algorithm',
    'projected_key_id',
    'has_constraints',
    'delegation_mode',
    'has_delegation_assertion',
    'confirmation_key_present',
]);
const NATIVE_VERIFICATIONS = new Set([
    'VERIFIED',
    'FAILED',
    'INDETERMINATE',
]);
const STATUSES = new Set([
    'CURRENT',
    'STALE',
    'UNAVAILABLE',
    'REVOKED',
    'INDETERMINATE',
]);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    const keys = Reflect.ownKeys(value);
    return keys.length === expected.size
        && keys.every((key) => typeof key === 'string' && expected.has(key));
}
function identifier(value) {
    return typeof value === 'string'
        && IDENTIFIER_RE.test(value)
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function digest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function instant(value) {
    return typeof value === 'string'
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)
        && Number.isFinite(Date.parse(value));
}
function validStatus(value) {
    return isRecord(value)
        && exactKeys(value, STATUS_KEYS)
        && typeof value.value === 'string'
        && STATUSES.has(value.value)
        && instant(value.checked_at)
        && digest(value.source_head_digest);
}
function validValidity(value) {
    return isRecord(value)
        && exactKeys(value, VALIDITY_KEYS)
        && instant(value.not_before)
        && instant(value.not_after)
        && Date.parse(value.not_before) < Date.parse(value.not_after);
}
function validAction(value) {
    return isRecord(value)
        && exactKeys(value, ACTION_KEYS)
        && typeof value.caid === 'string'
        && CAID_RE.test(value.caid)
        && digest(value.action_digest);
}
function validAdmissionDomain(value) {
    return isRecord(value)
        && exactKeys(value, ADMISSION_DOMAIN_KEYS)
        && identifier(value.relying_party_id)
        && identifier(value.audience)
        && identifier(value.executor_id)
        && identifier(value.state_domain_id);
}
function validRequestBinding(value) {
    return isRecord(value)
        && exactKeys(value, REQUEST_BINDING_KEYS)
        && identifier(value.action_projection_profile_id)
        && digest(value.action_projection_profile_digest)
        && digest(value.requested_capability_digest)
        && validAction(value.projected_action)
        && digest(value.projected_admission_domain_digest);
}
function validRelyingPartyContext(value) {
    return isRecord(value)
        && exactKeys(value, RP_CONTEXT_KEYS)
        && validAction(value.action)
        && validAdmissionDomain(value.admission_domain)
        && instant(value.evaluated_at)
        && Number.isSafeInteger(value.max_status_age_seconds)
        && Number(value.max_status_age_seconds) >= 0
        && Number(value.max_status_age_seconds) <= 86_400;
}
function validTrustSet(value) {
    return Array.isArray(value)
        && value.length > 0
        && value.length <= 64
        && value.every(digest)
        && new Set(value).size === value.length;
}
function commonValid(value) {
    return NATIVE_VERIFICATIONS.has(value.native_verification)
        && identifier(value.issuer)
        && identifier(value.subject)
        && identifier(value.artifact_id)
        && digest(value.artifact_digest)
        && digest(value.issuer_trust_anchor_digest)
        && Array.isArray(value.trusted_issuer_trust_anchor_digests)
        && value.trusted_issuer_trust_anchor_digests.length <= 64
        && value.trusted_issuer_trust_anchor_digests.every(digest)
        && new Set(value.trusted_issuer_trust_anchor_digests).size
            === value.trusted_issuer_trust_anchor_digests.length
        && digest(value.mapping_profile_digest)
        && digest(value.constraints_digest)
        && validStatus(value.status)
        && validValidity(value.validity);
}
function expectedHashLength(hashAlg) {
    if (hashAlg === 'sha-384')
        return 64;
    if (hashAlg === 'sha-512')
        return 86;
    return 43;
}
function keyHash(value, hashAlg) {
    return typeof value === 'string'
        && value.length === expectedHashLength(hashAlg)
        && BASE64URL_RE.test(value);
}
function validJktBinding(value) {
    return isRecord(value)
        && exactKeys(value, BINDING_KEYS)
        && value.kind === 'RFC7638_JKT'
        && value.hash_alg === 'jkt'
        && keyHash(value.claimed_key_hash, 'jkt')
        && keyHash(value.presented_key_hash, 'jkt');
}
function validSpkiBinding(value) {
    if (!isRecord(value) || !exactKeys(value, BINDING_KEYS))
        return false;
    if (value.kind !== 'X509_SPKI')
        return false;
    if (!['sha-256', 'sha-384', 'sha-512'].includes(String(value.hash_alg)))
        return false;
    const hashAlg = value.hash_alg;
    return keyHash(value.claimed_key_hash, hashAlg)
        && keyHash(value.presented_key_hash, hashAlg);
}
function trustDisposition(input) {
    if (input.native_verification === 'FAILED')
        return 'aic_native_verification_failed';
    if (input.native_verification === 'INDETERMINATE') {
        return 'aic_native_verification_indeterminate';
    }
    if (!validTrustSet(input.trusted_issuer_trust_anchor_digests)
        || !input.trusted_issuer_trust_anchor_digests.includes(input.issuer_trust_anchor_digest)) {
        return 'aic_issuer_untrusted';
    }
    return null;
}
function authorityFrom(input, native) {
    return {
        adapter_id: native.adapterId,
        adapter_version: '1',
        mapping_profile_id: native.mappingProfile,
        mapping_profile_digest: input.mapping_profile_digest,
        native_profile: native.nativeProfile,
        issuer: input.issuer,
        subject: input.subject,
        authority_instance_digest: digestAebTyped({
            native_profile: native.nativeProfile,
            issuer: input.issuer,
            subject: input.subject,
            artifact_id: input.artifact_id,
            artifact_digest: input.artifact_digest,
            issuer_trust_anchor_digest: input.issuer_trust_anchor_digest,
            principal_binding: native.binding,
            native: native.instanceContext,
        }, `${native.mappingProfile}:authority-instance`),
        evidence_digest: input.artifact_digest,
        replay_unit: digestAebTyped({
            issuer: input.issuer,
            artifact_id: input.artifact_id,
            native: native.replayContext,
        }, `${native.mappingProfile}:replay-unit`),
        native_verification: 'VERIFIED',
        rp_acceptance: 'ACCEPTED',
        status: structuredClone(input.status),
        constraints_digest: input.constraints_digest,
        validity: structuredClone(input.validity),
    };
}
function boundDisposition(input, context) {
    const trust = trustDisposition(input);
    if (trust)
        return trust;
    if (input.status.value !== 'CURRENT')
        return 'aic_status_not_current';
    const evaluatedAt = Date.parse(context.evaluated_at);
    const observedAt = Date.parse(input.status.checked_at);
    if (observedAt > evaluatedAt)
        return 'aic_status_observation_future';
    if (evaluatedAt - observedAt > context.max_status_age_seconds * 1_000) {
        return 'aic_status_observation_stale';
    }
    if (evaluatedAt < Date.parse(input.validity.not_before)
        || evaluatedAt > Date.parse(input.validity.not_after)) {
        return 'aic_validity_window_mismatch';
    }
    if (input.request_binding.projected_action.caid !== context.action.caid
        || input.request_binding.projected_action.action_digest
            !== context.action.action_digest) {
        return 'aic_action_projection_mismatch';
    }
    const expectedAdmissionDomainDigest = digestAebTyped(context.admission_domain, AIC_ADMISSION_DOMAIN_VERSION);
    if (input.request_binding.projected_admission_domain_digest
        !== expectedAdmissionDomainDigest) {
        return 'aic_admission_domain_mismatch';
    }
    return null;
}
function boundAuthorityFrom(input, context, native) {
    const actionAndDomain = {
        requested_capability_digest: input.request_binding.requested_capability_digest,
        action_projection_profile_id: input.request_binding.action_projection_profile_id,
        action_projection_profile_digest: input.request_binding.action_projection_profile_digest,
        action: context.action,
        admission_domain: context.admission_domain,
    };
    const authority = authorityFrom(input, {
        ...native,
        replayContext: {
            ...native.replayContext,
            action_and_domain: actionAndDomain,
        },
        instanceContext: {
            ...native.instanceContext,
            action_and_domain: actionAndDomain,
            source_status: input.status,
            evaluated_at: context.evaluated_at,
        },
    });
    return {
        ...authority,
        constraints_digest: digestAebTyped({
            native_constraints_digest: input.constraints_digest,
            ...actionAndDomain,
        }, `${native.mappingProfile}:bound-constraints`),
    };
}
export function mapAicJwtJktCrossingAuthority(input) {
    if (!isRecord(input) || !exactKeys(input, JWT_INPUT_KEYS) || !commonValid(input)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    if (input.native_typ !== 'aic+jwt' || !validJktBinding(input.principal_binding)) {
        return { ok: false, reason: 'aic_native_type_confusion' };
    }
    const trust = trustDisposition(input);
    if (trust)
        return { ok: false, reason: trust };
    if (input.principal_binding.claimed_key_hash
        !== input.principal_binding.presented_key_hash) {
        return { ok: false, reason: 'aic_principal_binding_mismatch' };
    }
    return {
        ok: true,
        authority: authorityFrom(input, {
            adapterId: 'native:aic-jwt-rfc7638-jkt',
            mappingProfile: AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
            nativeProfile: 'AIC-JWT-RFC7638-JKT',
            binding: input.principal_binding,
            replayContext: { typ: input.native_typ },
            instanceContext: { typ: input.native_typ },
        }),
    };
}
export function mapAicX509SpkiCrossingAuthority(input) {
    if (!isRecord(input) || !exactKeys(input, X509_INPUT_KEYS) || !commonValid(input)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    if (input.native_type !== 'AIC-X509' || !validSpkiBinding(input.principal_binding)) {
        return { ok: false, reason: 'aic_native_type_confusion' };
    }
    if (!CERTIFICATE_SERIAL_RE.test(input.certificate_serial)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    const trust = trustDisposition(input);
    if (trust)
        return { ok: false, reason: trust };
    if (input.principal_binding.claimed_key_hash
        !== input.principal_binding.presented_key_hash) {
        return { ok: false, reason: 'aic_principal_binding_mismatch' };
    }
    return {
        ok: true,
        authority: authorityFrom(input, {
            adapterId: 'native:aic-x509-spki',
            mappingProfile: AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
            nativeProfile: 'AIC-X509-SPKI',
            binding: input.principal_binding,
            replayContext: {
                certificate_serial: input.certificate_serial,
            },
            instanceContext: {
                certificate_serial: input.certificate_serial,
                hash_alg: input.principal_binding.hash_alg,
            },
        }),
    };
}
export function mapAicJwtJktBoundCrossingAuthority(input, context) {
    if (!isRecord(input)
        || !exactKeys(input, BOUND_JWT_INPUT_KEYS)
        || !commonValid(input)
        || !validRequestBinding(input.request_binding)
        || !validRelyingPartyContext(context)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    if (input.native_typ !== 'aic+jwt' || !validJktBinding(input.principal_binding)) {
        return { ok: false, reason: 'aic_native_type_confusion' };
    }
    if (input.principal_binding.claimed_key_hash
        !== input.principal_binding.presented_key_hash) {
        return { ok: false, reason: 'aic_principal_binding_mismatch' };
    }
    const disposition = boundDisposition(input, context);
    if (disposition)
        return { ok: false, reason: disposition };
    return {
        ok: true,
        authority: boundAuthorityFrom(input, context, {
            adapterId: 'native:aic-jwt-rfc7638-jkt-bound',
            mappingProfile: AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
            nativeProfile: 'AIC-JWT-RFC7638-JKT',
            binding: input.principal_binding,
            replayContext: { typ: input.native_typ },
            instanceContext: { typ: input.native_typ },
        }),
    };
}
export function mapAicX509SpkiBoundCrossingAuthority(input, context) {
    if (!isRecord(input)
        || !exactKeys(input, BOUND_X509_INPUT_KEYS)
        || !commonValid(input)
        || !validRequestBinding(input.request_binding)
        || !validRelyingPartyContext(context)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    if (input.native_type !== 'AIC-X509' || !validSpkiBinding(input.principal_binding)) {
        return { ok: false, reason: 'aic_native_type_confusion' };
    }
    if (!CERTIFICATE_SERIAL_RE.test(input.certificate_serial)) {
        return { ok: false, reason: 'mapping_input_invalid' };
    }
    if (input.principal_binding.claimed_key_hash
        !== input.principal_binding.presented_key_hash) {
        return { ok: false, reason: 'aic_principal_binding_mismatch' };
    }
    const disposition = boundDisposition(input, context);
    if (disposition)
        return { ok: false, reason: disposition };
    return {
        ok: true,
        authority: boundAuthorityFrom(input, context, {
            adapterId: 'native:aic-x509-spki-bound',
            mappingProfile: AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
            nativeProfile: 'AIC-X509-SPKI',
            binding: input.principal_binding,
            replayContext: { certificate_serial: input.certificate_serial },
            instanceContext: {
                certificate_serial: input.certificate_serial,
                hash_alg: input.principal_binding.hash_alg,
            },
        }),
    };
}
function spiffeId(value) {
    if (typeof value !== 'string')
        return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'spiffe:'
            && parsed.hostname.length > 0
            && parsed.username === ''
            && parsed.password === ''
            && parsed.port === ''
            && parsed.search === ''
            && parsed.hash === '';
    }
    catch {
        return false;
    }
}
function validProjectionInput(value) {
    return exactKeys(value, PROJECTION_INPUT_KEYS)
        && (value.purpose === 'WORKLOAD_IDENTITY_ONLY' || value.purpose === 'AIC_AUTHORITY')
        && Array.isArray(value.audience)
        && value.audience.every(identifier)
        && Number.isSafeInteger(value.issued_at)
        && (value.not_before === null || Number.isSafeInteger(value.not_before))
        && Number.isSafeInteger(value.expires_at)
        && identifier(value.token_id)
        && (value.projected_algorithm === 'ES256' || value.projected_algorithm === 'RS256')
        && identifier(value.projected_key_id)
        && typeof value.has_constraints === 'boolean'
        && (value.delegation_mode === 'authorized' || value.delegation_mode === 'representative')
        && typeof value.has_delegation_assertion === 'boolean'
        && typeof value.confirmation_key_present === 'boolean';
}
export function projectAicJwtToStrictJwtSvid(input) {
    if (!isRecord(input) || !validProjectionInput(input)) {
        return { ok: false, reason: 'jwt_svid_projection_input_invalid' };
    }
    const source = mapAicJwtJktCrossingAuthority(input.source);
    if (!source.ok)
        return source;
    if (!spiffeId(input.source.subject)) {
        return { ok: false, reason: 'jwt_svid_spiffe_subject_required' };
    }
    if (input.audience.length !== 1) {
        return { ok: false, reason: 'jwt_svid_single_audience_required' };
    }
    if (input.expires_at <= input.issued_at
        || (input.not_before !== null && input.not_before >= input.expires_at)) {
        return { ok: false, reason: 'jwt_svid_projection_time_invalid' };
    }
    if (input.purpose !== 'WORKLOAD_IDENTITY_ONLY') {
        return { ok: false, reason: 'aic_jwt_svid_semantic_loss' };
    }
    const omittedSourceMembers = [
        'iss',
        'aic.principal',
        'aic.capabilities',
        'aic.delegation_mode',
        ...(input.has_constraints ? ['aic.constraints'] : []),
        ...(input.has_delegation_assertion ? ['da'] : []),
        ...(input.confirmation_key_present ? ['cnf'] : []),
    ];
    const protectedHeader = {
        alg: input.projected_algorithm,
        kid: input.projected_key_id,
        typ: 'JWT',
    };
    const payload = {
        sub: input.source.subject,
        aud: input.audience[0],
        iat: input.issued_at,
        exp: input.expires_at,
        ...(input.not_before === null ? {} : { nbf: input.not_before }),
        jti: input.token_id,
    };
    const sourceEvidence = {
        typ: 'aic+jwt',
        issuer: input.source.issuer,
        token_digest: input.source.artifact_digest,
        source_semantics_digest: digestAebTyped({
            principal_binding: input.source.principal_binding,
            has_constraints: input.has_constraints,
            delegation_mode: input.delegation_mode,
            has_delegation_assertion: input.has_delegation_assertion,
            confirmation_key_present: input.confirmation_key_present,
        }, `${AIC_JWT_SVID_PROJECTION_VERSION}:source-semantics`),
    };
    const projectionDigest = digestAebTyped({
        protected_header: protectedHeader,
        payload,
        source: sourceEvidence,
        purpose: input.purpose,
        omitted_source_members: omittedSourceMembers,
        authority_semantics_preserved: false,
        new_signature_required: true,
    }, `${AIC_JWT_SVID_PROJECTION_VERSION}:projection`);
    return {
        ok: true,
        projection: {
            '@version': AIC_JWT_SVID_PROJECTION_VERSION,
            protected_header: protectedHeader,
            payload,
            source: sourceEvidence,
            purpose: 'WORKLOAD_IDENTITY_ONLY',
            omitted_source_members: omittedSourceMembers,
            authority_semantics_preserved: false,
            new_signature_required: true,
            compact_token: null,
            authorization_decision: false,
            projection_digest: projectionDigest,
        },
    };
}
//# sourceMappingURL=aeb-aic-crossing-adapter.js.map