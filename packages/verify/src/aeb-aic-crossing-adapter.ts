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
import {
  digestAebTyped,
  type AebDigest,
} from './aeb-adapter-contract.js';
import {
  type CrossingAuthorityMappingResult,
  type CrossingNativeAuthority,
  type CrossingNativeStatus,
  type CrossingNativeVerification,
  type CrossingValidity,
} from './aeb-crossing-record.js';

export const AIC_JWT_JKT_CROSSING_MAPPING_PROFILE =
  'EP-AEB-CROSSING-AIC-JWT-JKT-v1';
export const AIC_X509_SPKI_CROSSING_MAPPING_PROFILE =
  'EP-AEB-CROSSING-AIC-X509-SPKI-v1';
export const AIC_JWT_SVID_PROJECTION_VERSION =
  'EP-AIC-JWT-SVID-PROJECTION-v1';

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

export interface AicJwtJktCrossingInput extends AicCrossingCommonInput {
  native_typ: 'aic+jwt';
  principal_binding: AicRfc7638JktBinding;
}

export interface AicX509SpkiCrossingInput extends AicCrossingCommonInput {
  native_type: 'AIC-X509';
  certificate_serial: string;
  principal_binding: AicX509SpkiBinding;
}

export type AicJwtSvidProjectionPurpose =
  | 'WORKLOAD_IDENTITY_ONLY'
  | 'AIC_AUTHORITY';

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

export type AicJwtSvidProjectionResult =
  | { ok: true; projection: AicStrictJwtSvidProjection }
  | { ok: false; reason: string };

type Obj = Record<string, unknown>;

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
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
const NATIVE_VERIFICATIONS = new Set<CrossingNativeVerification>([
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

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, expected: ReadonlySet<string>): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.size
    && keys.every((key) => typeof key === 'string' && expected.has(key));
}

function identifier(value: unknown): value is string {
  return typeof value === 'string'
    && IDENTIFIER_RE.test(value)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function digest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function instant(value: unknown): value is string {
  return typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function validStatus(value: unknown): value is CrossingNativeStatus {
  return isRecord(value)
    && exactKeys(value, STATUS_KEYS)
    && typeof value.value === 'string'
    && STATUSES.has(value.value)
    && instant(value.checked_at)
    && digest(value.source_head_digest);
}

function validValidity(value: unknown): value is CrossingValidity {
  return isRecord(value)
    && exactKeys(value, VALIDITY_KEYS)
    && instant(value.not_before)
    && instant(value.not_after)
    && Date.parse(value.not_before) < Date.parse(value.not_after);
}

function validTrustSet(value: unknown): value is AebDigest[] {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= 64
    && value.every(digest)
    && new Set(value).size === value.length;
}

function commonValid(value: Obj): value is Obj & AicCrossingCommonInput {
  return NATIVE_VERIFICATIONS.has(value.native_verification as CrossingNativeVerification)
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

function expectedHashLength(hashAlg: 'jkt' | AicSpkiHashAlgorithm): number {
  if (hashAlg === 'sha-384') return 64;
  if (hashAlg === 'sha-512') return 86;
  return 43;
}

function keyHash(value: unknown, hashAlg: 'jkt' | AicSpkiHashAlgorithm): value is string {
  return typeof value === 'string'
    && value.length === expectedHashLength(hashAlg)
    && BASE64URL_RE.test(value);
}

function validJktBinding(value: unknown): value is AicRfc7638JktBinding {
  return isRecord(value)
    && exactKeys(value, BINDING_KEYS)
    && value.kind === 'RFC7638_JKT'
    && value.hash_alg === 'jkt'
    && keyHash(value.claimed_key_hash, 'jkt')
    && keyHash(value.presented_key_hash, 'jkt');
}

function validSpkiBinding(value: unknown): value is AicX509SpkiBinding {
  if (!isRecord(value) || !exactKeys(value, BINDING_KEYS)) return false;
  if (value.kind !== 'X509_SPKI') return false;
  if (!['sha-256', 'sha-384', 'sha-512'].includes(String(value.hash_alg))) return false;
  const hashAlg = value.hash_alg as AicSpkiHashAlgorithm;
  return keyHash(value.claimed_key_hash, hashAlg)
    && keyHash(value.presented_key_hash, hashAlg);
}

function trustDisposition(input: AicCrossingCommonInput): string | null {
  if (input.native_verification === 'FAILED') return 'aic_native_verification_failed';
  if (input.native_verification === 'INDETERMINATE') {
    return 'aic_native_verification_indeterminate';
  }
  if (!validTrustSet(input.trusted_issuer_trust_anchor_digests)
    || !input.trusted_issuer_trust_anchor_digests.includes(
      input.issuer_trust_anchor_digest,
    )) {
    return 'aic_issuer_untrusted';
  }
  return null;
}

function authorityFrom(
  input: AicCrossingCommonInput,
  native: {
    adapterId: string;
    mappingProfile: string;
    nativeProfile: string;
    binding: AicRfc7638JktBinding | AicX509SpkiBinding;
    replayContext: Obj;
    instanceContext: Obj;
  },
): CrossingNativeAuthority {
  return {
    adapter_id: native.adapterId,
    adapter_version: '1',
    mapping_profile_id: native.mappingProfile,
    mapping_profile_digest: input.mapping_profile_digest,
    native_profile: native.nativeProfile,
    issuer: input.issuer,
    subject: input.subject,
    authority_instance_digest: digestAebTyped(
      {
        native_profile: native.nativeProfile,
        issuer: input.issuer,
        subject: input.subject,
        artifact_id: input.artifact_id,
        artifact_digest: input.artifact_digest,
        issuer_trust_anchor_digest: input.issuer_trust_anchor_digest,
        principal_binding: native.binding,
        native: native.instanceContext,
      },
      `${native.mappingProfile}:authority-instance`,
    ),
    evidence_digest: input.artifact_digest,
    replay_unit: digestAebTyped(
      {
        issuer: input.issuer,
        artifact_id: input.artifact_id,
        native: native.replayContext,
      },
      `${native.mappingProfile}:replay-unit`,
    ),
    native_verification: 'VERIFIED',
    rp_acceptance: 'ACCEPTED',
    status: structuredClone(input.status),
    constraints_digest: input.constraints_digest,
    validity: structuredClone(input.validity),
  };
}

export function mapAicJwtJktCrossingAuthority(
  input: AicJwtJktCrossingInput,
): CrossingAuthorityMappingResult {
  if (!isRecord(input) || !exactKeys(input, JWT_INPUT_KEYS) || !commonValid(input)) {
    return { ok: false, reason: 'mapping_input_invalid' };
  }
  if (input.native_typ !== 'aic+jwt' || !validJktBinding(input.principal_binding)) {
    return { ok: false, reason: 'aic_native_type_confusion' };
  }
  const trust = trustDisposition(input);
  if (trust) return { ok: false, reason: trust };
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

export function mapAicX509SpkiCrossingAuthority(
  input: AicX509SpkiCrossingInput,
): CrossingAuthorityMappingResult {
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
  if (trust) return { ok: false, reason: trust };
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

function spiffeId(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'spiffe:'
      && parsed.hostname.length > 0
      && parsed.username === ''
      && parsed.password === ''
      && parsed.port === ''
      && parsed.search === ''
      && parsed.hash === '';
  } catch {
    return false;
  }
}

function validProjectionInput(value: Obj): value is Obj & AicJwtSvidProjectionInput {
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

export function projectAicJwtToStrictJwtSvid(
  input: AicJwtSvidProjectionInput,
): AicJwtSvidProjectionResult {
  if (!isRecord(input) || !validProjectionInput(input)) {
    return { ok: false, reason: 'jwt_svid_projection_input_invalid' };
  }
  const source = mapAicJwtJktCrossingAuthority(input.source);
  if (!source.ok) return source;
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
    typ: 'JWT' as const,
  };
  const payload: AicStrictJwtSvidProjection['payload'] = {
    sub: input.source.subject,
    aud: input.audience[0],
    iat: input.issued_at,
    exp: input.expires_at,
    ...(input.not_before === null ? {} : { nbf: input.not_before }),
    jti: input.token_id,
  };
  const sourceEvidence: AicStrictJwtSvidProjection['source'] = {
    typ: 'aic+jwt',
    issuer: input.source.issuer,
    token_digest: input.source.artifact_digest,
    source_semantics_digest: digestAebTyped(
      {
        principal_binding: input.source.principal_binding,
        has_constraints: input.has_constraints,
        delegation_mode: input.delegation_mode,
        has_delegation_assertion: input.has_delegation_assertion,
        confirmation_key_present: input.confirmation_key_present,
      },
      `${AIC_JWT_SVID_PROJECTION_VERSION}:source-semantics`,
    ),
  };
  const projectionDigest = digestAebTyped(
    {
      protected_header: protectedHeader,
      payload,
      source: sourceEvidence,
      purpose: input.purpose,
      omitted_source_members: omittedSourceMembers,
      authority_semantics_preserved: false,
      new_signature_required: true,
    },
    `${AIC_JWT_SVID_PROJECTION_VERSION}:projection`,
  );
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
