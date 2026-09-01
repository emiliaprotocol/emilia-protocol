// SPDX-License-Identifier: Apache-2.0
/**
 * AIC native-authority mappings for EP-AEB-CROSSING-RECORD-v1.
 *
 * The adapter consumes the result of an AIC native verifier. It does not
 * reimplement AIC-JWT signature, delegation, capability, constraint, status,
 * or X.509 path validation. It keeps the RFC 7638 JWK-thumbprint and X.509
 * SPKI-hash paths separate, derives original-carrier provenance from the raw
 * compact token or native certificate bundle, and keeps relying-party policy
 * structurally separate from the native verifier result. The pinned upstream
 * bearer helper returns a bare synthesized X.509 object without authenticated
 * provenance, so that object cannot enter the native X.509 mapping: the latter
 * requires real agent and principal certificate DER. A deployment still needs
 * to preserve this provenance inside its trusted verifier boundary.
 *
 * The JWT-SVID helper emits only a to-be-signed identity projection. Rewriting
 * the protected header would invalidate the AIC-JWT signature, so a deployment
 * must issue a new typ=JWT token under a key in its JWT-SVID bundle. The
 * projection is never an AIC authority decision.
 */
import crypto, { X509Certificate } from 'node:crypto';

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
export const AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE =
  'EP-AEB-CROSSING-AIC-JWT-JKT-BOUND-v2';
export const AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE =
  'EP-AEB-CROSSING-AIC-X509-SPKI-BOUND-v2';
export const AIC_ADMISSION_DOMAIN_VERSION =
  'EP-AIC-ADMISSION-DOMAIN-v1';
export const AIC_JWT_SVID_PROJECTION_VERSION =
  'EP-AIC-JWT-SVID-PROJECTION-v1';
export const AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION =
  'EP-AIC-X509-CREDENTIAL-BUNDLE-v1';

export type AicSpkiHashAlgorithm = 'sha-256';
export type AicJwtDownstreamRepresentation = 'DIRECT' | 'SYNTHESIZED-X509';

export type AicPrincipalPublicJwk =
  | { kty: 'EC'; crv: string; x: string; y: string }
  | { kty: 'RSA'; n: string; e: string }
  | { kty: 'OKP'; crv: string; x: string };

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

export type AicJwtSvidProjectionResult =
  | { ok: true; projection: AicStrictJwtSvidProjection }
  | { ok: false; reason: string };

type Obj = Record<string, unknown>;

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/#-]{0,511}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const MAX_AIC_JWT_BYTES = 64 * 1024;
const MAX_AIC_CERTIFICATE_BYTES = 64 * 1024;
const COMMON_KEYS = new Set([
  'native_verification',
  'native_verifier',
  'native_verification_evidence_digest',
  'issuer',
  'subject',
  'artifact_id',
  'artifact_digest',
  'issuer_trust_anchor_digest',
  'constraints_digest',
  'status',
  'validity',
]);
const JWT_INPUT_KEYS = new Set([
  ...COMMON_KEYS,
  'carrier_provenance',
  'principal_binding',
]);
const X509_INPUT_KEYS = new Set([
  ...COMMON_KEYS,
  'carrier_provenance',
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
  'requested_capability_digest',
  'evaluated_at',
  'max_status_age_seconds',
  'policy',
]);
const RP_TEMPORAL_CONTEXT_KEYS = new Set([
  'evaluated_at',
  'max_status_age_seconds',
]);
const RP_POLICY_KEYS = new Set([
  'mapping_profile_id',
  'mapping_profile_digest',
  'action_projection_profile_id',
  'action_projection_profile_digest',
  'trusted_issuer_trust_anchor_digests',
  'native_verifier',
]);
const VERIFIER_DESCRIPTOR_KEYS = new Set(['id', 'version', 'implementation_digest']);
const JWT_PROVENANCE_KEYS = new Set([
  'source_carrier',
  'compact_token',
  'presented_principal_jwk',
  'downstream_representation',
]);
const X509_PROVENANCE_KEYS = new Set([
  'source_carrier',
  'agent_certificate_der',
  'principal_certificate_der',
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
]);
const PROJECTION_CONTEXT_KEYS = new Set([
  'relying_party_policy',
  'evaluated_at',
  'max_status_age_seconds',
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

function validAction(value: unknown): value is AicCrossingExactAction {
  return isRecord(value)
    && exactKeys(value, ACTION_KEYS)
    && typeof value.caid === 'string'
    && CAID_RE.test(value.caid)
    && digest(value.action_digest);
}

function validAdmissionDomain(value: unknown): value is AicCrossingAdmissionDomain {
  return isRecord(value)
    && exactKeys(value, ADMISSION_DOMAIN_KEYS)
    && identifier(value.relying_party_id)
    && identifier(value.audience)
    && identifier(value.executor_id)
    && identifier(value.state_domain_id);
}

function validRequestBinding(value: unknown): value is AicCrossingRequestBinding {
  return isRecord(value)
    && exactKeys(value, REQUEST_BINDING_KEYS)
    && identifier(value.action_projection_profile_id)
    && digest(value.action_projection_profile_digest)
    && digest(value.requested_capability_digest)
    && validAction(value.projected_action)
    && digest(value.projected_admission_domain_digest);
}

function validVerifierDescriptor(value: unknown): value is AicNativeVerifierDescriptor {
  return isRecord(value)
    && exactKeys(value, VERIFIER_DESCRIPTOR_KEYS)
    && identifier(value.id)
    && identifier(value.version)
    && digest(value.implementation_digest);
}

function validRelyingPartyPolicy(
  value: unknown,
): value is AicCrossingRelyingPartyPolicy {
  return isRecord(value)
    && exactKeys(value, RP_POLICY_KEYS)
    && identifier(value.mapping_profile_id)
    && digest(value.mapping_profile_digest)
    && identifier(value.action_projection_profile_id)
    && digest(value.action_projection_profile_digest)
    && validTrustSet(value.trusted_issuer_trust_anchor_digests)
    && validVerifierDescriptor(value.native_verifier);
}

function validRelyingPartyContext(
  value: unknown,
): value is AicCrossingRelyingPartyContext {
  return isRecord(value)
    && exactKeys(value, RP_CONTEXT_KEYS)
    && validAction(value.action)
    && validAdmissionDomain(value.admission_domain)
    && digest(value.requested_capability_digest)
    && instant(value.evaluated_at)
    && Number.isSafeInteger(value.max_status_age_seconds)
    && Number(value.max_status_age_seconds) >= 0
    && Number(value.max_status_age_seconds) <= 86_400
    && validRelyingPartyPolicy(value.policy);
}

function validRelyingPartyTemporalContext(
  value: unknown,
): value is AicCrossingRelyingPartyTemporalContext {
  return isRecord(value)
    && exactKeys(value, RP_TEMPORAL_CONTEXT_KEYS)
    && instant(value.evaluated_at)
    && Number.isSafeInteger(value.max_status_age_seconds)
    && Number(value.max_status_age_seconds) >= 0
    && Number(value.max_status_age_seconds) <= 86_400;
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
    && validVerifierDescriptor(value.native_verifier)
    && digest(value.native_verification_evidence_digest)
    && identifier(value.issuer)
    && identifier(value.subject)
    && identifier(value.artifact_id)
    && digest(value.artifact_digest)
    && digest(value.issuer_trust_anchor_digest)
    && digest(value.constraints_digest)
    && validStatus(value.status)
    && validValidity(value.validity);
}

function expectedHashLength(hashAlg: 'jkt' | AicSpkiHashAlgorithm): number {
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
  if (value.hash_alg !== 'sha-256') return false;
  const hashAlg = value.hash_alg as AicSpkiHashAlgorithm;
  return keyHash(value.claimed_key_hash, hashAlg)
    && keyHash(value.presented_key_hash, hashAlg);
}

type InspectedJwtCarrier = {
  carrierOrigin: 'AIC-JWT';
  representation: AicJwtDownstreamRepresentation;
  artifactDigest: AebDigest;
  issuer: string;
  artifactId: string;
  claimedKeyHash: string;
  presentedKeyHash: string;
  audiences: string[];
  issuedAt: number;
  notBefore: number | null;
  expiresAt: number;
  semantics: {
    hasConstraints: boolean;
    delegationMode: 'authorized' | 'representative';
    hasDelegationAssertion: boolean;
    confirmationKeyPresent: boolean;
  };
};

type InspectedX509Carrier = {
  carrierOrigin: 'AIC-X509-CERTIFICATE';
  artifactDigest: AebDigest;
  certificateSerial: string;
  presentedKeyHash: string;
};

function canonicalBase64urlBytes(value: unknown, maximumBytes: number): Buffer | null {
  if (typeof value !== 'string'
    || value.length === 0
    || !BASE64URL_RE.test(value)
    || value.length % 4 === 1) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length === 0
      || bytes.length > maximumBytes
      || bytes.toString('base64url') !== value) return null;
    return bytes;
  } catch {
    return null;
  }
}

function jsonObjectFromSegment(segment: string): Obj | null {
  const bytes = canonicalBase64urlBytes(segment, MAX_AIC_JWT_BYTES);
  if (!bytes) return null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function jwtNumericDate(value: unknown): number | null {
  if (!Number.isSafeInteger(value)) return null;
  const milliseconds = Number(value) * 1_000;
  return Number.isSafeInteger(milliseconds) && Number.isFinite(new Date(milliseconds).valueOf())
    ? Number(value)
    : null;
}

function inspectPrincipalPublicJwk(value: unknown): {
  jwk: AicPrincipalPublicJwk;
  thumbprint: string;
} | null {
  if (!isRecord(value) || typeof value.kty !== 'string') return null;
  let jwk: AicPrincipalPublicJwk;
  let canonical: Obj;
  if (value.kty === 'EC') {
    const keys = new Set(['kty', 'crv', 'x', 'y']);
    const { crv, x, y } = value;
    if (!exactKeys(value, keys)
      || !identifier(crv)
      || typeof x !== 'string'
      || typeof y !== 'string'
      || !canonicalBase64urlBytes(x, 1_024)
      || !canonicalBase64urlBytes(y, 1_024)) return null;
    jwk = { kty: 'EC', crv, x, y };
    canonical = { crv, kty: 'EC', x, y };
  } else if (value.kty === 'RSA') {
    const keys = new Set(['kty', 'n', 'e']);
    const { n, e } = value;
    if (!exactKeys(value, keys)
      || typeof n !== 'string'
      || typeof e !== 'string'
      || !canonicalBase64urlBytes(n, 16 * 1_024)
      || !canonicalBase64urlBytes(e, 16)) return null;
    jwk = { kty: 'RSA', n, e };
    canonical = { e, kty: 'RSA', n };
  } else if (value.kty === 'OKP') {
    const keys = new Set(['kty', 'crv', 'x']);
    const { crv, x } = value;
    if (!exactKeys(value, keys)
      || !identifier(crv)
      || typeof x !== 'string'
      || !canonicalBase64urlBytes(x, 1_024)) return null;
    jwk = { kty: 'OKP', crv, x };
    canonical = { crv, kty: 'OKP', x };
  } else {
    return null;
  }
  try {
    crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    return null;
  }
  return {
    jwk,
    thumbprint: crypto.createHash('sha256')
      .update(JSON.stringify(canonical), 'utf8')
      .digest('base64url'),
  };
}

function inspectJwtCarrier(input: AicJwtJktCrossingInput): InspectedJwtCarrier | null {
  const provenance = input.carrier_provenance;
  if (!isRecord(provenance)
    || !exactKeys(provenance, JWT_PROVENANCE_KEYS)
    || provenance.source_carrier !== 'AIC-JWT-COMPACT'
    || !['DIRECT', 'SYNTHESIZED-X509'].includes(
      String(provenance.downstream_representation),
    )
    || typeof provenance.compact_token !== 'string'
    || Buffer.byteLength(provenance.compact_token, 'utf8') > MAX_AIC_JWT_BYTES) {
    return null;
  }
  const segments = provenance.compact_token.split('.');
  if (segments.length !== 3
    || segments.some((segment) => !canonicalBase64urlBytes(segment, MAX_AIC_JWT_BYTES))) {
    return null;
  }
  const header = jsonObjectFromSegment(segments[0]);
  const payload = jsonObjectFromSegment(segments[1]);
  if (!header || !payload || header.typ !== 'aic+jwt') return null;
  const aic = payload.aic;
  const principal = isRecord(aic) ? aic.principal : null;
  const presentedPrincipal = inspectPrincipalPublicJwk(
    provenance.presented_principal_jwk,
  );
  const issuedAt = jwtNumericDate(payload.iat);
  const expiresAt = jwtNumericDate(payload.exp);
  const notBefore = payload.nbf === undefined ? null : jwtNumericDate(payload.nbf);
  if (!isRecord(principal)
    || !presentedPrincipal
    || issuedAt === null
    || issuedAt === 0
    || expiresAt === null
    || expiresAt === 0
    || expiresAt <= issuedAt
    || (payload.nbf !== undefined && notBefore === null)
    || (notBefore !== null && notBefore > expiresAt)
    || principal.hash_alg !== 'jkt'
    || !keyHash(principal.key_hash, 'jkt')
    || payload.iss !== input.issuer
    || payload.sub !== input.subject
    || payload.jti !== input.artifact_id) return null;
  const audiences = typeof payload.aud === 'string'
    ? [payload.aud]
    : Array.isArray(payload.aud) ? payload.aud : null;
  if (!audiences
    || audiences.length === 0
    || audiences.length > 64
    || !audiences.every(identifier)
    || new Set(audiences).size !== audiences.length) return null;
  const delegationMode = isRecord(aic) ? aic.delegation_mode : null;
  if (delegationMode !== 'authorized' && delegationMode !== 'representative') {
    return null;
  }
  const constraints = isRecord(aic) ? aic.constraints : undefined;
  if (constraints !== undefined && !Array.isArray(constraints)) return null;
  const delegationAssertion = payload.da;
  if (delegationAssertion !== undefined
    && (typeof delegationAssertion !== 'string' || delegationAssertion.length === 0)) {
    return null;
  }
  const confirmation = payload.cnf;
  if (confirmation !== undefined
    && (!isRecord(confirmation) || !keyHash(confirmation.jkt, 'jkt'))) return null;
  return {
    carrierOrigin: 'AIC-JWT',
    representation:
      provenance.downstream_representation as AicJwtDownstreamRepresentation,
    artifactDigest: `sha256:${crypto.createHash('sha256')
      .update(provenance.compact_token, 'utf8')
      .digest('hex')}`,
    issuer: payload.iss,
    artifactId: payload.jti,
    claimedKeyHash: principal.key_hash,
    presentedKeyHash: presentedPrincipal.thumbprint,
    audiences,
    issuedAt,
    notBefore,
    expiresAt,
    semantics: {
      hasConstraints: Array.isArray(constraints) && constraints.length > 0,
      delegationMode,
      hasDelegationAssertion: typeof delegationAssertion === 'string',
      confirmationKeyPresent: isRecord(confirmation),
    },
  };
}

function inspectX509Carrier(
  input: AicX509SpkiCrossingInput,
): InspectedX509Carrier | null {
  const provenance = input.carrier_provenance;
  if (!isRecord(provenance)
    || !exactKeys(provenance, X509_PROVENANCE_KEYS)
    || provenance.source_carrier !== 'AIC-X509-CREDENTIAL-BUNDLE') return null;
  const agentDer = canonicalBase64urlBytes(
    provenance.agent_certificate_der,
    MAX_AIC_CERTIFICATE_BYTES,
  );
  const principalDer = canonicalBase64urlBytes(
    provenance.principal_certificate_der,
    MAX_AIC_CERTIFICATE_BYTES,
  );
  if (!agentDer || !principalDer || agentDer.equals(principalDer)) return null;
  try {
    const agent = new X509Certificate(agentDer);
    const principal = new X509Certificate(principalDer);
    if (!agent.raw.equals(agentDer) || !principal.raw.equals(principalDer)) return null;
    const principalSpki = principal.publicKey.export({ type: 'spki', format: 'der' });
    if (!Buffer.isBuffer(principalSpki)) return null;
    const hashName = input.principal_binding.hash_alg.replace('-', '');
    const serial = agent.serialNumber.replaceAll(':', '').toUpperCase();
    if (!/^[0-9A-F]{2,128}$/.test(serial)) return null;
    return {
      carrierOrigin: 'AIC-X509-CERTIFICATE',
      artifactDigest: digestAebTyped(
        {
          agent_certificate_der: provenance.agent_certificate_der,
          principal_certificate_der: provenance.principal_certificate_der,
        },
        AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION,
      ),
      certificateSerial: serial,
      presentedKeyHash: crypto.createHash(hashName)
        .update(principalSpki)
        .digest('base64url'),
    };
  } catch {
    return null;
  }
}

function sameVerifier(
  left: AicNativeVerifierDescriptor,
  right: AicNativeVerifierDescriptor,
): boolean {
  return left.id === right.id
    && left.version === right.version
    && left.implementation_digest === right.implementation_digest;
}

function trustDisposition(
  input: AicCrossingCommonInput,
  policy: AicCrossingRelyingPartyPolicy,
  expectedMappingProfileId: string,
): string | null {
  if (input.native_verification === 'FAILED') return 'aic_native_verification_failed';
  if (input.native_verification === 'INDETERMINATE') {
    return 'aic_native_verification_indeterminate';
  }
  if (!validRelyingPartyPolicy(policy)) return 'aic_relying_party_policy_invalid';
  if (policy.mapping_profile_id !== expectedMappingProfileId) {
    return 'aic_mapping_profile_unpinned';
  }
  if (!sameVerifier(input.native_verifier, policy.native_verifier)) {
    return 'aic_native_verifier_unpinned';
  }
  if (!policy.trusted_issuer_trust_anchor_digests.includes(
    input.issuer_trust_anchor_digest,
  )) {
    return 'aic_issuer_untrusted';
  }
  if (input.status.value !== 'CURRENT') return 'aic_status_not_current';
  return null;
}

function temporalDisposition(
  input: AicCrossingCommonInput,
  context: AicCrossingRelyingPartyTemporalContext,
): string | null {
  const evaluatedAt = Date.parse(context.evaluated_at);
  const observedAt = Date.parse(input.status.checked_at);
  if (observedAt > evaluatedAt) return 'aic_status_observation_future';
  if (evaluatedAt - observedAt > context.max_status_age_seconds * 1_000) {
    return 'aic_status_observation_stale';
  }
  if (evaluatedAt < Date.parse(input.validity.not_before)
    || evaluatedAt > Date.parse(input.validity.not_after)) {
    return 'aic_validity_window_mismatch';
  }
  return null;
}

function jwtValidityDisposition(
  input: AicJwtJktCrossingInput,
  carrier: InspectedJwtCarrier,
): string | null {
  const signedNotBefore = (carrier.notBefore ?? carrier.issuedAt) * 1_000;
  if (Date.parse(input.validity.not_before) !== signedNotBefore
    || Date.parse(input.validity.not_after) !== carrier.expiresAt * 1_000) {
    return 'aic_jwt_validity_mismatch';
  }
  return null;
}

function authorityFrom(
  input: AicCrossingCommonInput,
  policy: AicCrossingRelyingPartyPolicy,
  native: {
    adapterId: string;
    mappingProfile: string;
    nativeProfile: string;
    binding: AicRfc7638JktBinding | AicX509SpkiBinding;
    replayIdentity: Obj;
    instanceContext: Obj;
  },
): CrossingNativeAuthority {
  return {
    adapter_id: native.adapterId,
    adapter_version: '1',
    mapping_profile_id: native.mappingProfile,
    mapping_profile_digest: policy.mapping_profile_digest,
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
        native_verifier: input.native_verifier,
        native_verification_evidence_digest:
          input.native_verification_evidence_digest,
        principal_binding: native.binding,
        native: native.instanceContext,
      },
      `${native.mappingProfile}:authority-instance`,
    ),
    evidence_digest: input.artifact_digest,
    replay_unit: digestAebTyped(
      native.replayIdentity,
      `${native.mappingProfile}:replay-unit`,
    ),
    native_verification: 'VERIFIED',
    rp_acceptance: 'ACCEPTED',
    status: structuredClone(input.status),
    constraints_digest: input.constraints_digest,
    validity: structuredClone(input.validity),
  };
}

function boundDisposition(
  input: AicCrossingCommonInput & { request_binding: AicCrossingRequestBinding },
  context: AicCrossingRelyingPartyContext,
  expectedMappingProfileId: string,
): string | null {
  const trust = trustDisposition(input, context.policy, expectedMappingProfileId);
  if (trust) return trust;
  if (input.request_binding.action_projection_profile_id
      !== context.policy.action_projection_profile_id
    || input.request_binding.action_projection_profile_digest
      !== context.policy.action_projection_profile_digest) {
    return 'aic_action_projection_profile_unpinned';
  }
  if (input.request_binding.requested_capability_digest
      !== context.requested_capability_digest) {
    return 'aic_requested_capability_mismatch';
  }
  if (input.status.value !== 'CURRENT') return 'aic_status_not_current';
  const temporal = temporalDisposition(input, context);
  if (temporal) return temporal;
  if (input.request_binding.projected_action.caid !== context.action.caid
    || input.request_binding.projected_action.action_digest
      !== context.action.action_digest) {
    return 'aic_action_projection_mismatch';
  }
  const expectedAdmissionDomainDigest = digestAebTyped(
    context.admission_domain,
    AIC_ADMISSION_DOMAIN_VERSION,
  );
  if (input.request_binding.projected_admission_domain_digest
    !== expectedAdmissionDomainDigest) {
    return 'aic_admission_domain_mismatch';
  }
  return null;
}

function boundAuthorityFrom(
  input: AicCrossingCommonInput & { request_binding: AicCrossingRequestBinding },
  context: AicCrossingRelyingPartyContext,
  native: {
    adapterId: string;
    mappingProfile: string;
    nativeProfile: string;
    binding: AicRfc7638JktBinding | AicX509SpkiBinding;
    replayIdentity: Obj;
    instanceContext: Obj;
  },
): CrossingNativeAuthority {
  const actionAndDomain = {
    requested_capability_digest: context.requested_capability_digest,
    action_projection_profile_id:
      input.request_binding.action_projection_profile_id,
    action_projection_profile_digest:
      input.request_binding.action_projection_profile_digest,
    action: context.action,
    admission_domain: context.admission_domain,
  };
  const authority = authorityFrom(input, context.policy, {
    ...native,
    replayIdentity: {
      ...native.replayIdentity,
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
    constraints_digest: digestAebTyped(
      {
        native_constraints_digest: input.constraints_digest,
        ...actionAndDomain,
      },
      `${native.mappingProfile}:bound-constraints`,
    ),
  };
}

export function mapAicJwtJktCrossingAuthority(
  input: AicJwtJktCrossingInput,
  policy: AicCrossingRelyingPartyPolicy,
  temporalContext?: AicCrossingRelyingPartyTemporalContext,
): CrossingAuthorityMappingResult {
  if (!isRecord(input) || !exactKeys(input, JWT_INPUT_KEYS) || !commonValid(input)) {
    return { ok: false, reason: 'mapping_input_invalid' };
  }
  if (!validJktBinding(input.principal_binding)) {
    return { ok: false, reason: 'aic_native_type_confusion' };
  }
  const carrier = inspectJwtCarrier(input);
  if (!carrier) return { ok: false, reason: 'aic_carrier_provenance_unverifiable' };
  if (carrier.artifactDigest !== input.artifact_digest) {
    return { ok: false, reason: 'aic_carrier_artifact_digest_mismatch' };
  }
  if (carrier.claimedKeyHash !== input.principal_binding.claimed_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  if (carrier.presentedKeyHash !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  const jwtValidity = jwtValidityDisposition(input, carrier);
  if (jwtValidity) return { ok: false, reason: jwtValidity };
  const trust = trustDisposition(
    input,
    policy,
    AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
  );
  if (trust) return { ok: false, reason: trust };
  if (!validRelyingPartyTemporalContext(temporalContext)) {
    return { ok: false, reason: 'aic_relying_party_temporal_context_required' };
  }
  const temporal = temporalDisposition(input, temporalContext);
  if (temporal) return { ok: false, reason: temporal };
  if (input.principal_binding.claimed_key_hash
    !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  return {
    ok: true,
    authority: authorityFrom(input, policy, {
      adapterId: 'native:aic-jwt-rfc7638-jkt',
      mappingProfile: AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
      nativeProfile: 'AIC-JWT-RFC7638-JKT',
      binding: input.principal_binding,
      replayIdentity: {
        carrier_origin: carrier.carrierOrigin,
        issuer: carrier.issuer,
        artifact_id: carrier.artifactId,
      },
      instanceContext: {
        carrier_origin: carrier.carrierOrigin,
        downstream_representation: carrier.representation,
        typ: 'aic+jwt',
      },
    }),
  };
}

export function mapAicX509SpkiCrossingAuthority(
  input: AicX509SpkiCrossingInput,
  policy: AicCrossingRelyingPartyPolicy,
  temporalContext?: AicCrossingRelyingPartyTemporalContext,
): CrossingAuthorityMappingResult {
  if (!isRecord(input) || !exactKeys(input, X509_INPUT_KEYS) || !commonValid(input)) {
    return { ok: false, reason: 'mapping_input_invalid' };
  }
  if (!validSpkiBinding(input.principal_binding)) {
    return { ok: false, reason: 'aic_native_type_confusion' };
  }
  const carrier = inspectX509Carrier(input);
  if (!carrier) return { ok: false, reason: 'aic_carrier_provenance_unverifiable' };
  if (carrier.artifactDigest !== input.artifact_digest) {
    return { ok: false, reason: 'aic_carrier_artifact_digest_mismatch' };
  }
  if (carrier.presentedKeyHash !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  const trust = trustDisposition(
    input,
    policy,
    AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
  );
  if (trust) return { ok: false, reason: trust };
  if (!validRelyingPartyTemporalContext(temporalContext)) {
    return { ok: false, reason: 'aic_relying_party_temporal_context_required' };
  }
  const temporal = temporalDisposition(input, temporalContext);
  if (temporal) return { ok: false, reason: temporal };
  if (input.principal_binding.claimed_key_hash
    !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  return {
    ok: true,
    authority: authorityFrom(input, policy, {
      adapterId: 'native:aic-x509-spki',
      mappingProfile: AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
      nativeProfile: 'AIC-X509-SPKI',
      binding: input.principal_binding,
      replayIdentity: {
        carrier_origin: carrier.carrierOrigin,
        artifact_digest: carrier.artifactDigest,
        certificate_serial: carrier.certificateSerial,
      },
      instanceContext: {
        carrier_origin: carrier.carrierOrigin,
        certificate_serial: carrier.certificateSerial,
        hash_alg: input.principal_binding.hash_alg,
      },
    }),
  };
}

export function mapAicJwtJktBoundCrossingAuthority(
  input: AicJwtJktBoundCrossingInput,
  context: AicCrossingRelyingPartyContext,
): CrossingAuthorityMappingResult {
  if (!isRecord(input)
    || !exactKeys(input, BOUND_JWT_INPUT_KEYS)
    || !commonValid(input)
    || !validRequestBinding(input.request_binding)
    || !validRelyingPartyContext(context)) {
    return { ok: false, reason: 'mapping_input_invalid' };
  }
  if (!validJktBinding(input.principal_binding)) {
    return { ok: false, reason: 'aic_native_type_confusion' };
  }
  const carrier = inspectJwtCarrier(input);
  if (!carrier) return { ok: false, reason: 'aic_carrier_provenance_unverifiable' };
  if (carrier.artifactDigest !== input.artifact_digest) {
    return { ok: false, reason: 'aic_carrier_artifact_digest_mismatch' };
  }
  if (carrier.claimedKeyHash !== input.principal_binding.claimed_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  if (carrier.presentedKeyHash !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  const jwtValidity = jwtValidityDisposition(input, carrier);
  if (jwtValidity) return { ok: false, reason: jwtValidity };
  if (!carrier.audiences.includes(context.admission_domain.audience)) {
    return { ok: false, reason: 'aic_audience_mismatch' };
  }
  if (input.principal_binding.claimed_key_hash
    !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  const disposition = boundDisposition(
    input,
    context,
    AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
  );
  if (disposition) return { ok: false, reason: disposition };
  return {
    ok: true,
    authority: boundAuthorityFrom(input, context, {
      adapterId: 'native:aic-jwt-rfc7638-jkt-bound',
      mappingProfile: AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE,
      nativeProfile: 'AIC-JWT-RFC7638-JKT',
      binding: input.principal_binding,
      replayIdentity: {
        carrier_origin: carrier.carrierOrigin,
        issuer: carrier.issuer,
        artifact_id: carrier.artifactId,
      },
      instanceContext: {
        carrier_origin: carrier.carrierOrigin,
        downstream_representation: carrier.representation,
        typ: 'aic+jwt',
      },
    }),
  };
}

export function mapAicX509SpkiBoundCrossingAuthority(
  input: AicX509SpkiBoundCrossingInput,
  context: AicCrossingRelyingPartyContext,
): CrossingAuthorityMappingResult {
  if (!isRecord(input)
    || !exactKeys(input, BOUND_X509_INPUT_KEYS)
    || !commonValid(input)
    || !validRequestBinding(input.request_binding)
    || !validRelyingPartyContext(context)) {
    return { ok: false, reason: 'mapping_input_invalid' };
  }
  if (!validSpkiBinding(input.principal_binding)) {
    return { ok: false, reason: 'aic_native_type_confusion' };
  }
  const carrier = inspectX509Carrier(input);
  if (!carrier) return { ok: false, reason: 'aic_carrier_provenance_unverifiable' };
  if (carrier.artifactDigest !== input.artifact_digest) {
    return { ok: false, reason: 'aic_carrier_artifact_digest_mismatch' };
  }
  if (carrier.presentedKeyHash !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  if (input.principal_binding.claimed_key_hash
    !== input.principal_binding.presented_key_hash) {
    return { ok: false, reason: 'aic_principal_binding_mismatch' };
  }
  const disposition = boundDisposition(
    input,
    context,
    AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
  );
  if (disposition) return { ok: false, reason: disposition };
  return {
    ok: true,
    authority: boundAuthorityFrom(input, context, {
      adapterId: 'native:aic-x509-spki-bound',
      mappingProfile: AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE,
      nativeProfile: 'AIC-X509-SPKI',
      binding: input.principal_binding,
      replayIdentity: {
        carrier_origin: carrier.carrierOrigin,
        artifact_digest: carrier.artifactDigest,
        certificate_serial: carrier.certificateSerial,
      },
      instanceContext: {
        carrier_origin: carrier.carrierOrigin,
        certificate_serial: carrier.certificateSerial,
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
    && identifier(value.projected_key_id);
}

function validProjectionContext(
  value: unknown,
): value is AicJwtSvidProjectionRelyingPartyContext {
  return isRecord(value)
    && exactKeys(value, PROJECTION_CONTEXT_KEYS)
    && validRelyingPartyPolicy(value.relying_party_policy)
    && instant(value.evaluated_at)
    && Number.isSafeInteger(value.max_status_age_seconds)
    && Number(value.max_status_age_seconds) >= 0
    && Number(value.max_status_age_seconds) <= 86_400;
}

export function projectAicJwtToStrictJwtSvid(
  input: AicJwtSvidProjectionInput,
  context: AicJwtSvidProjectionRelyingPartyContext,
): AicJwtSvidProjectionResult {
  if (!isRecord(input)
    || !validProjectionInput(input)
    || !validProjectionContext(context)) {
    return { ok: false, reason: 'jwt_svid_projection_input_invalid' };
  }
  const source = mapAicJwtJktCrossingAuthority(
    input.source,
    context.relying_party_policy,
    {
      evaluated_at: context.evaluated_at,
      max_status_age_seconds: context.max_status_age_seconds,
    },
  );
  if (!source.ok) {
    if (source.reason === 'aic_status_observation_future') {
      return { ok: false, reason: 'jwt_svid_source_status_future' };
    }
    if (source.reason === 'aic_status_observation_stale') {
      return { ok: false, reason: 'jwt_svid_source_status_stale' };
    }
    if (source.reason === 'aic_validity_window_mismatch') {
      return { ok: false, reason: 'jwt_svid_source_validity_mismatch' };
    }
    return source;
  }
  const carrier = inspectJwtCarrier(input.source);
  if (!carrier) return { ok: false, reason: 'aic_carrier_provenance_unverifiable' };
  const evaluatedAtMillis = Date.parse(context.evaluated_at);
  const issuedAtMillis = input.issued_at * 1_000;
  if (issuedAtMillis !== evaluatedAtMillis) {
    return { ok: false, reason: 'jwt_svid_projection_evaluation_time_mismatch' };
  }
  const observedAtMillis = Date.parse(input.source.status.checked_at);
  if (observedAtMillis > evaluatedAtMillis) {
    return { ok: false, reason: 'jwt_svid_source_status_future' };
  }
  if (evaluatedAtMillis - observedAtMillis
      > context.max_status_age_seconds * 1_000) {
    return { ok: false, reason: 'jwt_svid_source_status_stale' };
  }
  const sourceNotBeforeMillis = Date.parse(input.source.validity.not_before);
  const sourceNotAfterMillis = Date.parse(input.source.validity.not_after);
  const projectedNotBeforeMillis = (input.not_before ?? input.issued_at) * 1_000;
  if (issuedAtMillis < sourceNotBeforeMillis
    || projectedNotBeforeMillis < sourceNotBeforeMillis
    || input.expires_at * 1_000 > sourceNotAfterMillis) {
    return { ok: false, reason: 'jwt_svid_source_validity_mismatch' };
  }
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
    ...(carrier.semantics.hasConstraints ? ['aic.constraints'] : []),
    ...(carrier.semantics.hasDelegationAssertion ? ['da'] : []),
    ...(carrier.semantics.confirmationKeyPresent ? ['cnf'] : []),
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
    issuer: carrier.issuer,
    token_digest: carrier.artifactDigest,
    source_semantics_digest: digestAebTyped(
      {
        principal_binding: input.source.principal_binding,
        source_audiences: carrier.audiences,
        has_constraints: carrier.semantics.hasConstraints,
        delegation_mode: carrier.semantics.delegationMode,
        has_delegation_assertion: carrier.semantics.hasDelegationAssertion,
        confirmation_key_present: carrier.semantics.confirmationKeyPresent,
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
