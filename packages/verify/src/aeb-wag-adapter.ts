// SPDX-License-Identifier: Apache-2.0
/**
 * Revision-pinned Workload Authorization Grant adapter for AEB-ADAPTER-v1.
 *
 * The adapter verifies a WAG -00 JWT authorization grant under an exact,
 * relying-party-pinned per-tenancy issuer key. It then maps the observed
 * RFC 7523 token request, not a downstream resource-server operation, to an
 * exact CAID. WAG properties remain evidence for local policy and never become
 * authorization merely because the platform signed them.
 *
 * Important boundary: WAG -00 does not bind the downstream tool or resource-
 * server action. Asking this adapter to use WAG alone for such an action
 * returns INDETERMINATE.
 */
import crypto, { type KeyObject } from 'node:crypto';

// The governed CAID implementation is JavaScript and has no declaration file.
// @ts-expect-error -- runtime shape is checked before use.
import { computeCaid } from '../vendor/caid.mjs';
import {
  digestAeb,
  type Acceptance,
  type AebAdapter,
  type AebAdapterInput,
  type AebDigest,
  type AebMappingResult,
  type AebNativeResult,
  type AebPinnedProfile,
  type AebStatusInput,
} from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, unknown>;

export const WAG_DRAFT_REVISION = 'draft-carleton-workload-authz-grant-00';
export const WAG_DRAFT_SOURCE_COMMIT = '13f516a5e458b89ca30f7ea47a802091dd9d4154';
export const WAG_DRAFT_TXT_SHA256 = 'sha256:4b92283fefdce2093e11f70bbfce5aa00af9191f7b278d498f30f2b34a78f798';
export const WAG_DRAFT_SOURCE_SHA256 = 'sha256:195fa249380052324d78c8dbfbdeb4ff7b7c5b3bd5d9a9f4d9abf110e944e4e2';
export const WAG_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
export const WAG_TOKEN_ISSUANCE_ACTION_TYPE = 'oauth.access-token.issue.1';
export const WAG_AEB_ADAPTER_ID = 'native:workload-authorization-grant';
export const WAG_AEB_ADAPTER_VERSION = '1';
export const WAG_AEB_CONFIG_VERSION = 'AEB-WAG-CONFIG-v1';
export const WAG_TRUST_ROOT_VERSION = 'AEB-WAG-PER-TENANCY-ROOT-v1';
export const WAG_CAID_MAPPING_VERSION = 'AEB-WAG-TOKEN-ISSUANCE-CAID-MAPPING-v1';
export const WAG_CAID_MAPPER_ID = 'mapper:wag-token-issuance-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$/;
const CONFIG_KEYS = new Set([
  '@version', 'evidence_role', 'issuer', 'tenancy', 'wimse_authority',
  'authorization_server_issuer', 'token_endpoint', 'resource', 'action_type',
  'property_claims', 'require_wimse_identifier', 'clock_skew_seconds',
  'max_grant_lifetime_seconds', 'max_status_age_seconds',
]);
const ROOT_KEYS = new Set([
  '@version', 'use', 'issuer', 'tenancy', 'key_id', 'algorithm', 'public_jwk',
]);
const JWK_KEYS = new Set(['kty', 'crv', 'x', 'y']);
const STATUS_KEYS = new Set([
  'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const ARTIFACT_KEYS = new Set(['grant_type', 'assertion', 'resource']);
const HEADER_KEYS = new Set(['alg', 'kid', 'typ']);
const ACTION_KEYS = new Set([
  'action_type', 'authorization_server', 'grant', 'resource', 'properties',
]);
const AUTHORIZATION_SERVER_KEYS = new Set(['issuer', 'token_endpoint']);
const GRANT_KEYS = new Set(['issuer', 'subject', 'jti', 'assertion_digest']);
const MAPPING_KEYS = new Set([
  '@version', 'native_protocol', 'projection', 'action_type', 'suite', 'definitions',
]);

export interface WagAdapterConfig {
  '@version': typeof WAG_AEB_CONFIG_VERSION;
  evidence_role: string;
  /** Exact per-tenancy issuer allowlisted by the authorization server. */
  issuer: string;
  tenancy: string;
  /** Exact authority component accepted for a URI-form Workload Identifier. */
  wimse_authority: string;
  authorization_server_issuer: string;
  token_endpoint: string;
  resource: string;
  action_type: typeof WAG_TOKEN_ISSUANCE_ACTION_TYPE;
  /** Signed properties that are material to this relying party's token request. */
  property_claims: string[];
  require_wimse_identifier: boolean;
  clock_skew_seconds: number;
  max_grant_lifetime_seconds: number;
  max_status_age_seconds: number;
}

export interface WagTrustRoot {
  '@version': typeof WAG_TRUST_ROOT_VERSION;
  use: 'wag-per-tenancy-issuer-key';
  issuer: string;
  tenancy: string;
  key_id: string;
  algorithm: 'ES256';
  public_jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
}

export interface WagConstructorPins {
  config: WagAdapterConfig;
  trust_roots: readonly WagTrustRoot[];
}

export interface WagArtifact {
  grant_type: typeof WAG_GRANT_TYPE;
  assertion: string;
  resource: string;
}

interface ParsedRoot extends WagTrustRoot { key: KeyObject }
interface ParsedPins {
  config: WagAdapterConfig;
  roots: ParsedRoot[];
  configDigest: AebDigest;
  rootsDigest: AebDigest;
}
interface ParsedGrant {
  header: Obj;
  claims: Obj;
  signingInput: string;
  signature: Buffer;
}

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, allowed: ReadonlySet<string>, optional: ReadonlySet<string> = new Set()): boolean {
  const required = [...allowed].filter((key) => !optional.has(key));
  return Object.keys(value).every((key) => allowed.has(key))
    && required.every((key) => Object.hasOwn(value, key));
}

function nonEmptyString(value: unknown, max = 2048): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function canonicalBase64url(value: unknown, length?: number): value is string {
  if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length > 0 && bytes.toString('base64url') === value
      && (length === undefined || bytes.length === length);
  } catch { return false; }
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return NaN;
  return Date.parse(value);
}

function safeDigest(value: unknown): AebDigest {
  try { return digestAeb(value); } catch { return digestAeb({ invalid_native_value: true }); }
}

function statusDigest(status: AebStatusInput): AebDigest {
  return safeDigest({
    checked_at: status?.checked_at,
    expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked,
    revoked: status?.revoked,
    consumed: status?.consumed,
    unavailable: status?.unavailable === true,
  });
}

function statusDisposition(
  status: AebStatusInput,
  now: string,
  maxAgeSeconds: number,
): { acceptance: Acceptance; reasons: string[] } {
  if (!isRecord(status) || !exactKeys(status, STATUS_KEYS, new Set(['unavailable']))) {
    return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
  }
  const reasons: string[] = [];
  if (status.unavailable === true) reasons.push('status_unavailable');
  if (status.revoked === true) reasons.push('evidence_revoked');
  if (status.consumed === true) reasons.push('evidence_consumed');
  if (status.revocation_checked !== true) reasons.push('revocation_not_checked');
  if (typeof status.revoked !== 'boolean' || typeof status.consumed !== 'boolean'
      || typeof status.revocation_checked !== 'boolean'
      || (status.unavailable !== undefined && typeof status.unavailable !== 'boolean')) {
    reasons.push('status_malformed');
  }
  const nowMs = parseInstant(now);
  const checkedMs = parseInstant(status.checked_at);
  const expiresMs = parseInstant(status.expires_at);
  if (![nowMs, checkedMs, expiresMs].every(Number.isFinite)) {
    reasons.push('status_time_indeterminate');
  } else {
    const age = Math.floor((nowMs - checkedMs) / 1000);
    if (checkedMs > nowMs) reasons.push('status_checked_in_future');
    if (checkedMs >= expiresMs || nowMs >= expiresMs) reasons.push('status_expired');
    if (age < 0 || age > maxAgeSeconds) reasons.push('status_too_old');
  }
  const unique = [...new Set(reasons)].sort();
  if (status.revoked === true || status.consumed === true) {
    return { acceptance: 'REJECTED', reasons: unique };
  }
  return unique.length === 0
    ? { acceptance: 'ACCEPTED', reasons: [] }
    : { acceptance: 'INDETERMINATE', reasons: unique };
}

function exactUrl(value: unknown): value is string {
  if (!nonEmptyString(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === ''
      && parsed.hash === '';
  } catch { return false; }
}

function validPropertyName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$/.test(value)
    && !['iss', 'sub', 'aud', 'exp', 'iat', 'jti'].includes(value);
}

function parseConfig(value: unknown): WagAdapterConfig | null {
  if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== WAG_AEB_CONFIG_VERSION
      || typeof value.evidence_role !== 'string' || !IDENTIFIER_RE.test(value.evidence_role)
      || !exactUrl(value.issuer) || !nonEmptyString(value.tenancy, 256)
      || !nonEmptyString(value.wimse_authority, 253)
      || !exactUrl(value.authorization_server_issuer) || !exactUrl(value.token_endpoint)
      || !exactUrl(value.resource) || value.action_type !== WAG_TOKEN_ISSUANCE_ACTION_TYPE
      || !Array.isArray(value.property_claims)
      || !value.property_claims.every(validPropertyName)
      || new Set(value.property_claims).size !== value.property_claims.length
      || [...value.property_claims].sort().join('\0') !== value.property_claims.join('\0')
      || typeof value.require_wimse_identifier !== 'boolean'
      || !nonNegativeInteger(value.clock_skew_seconds)
      || !nonNegativeInteger(value.max_grant_lifetime_seconds)
      || value.max_grant_lifetime_seconds < 1
      || !nonNegativeInteger(value.max_status_age_seconds)) return null;
  return structuredClone(value) as unknown as WagAdapterConfig;
}

function parseRoots(value: readonly unknown[], config: WagAdapterConfig): ParsedRoot[] | null {
  if (!Array.isArray(value) || value.length < 1) return null;
  const keys = new Set<string>();
  const roots: ParsedRoot[] = [];
  for (const candidate of value) {
    if (!isRecord(candidate) || !exactKeys(candidate, ROOT_KEYS)
        || candidate['@version'] !== WAG_TRUST_ROOT_VERSION
        || candidate.use !== 'wag-per-tenancy-issuer-key'
        || candidate.issuer !== config.issuer || candidate.tenancy !== config.tenancy
        || !nonEmptyString(candidate.key_id, 256) || keys.has(candidate.key_id)
        || candidate.algorithm !== 'ES256'
        || !isRecord(candidate.public_jwk) || !exactKeys(candidate.public_jwk, JWK_KEYS)
        || candidate.public_jwk.kty !== 'EC' || candidate.public_jwk.crv !== 'P-256'
        || !canonicalBase64url(candidate.public_jwk.x, 32)
        || !canonicalBase64url(candidate.public_jwk.y, 32)) return null;
    let key: KeyObject;
    try { key = crypto.createPublicKey({ key: candidate.public_jwk, format: 'jwk' }); }
    catch { return null; }
    if (key.asymmetricKeyType !== 'ec'
        || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
    keys.add(candidate.key_id);
    roots.push({ ...(structuredClone(candidate) as unknown as WagTrustRoot), key });
  }
  return roots;
}

function parsePins(value: WagConstructorPins): ParsedPins {
  const config = parseConfig(value?.config);
  if (!config) throw new TypeError('invalid WAG constructor config');
  const roots = parseRoots(value?.trust_roots, config);
  if (!roots) throw new TypeError('invalid WAG constructor trust roots');
  return {
    config,
    roots,
    configDigest: safeDigest(config),
    rootsDigest: safeDigest(value.trust_roots),
  };
}

function decodeBase64urlUtf8(segment: string): string | null {
  if (!canonicalBase64url(segment)) return null;
  try {
    const bytes = Buffer.from(segment, 'base64url');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return Buffer.from(text, 'utf8').equals(bytes) ? text : null;
  } catch { return null; }
}

function parseCompactGrant(value: unknown): ParsedGrant | null {
  if (typeof value !== 'string') return null;
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const headerText = decodeBase64urlUtf8(parts[0]);
  const claimsText = decodeBase64urlUtf8(parts[1]);
  if (headerText === null || claimsText === null
      || !strictJsonGate(headerText).ok || !strictJsonGate(claimsText).ok
      || !canonicalBase64url(parts[2], 64)) return null;
  let header: unknown;
  let claims: unknown;
  try { header = JSON.parse(headerText); claims = JSON.parse(claimsText); }
  catch { return null; }
  if (!isRecord(header) || !exactKeys(header, HEADER_KEYS, new Set(['typ']))
      || !isRecord(claims)) return null;
  return {
    header,
    claims,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: Buffer.from(parts[2], 'base64url'),
  };
}

function validAudience(value: unknown): value is string | string[] {
  return nonEmptyString(value)
    || (Array.isArray(value) && value.length > 0 && value.every((entry) => nonEmptyString(entry))
      && new Set(value).size === value.length);
}

function audienceContains(value: string | string[], candidate: string): boolean {
  return (Array.isArray(value) ? value : [value]).includes(candidate);
}

function validWimseSubject(subject: string, expectedAuthority: string): boolean {
  try {
    const parsedSubject = new URL(subject);
    return parsedSubject.protocol === 'wimse:' && parsedSubject.host === expectedAuthority
      && parsedSubject.username === '' && parsedSubject.password === ''
      && parsedSubject.search === '' && parsedSubject.hash === '';
  } catch { return false; }
}

function validMaterialProperty(value: unknown): boolean {
  return nonEmptyString(value)
    || (Array.isArray(value) && value.length > 0 && value.every((entry) => nonEmptyString(entry)));
}

function parseArtifact(value: unknown): WagArtifact | null {
  if (!isRecord(value) || !exactKeys(value, ARTIFACT_KEYS)
      || value.grant_type !== WAG_GRANT_TYPE
      || !nonEmptyString(value.assertion, 64 * 1024)
      || !exactUrl(value.resource)) return null;
  return structuredClone(value) as unknown as WagArtifact;
}

function projectAction(artifact: WagArtifact, claims: Obj, config: WagAdapterConfig): Obj | null {
  if (!nonEmptyString(claims.iss) || !nonEmptyString(claims.sub)
      || !nonEmptyString(claims.jti)) return null;
  const properties: Obj = {};
  for (const name of config.property_claims) {
    if (!Object.hasOwn(claims, name) || !validMaterialProperty(claims[name])) return null;
    properties[name] = structuredClone(claims[name]);
  }
  return {
    action_type: config.action_type,
    authorization_server: {
      issuer: config.authorization_server_issuer,
      token_endpoint: config.token_endpoint,
    },
    grant: {
      issuer: claims.iss,
      subject: claims.sub,
      jti: claims.jti,
      assertion_digest: safeDigest(artifact.assertion),
    },
    resource: artifact.resource,
    properties,
  };
}

function exactExpectedTokenIssuanceAction(value: unknown, config: WagAdapterConfig): value is Obj {
  if (!isRecord(value) || !exactKeys(value, ACTION_KEYS)
      || value.action_type !== config.action_type
      || !isRecord(value.authorization_server)
      || !exactKeys(value.authorization_server, AUTHORIZATION_SERVER_KEYS)
      || value.authorization_server.issuer !== config.authorization_server_issuer
      || value.authorization_server.token_endpoint !== config.token_endpoint
      || !isRecord(value.grant) || !exactKeys(value.grant, GRANT_KEYS)
      || !nonEmptyString(value.grant.issuer) || !nonEmptyString(value.grant.subject)
      || !nonEmptyString(value.grant.jti)
      || typeof value.grant.assertion_digest !== 'string'
      || !DIGEST_RE.test(value.grant.assertion_digest)
      || value.resource !== config.resource || !isRecord(value.properties)
      || !exactKeys(value.properties, new Set(config.property_claims))) return false;
  const properties = value.properties as Obj;
  return config.property_claims.every((name) => validMaterialProperty(properties[name]));
}

function fallbackNative(
  input: Omit<AebAdapterInput, 'profile'>,
  pins: ParsedPins,
): AebNativeResult {
  const evidenceDigest = safeDigest(input?.artifact);
  return {
    native_verification: 'FAILED',
    acceptance: 'INDETERMINATE',
    evidence_digest: evidenceDigest,
    status_digest: statusDigest(input?.status),
    evidence_role: pins.config.evidence_role,
    subject: { id: 'workload:unresolved', kind: 'workload' },
    replay_unit: evidenceDigest,
    reasons: [],
  };
}

function verifyNative(
  input: Omit<AebAdapterInput, 'profile'>,
  pins: ParsedPins,
): AebNativeResult {
  const result = fallbackNative(input, pins);
  if (safeDigest(input.adapter_config) !== pins.configDigest
      || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:constructor_pin_mismatch'];
    return result;
  }
  const artifact = parseArtifact(input.artifact);
  const grant = artifact ? parseCompactGrant(artifact.assertion) : null;
  if (!artifact || !grant) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:malformed_grant'];
    return result;
  }
  const root = pins.roots.find((candidate) => candidate.key_id === grant.header.kid);
  if (grant.header.alg !== 'ES256' || (grant.header.typ !== undefined && grant.header.typ !== 'JWT') || !root) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:unsupported_or_unpinned_key'];
    return result;
  }
  let signatureValid = false;
  try {
    signatureValid = crypto.verify(
      'sha256',
      Buffer.from(grant.signingInput, 'ascii'),
      { key: root.key, dsaEncoding: 'ieee-p1363' },
      grant.signature,
    );
  } catch { signatureValid = false; }
  if (!signatureValid) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:signature_invalid'];
    return result;
  }
  result.native_verification = 'VERIFIED';
  const claims = grant.claims;
  if (!nonEmptyString(claims.iss) || !nonEmptyString(claims.sub)
      || !validAudience(claims.aud) || !nonEmptyString(claims.jti)
      || !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat)) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:required_claim_invalid'];
    return result;
  }
  result.replay_unit = safeDigest({
    protocol: WAG_DRAFT_REVISION,
    issuer: claims.iss,
    subject: claims.sub,
    jti: claims.jti,
  });
  if (claims.iss !== pins.config.issuer || root.issuer !== claims.iss) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:issuer_mismatch'];
    return result;
  }
  if (pins.config.require_wimse_identifier
      && !validWimseSubject(String(claims.sub), pins.config.wimse_authority)) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:wimse_identifier_required'];
    return result;
  }
  result.subject = { id: String(claims.sub), kind: 'workload' };
  if (!audienceContains(claims.aud as string | string[], pins.config.authorization_server_issuer)
      && !audienceContains(claims.aud as string | string[], pins.config.token_endpoint)) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:audience_mismatch'];
    return result;
  }
  if (artifact.resource !== pins.config.resource) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:resource_mismatch'];
    return result;
  }
  const nowMs = parseInstant(input.now);
  if (!Number.isFinite(nowMs)) {
    result.acceptance = 'INDETERMINATE';
    result.reasons = ['wag:verification_time_invalid'];
    return result;
  }
  const nowSeconds = Math.floor(nowMs / 1000);
  const iat = Number(claims.iat);
  const exp = Number(claims.exp);
  if (exp <= nowSeconds - pins.config.clock_skew_seconds) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:grant_expired'];
    return result;
  }
  if (iat > nowSeconds + pins.config.clock_skew_seconds) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:grant_not_yet_valid'];
    return result;
  }
  if (exp <= iat || exp - iat > pins.config.max_grant_lifetime_seconds) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:grant_lifetime_invalid'];
    return result;
  }
  const projected = projectAction(artifact, claims, pins.config);
  if (!projected) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:material_property_invalid'];
    return result;
  }
  const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
  if (status.acceptance !== 'ACCEPTED') {
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    return result;
  }
  if (!isRecord(input.expected_action)
      || input.expected_action.action_type !== pins.config.action_type) {
    result.acceptance = 'INDETERMINATE';
    result.reasons = ['wag:does_not_bind_downstream_action'];
    return result;
  }
  if (!exactExpectedTokenIssuanceAction(input.expected_action, pins.config)
      || safeDigest(projected) !== safeDigest(input.expected_action)) {
    result.acceptance = 'REJECTED';
    result.reasons = ['wag:token_request_projection_mismatch'];
    return result;
  }
  result.acceptance = 'ACCEPTED';
  result.reasons = [];
  return result;
}

export function createWagActionDefinition(actionType: string): Obj {
  if (actionType !== WAG_TOKEN_ISSUANCE_ACTION_TYPE) {
    throw new TypeError('invalid WAG action definition');
  }
  return {
    '@version': WAG_CAID_MAPPING_VERSION,
    native_protocol: WAG_DRAFT_REVISION,
    projection: 'wag-observed-token-request-v1',
    action_type: actionType,
    suite: 'jcs-sha256',
    definitions: [{
      action_type: actionType,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'authorization_server', type: 'object' },
        { name: 'grant', type: 'object' },
        { name: 'resource', type: 'string' },
        { name: 'properties', type: 'object' },
      ],
      optional_fields: [],
    }],
  };
}

function validMappingProfile(profile: AebPinnedProfile, config: WagAdapterConfig): boolean {
  if (!isRecord(profile)
      || profile.version !== WAG_CAID_MAPPING_VERSION
      || profile.mapper_id !== WAG_CAID_MAPPER_ID
      || !isRecord(profile.resolver)
      || profile.resolver.id !== WAG_CAID_MAPPER_ID
      || profile.resolver.version !== '1'
      || typeof profile.resolver.implementation_digest !== 'string'
      || !DIGEST_RE.test(profile.resolver.implementation_digest)
      || !isRecord(profile.semantic_equivalence)
      || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
      || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
      || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
      || profile.semantic_equivalence.omitted_material_fields.length !== 0
      || !isRecord(profile.definition)
      || !exactKeys(profile.definition, MAPPING_KEYS)) return false;
  return safeDigest(profile.definition) === safeDigest(createWagActionDefinition(config.action_type));
}

function mapAction(
  input: AebAdapterInput & { native: AebNativeResult },
  pins: ParsedPins,
): AebMappingResult {
  if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
  }
  if (safeDigest(input.adapter_config) !== pins.configDigest
      || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
  }
  if (!validMappingProfile(input.profile, pins.config)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
  }
  if (!exactExpectedTokenIssuanceAction(input.expected_action, pins.config)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_token_request'] };
  }
  const actionDigest = safeDigest(input.expected_action);
  let computed: unknown;
  try {
    computed = computeCaid(input.expected_action, {
      suite: 'jcs-sha256',
      definitions: (input.profile.definition as Obj).definitions,
    });
  } catch { computed = null; }
  if (!isRecord(computed) || typeof computed.caid !== 'string'
      || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)
      || computed.digest !== actionDigest) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
  }
  return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}

export function createWagAebAdapter(constructorPins: WagConstructorPins): AebAdapter {
  const pins = parsePins(constructorPins);
  return Object.freeze({
    id: WAG_AEB_ADAPTER_ID,
    version: WAG_AEB_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      try { return verifyNative(input, pins); } catch {
        const result = fallbackNative(input, pins);
        result.reasons = ['wag:unexpected_adapter_error'];
        return result;
      }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try { return mapAction(input, pins); } catch {
        return {
          mapping: 'INDETERMINATE', caid: null, action_digest: null,
          reasons: ['wag:unexpected_mapping_error'],
        };
      }
    },
  });
}
