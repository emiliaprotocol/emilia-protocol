// SPDX-License-Identifier: Apache-2.0
/**
 * OAuth transaction-authorization challenge adapter for AEB-ADAPTER-v1.
 *
 * Source lock: draft-rosomakho-oauth-txn-challenge-00.
 *
 * The native artifact is deliberately a pair: the protected resource's signed
 * challenge and the authorization server's issued access token. A challenge,
 * accepted polling request, or transaction_authorization_id is not approval.
 * Only a valid access token bound to the challenge, exact transaction, actor,
 * and application-verified RAR details can become ACCEPTED evidence.
 */
import crypto, { type KeyObject } from 'node:crypto';

// @ts-expect-error -- governed JavaScript implementation, runtime checked.
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
type SupportedAlgorithm = 'ES256' | 'EdDSA';

export const OAUTH_TXN_CHALLENGE_DRAFT_REVISION = 'draft-rosomakho-oauth-txn-challenge-00';
export const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID = 'native:oauth-transaction-challenge';
export const OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION = '3';
export const OAUTH_TXN_CHALLENGE_CONFIG_VERSION = 'AEB-OAUTH-TXN-CHALLENGE-CONFIG-v1';
export const OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION = 'AEB-OAUTH-TXN-CHALLENGE-ROOT-v1';
export const OAUTH_TXN_CHALLENGE_MAPPING_VERSION = 'AEB-OAUTH-TXN-CHALLENGE-CAID-MAPPING-v2';
export const OAUTH_TXN_CHALLENGE_MAPPER_ID = 'mapper:oauth-transaction-exact-action-v2';
/** Stable across OAuth token reissuance, AEB wrapper changes, and profile revisions. */
export const OAUTH_TXN_CHALLENGE_REPLAY_NAMESPACE =
  'emilia:oauth-txn-challenge:protected-resource-transaction:v1';

export const OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS = Object.freeze([
  'challenge.header.alg',
  'challenge.header.kid',
  'challenge.header.typ',
  'challenge.iat',
  'challenge.exp',
  'challenge.jti',
  'challenge.reason',
  'challenge.reason_uri',
  'access_token.header.alg',
  'access_token.header.kid',
  'access_token.header.typ',
  'access_token.iat',
  'access_token.exp',
  'access_token.jti',
] as const);

export const OAUTH_TXN_CHALLENGE_SEMANTIC_OMISSION_BASIS = Object.freeze([
  ...OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS.map((path) => Object.freeze({
    path,
    relying_party_basis: path.includes('.header.')
      ? 'signature_and_type_verification_input_not_executed_action_semantics'
      : path.endsWith('.iat') || path.endsWith('.exp')
        ? 'freshness_verification_input_not_executed_action_semantics'
        : path.endsWith('.jti')
          ? 'artifact_instance_identifier_superseded_by_transaction_scoped_replay_identity'
          : 'protected_resource_explanation_not_executed_action_semantics',
  })),
]);

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/;
const CONFIG_KEYS = new Set([
  '@version', 'evidence_role', 'subject', 'action_type', 'protected_resource',
  'authorization_server', 'oauth_client_id', 'oauth_subject', 'require_actor_context',
  'replay_equivalence',
  'clock_skew_seconds', 'max_challenge_lifetime_seconds',
  'max_access_token_lifetime_seconds', 'max_status_age_seconds', 'details_verifier',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const DESCRIPTOR_KEYS = new Set(['id', 'version', 'implementation_digest']);
const ROOT_KEYS = new Set(['@version', 'use', 'issuer', 'key_id', 'algorithm', 'public_key']);
const STATUS_KEYS = new Set([
  'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const ARTIFACT_KEYS = new Set(['challenge_jwt', 'access_token_jwt']);
const HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const CHALLENGE_KEYS = new Set([
  'iss', 'aud', 'iat', 'exp', 'jti', 'txn', 'authorization_details', 'reason', 'reason_uri', 'act',
]);
const ACCESS_KEYS = new Set([
  'iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'client_id', 'txn', 'authorization_details', 'act',
]);
const EXPECTED_KEYS = new Set(['action_type', 'oauth_transaction']);
const TXN_ACTION_KEYS_WITH_ACTOR = new Set(['txn', 'authorization_details', 'actor', 'verified_context']);
const TXN_ACTION_KEYS_NO_ACTOR = new Set(['txn', 'authorization_details', 'verified_context']);
const VERIFIED_CONTEXT_KEYS = new Set([
  'challenge_issuer', 'challenge_audience', 'access_token_issuer',
  'access_token_subject', 'access_token_audience', 'access_token_client_id',
]);
const MAPPING_KEYS = new Set([
  '@version', 'native_protocol', 'projection', 'action_type', 'suite',
  'semantic_loss_contract', 'definitions',
]);

export interface OAuthTransactionChallengeDetailsVerifierDescriptor {
  id: string;
  version: string;
  implementation_digest: AebDigest;
}

export interface OAuthTransactionChallengeDetailsVerifier
  extends OAuthTransactionChallengeDetailsVerifierDescriptor {
  verify(input: {
    requested: unknown;
    granted: unknown;
    expected: unknown;
  }): { verified: boolean; reason: string | null };
}

export interface OAuthTransactionChallengeAdapterConfig {
  '@version': typeof OAUTH_TXN_CHALLENGE_CONFIG_VERSION;
  evidence_role: 'transaction-authorization';
  /** The signer of the authorization result; no human identity is inferred. */
  subject: { id: string; kind: 'organization' | 'system'; native_id: string };
  action_type: string;
  protected_resource: string;
  authorization_server: string;
  oauth_client_id: string;
  oauth_subject: string;
  require_actor_context: boolean;
  /** Profile rule: a protected-resource transaction identifier is never reusable. */
  replay_equivalence: 'nonreusable-protected-resource-transaction';
  clock_skew_seconds: number;
  max_challenge_lifetime_seconds: number;
  max_access_token_lifetime_seconds: number;
  max_status_age_seconds: number;
  details_verifier: OAuthTransactionChallengeDetailsVerifierDescriptor;
}

export type OAuthTransactionChallengeTrustUse =
  | 'protected-resource-challenge'
  | 'authorization-server-access-token';

export interface OAuthTransactionChallengeTrustRoot {
  '@version': typeof OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION;
  use: OAuthTransactionChallengeTrustUse;
  issuer: string;
  key_id: string;
  algorithm: SupportedAlgorithm;
  /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
  public_key: string;
}

export interface OAuthTransactionChallengeConstructorPins {
  config: OAuthTransactionChallengeAdapterConfig;
  trust_roots: readonly OAuthTransactionChallengeTrustRoot[];
  details_verifier: OAuthTransactionChallengeDetailsVerifier;
}

interface ParsedRoot extends OAuthTransactionChallengeTrustRoot { key: KeyObject }
interface ParsedPins {
  config: OAuthTransactionChallengeAdapterConfig;
  challengeRoot: ParsedRoot;
  accessRoot: ParsedRoot;
  detailsVerifier: OAuthTransactionChallengeDetailsVerifier;
  configDigest: AebDigest;
  rootsDigest: AebDigest;
}

interface ParsedJwt { claims: Obj; signingInput: string; signature: Buffer }

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, keys: ReadonlySet<string>, optional: ReadonlySet<string> = new Set()): boolean {
  const required = [...keys].filter((key) => !optional.has(key));
  return Object.keys(value).every((key) => keys.has(key))
    && required.every((key) => Object.hasOwn(value, key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function safeDigest(value: unknown): AebDigest {
  try { return digestAeb(value); } catch { return digestAeb({ invalid_native_value: true }); }
}

function canonicalB64url(value: unknown): value is string {
  if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length > 0 && bytes.toString('base64url') === value;
  } catch { return false; }
}

function descriptor(value: unknown): value is OAuthTransactionChallengeDetailsVerifierDescriptor {
  return isRecord(value) && exactKeys(value, DESCRIPTOR_KEYS)
    && nonEmptyString(value.id) && nonEmptyString(value.version)
    && typeof value.implementation_digest === 'string' && DIGEST_RE.test(value.implementation_digest);
}

function parseConfig(value: unknown): OAuthTransactionChallengeAdapterConfig | null {
  if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== OAUTH_TXN_CHALLENGE_CONFIG_VERSION
      || value.evidence_role !== 'transaction-authorization'
      || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
      || typeof value.subject.id !== 'string' || !ID_RE.test(value.subject.id)
      || !['organization', 'system'].includes(String(value.subject.kind))
      || !nonEmptyString(value.subject.native_id)
      || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
      || !nonEmptyString(value.protected_resource) || !nonEmptyString(value.authorization_server)
      || value.subject.native_id !== value.authorization_server
      || !nonEmptyString(value.oauth_client_id) || !nonEmptyString(value.oauth_subject)
      || typeof value.require_actor_context !== 'boolean'
      || value.replay_equivalence !== 'nonreusable-protected-resource-transaction'
      || !nonNegativeInteger(value.clock_skew_seconds) || value.clock_skew_seconds > 60
      || !nonNegativeInteger(value.max_challenge_lifetime_seconds)
      || value.max_challenge_lifetime_seconds < 1
      || !nonNegativeInteger(value.max_access_token_lifetime_seconds)
      || value.max_access_token_lifetime_seconds < 1
      || !nonNegativeInteger(value.max_status_age_seconds)
      || !descriptor(value.details_verifier)) return null;
  return structuredClone(value) as unknown as OAuthTransactionChallengeAdapterConfig;
}

function parseRoot(candidate: unknown): ParsedRoot | null {
  if (!isRecord(candidate) || !exactKeys(candidate, ROOT_KEYS)
      || candidate['@version'] !== OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION
      || !['protected-resource-challenge', 'authorization-server-access-token'].includes(String(candidate.use))
      || !nonEmptyString(candidate.issuer) || !nonEmptyString(candidate.key_id)
      || !['ES256', 'EdDSA'].includes(String(candidate.algorithm))
      || !canonicalB64url(candidate.public_key)) return null;
  try {
    const bytes = Buffer.from(candidate.public_key, 'base64url');
    const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    if (!key.export({ type: 'spki', format: 'der' }).equals(bytes)) return null;
    if (candidate.algorithm === 'ES256'
        && (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')) return null;
    if (candidate.algorithm === 'EdDSA' && key.asymmetricKeyType !== 'ed25519') return null;
    return { ...(structuredClone(candidate) as unknown as OAuthTransactionChallengeTrustRoot), key };
  } catch { return null; }
}

function parsePins(value: OAuthTransactionChallengeConstructorPins): ParsedPins {
  const config = parseConfig(value?.config);
  if (!config || !Array.isArray(value?.trust_roots) || value.trust_roots.length !== 2) {
    throw new TypeError('invalid OAuth transaction-challenge constructor pins');
  }
  const roots = value.trust_roots.map(parseRoot);
  const challengeRoot = roots.find((root) => root?.use === 'protected-resource-challenge') ?? null;
  const accessRoot = roots.find((root) => root?.use === 'authorization-server-access-token') ?? null;
  const verifier = value.details_verifier;
  if (!challengeRoot || !accessRoot
      || challengeRoot.issuer !== config.protected_resource
      || accessRoot.issuer !== config.authorization_server
      || !verifier || typeof verifier.verify !== 'function'
      || verifier.id !== config.details_verifier.id
      || verifier.version !== config.details_verifier.version
      || verifier.implementation_digest !== config.details_verifier.implementation_digest) {
    throw new TypeError('invalid OAuth transaction-challenge trust or verifier pins');
  }
  return {
    config, challengeRoot, accessRoot, detailsVerifier: verifier,
    configDigest: safeDigest(config), rootsDigest: safeDigest(value.trust_roots),
  };
}

function decodeUtf8(segment: string): string | null {
  if (!canonicalB64url(segment)) return null;
  try {
    const bytes = Buffer.from(segment, 'base64url');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return Buffer.from(text, 'utf8').equals(bytes) ? text : null;
  } catch { return null; }
}

function verifyJwt(token: unknown, root: ParsedRoot, typ: string): ParsedJwt | null {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3 || !canonicalB64url(parts[2])) return null;
  const headerText = decodeUtf8(parts[0]); const claimsText = decodeUtf8(parts[1]);
  if (headerText === null || claimsText === null
      || !strictJsonGate(headerText).ok || !strictJsonGate(claimsText).ok) return null;
  let header: unknown; let claims: unknown;
  try { header = JSON.parse(headerText); claims = JSON.parse(claimsText); } catch { return null; }
  if (!isRecord(header) || !exactKeys(header, HEADER_KEYS)
      || header.alg !== root.algorithm || header.typ !== typ || header.kid !== root.key_id
      || !isRecord(claims)) return null;
  const signature = Buffer.from(parts[2], 'base64url');
  if ((root.algorithm === 'ES256' && signature.length !== 64)
      || (root.algorithm === 'EdDSA' && signature.length !== 64)) return null;
  const signingInput = `${parts[0]}.${parts[1]}`;
  let valid = false;
  try {
    valid = root.algorithm === 'ES256'
      ? crypto.verify('sha256', Buffer.from(signingInput, 'ascii'), { key: root.key, dsaEncoding: 'ieee-p1363' }, signature)
      : crypto.verify(null, Buffer.from(signingInput, 'ascii'), root.key, signature);
  } catch { valid = false; }
  return valid ? { claims, signingInput, signature } : null;
}

function parseInstant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value)) return NaN;
  return Date.parse(value);
}

function statusDigest(status: AebStatusInput): AebDigest {
  return safeDigest({
    checked_at: status?.checked_at, expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked, revoked: status?.revoked,
    consumed: status?.consumed, unavailable: status?.unavailable === true,
  });
}

function statusDisposition(status: AebStatusInput, now: string, maxAge: number): { acceptance: Acceptance; reasons: string[] } {
  if (!isRecord(status) || !Object.keys(status).every((key) => STATUS_KEYS.has(key))
      || !['checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed']
        .every((key) => Object.hasOwn(status, key))) {
    return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
  }
  const reasons: string[] = [];
  if (status.unavailable === true) reasons.push('status_unavailable');
  if (status.revoked === true) reasons.push('evidence_revoked');
  if (status.consumed === true) reasons.push('evidence_consumed');
  if (status.revocation_checked !== true) reasons.push('revocation_not_checked');
  const nowMs = parseInstant(now); const checked = parseInstant(status.checked_at); const expires = parseInstant(status.expires_at);
  if (![nowMs, checked, expires].every(Number.isFinite)) reasons.push('status_time_indeterminate');
  else {
    const age = Math.floor((nowMs - checked) / 1000);
    if (checked > nowMs) reasons.push('status_checked_in_future');
    if (checked >= expires || nowMs >= expires) reasons.push('status_expired');
    if (age < 0 || age > maxAge) reasons.push('status_too_old');
  }
  const unique = [...new Set(reasons)].sort();
  if (status.revoked === true || status.consumed === true) return { acceptance: 'REJECTED', reasons: unique };
  return unique.length ? { acceptance: 'INDETERMINATE', reasons: unique } : { acceptance: 'ACCEPTED', reasons: [] };
}

function validDetails(value: unknown): boolean {
  if (!Array.isArray(value) || value.length < 1 || !value.every(isRecord)) return false;
  try { safeDigest(value); return true; } catch { return false; }
}

function exactVerifiedContext(value: unknown): value is Obj {
  if (!isRecord(value) || !exactKeys(value, VERIFIED_CONTEXT_KEYS)) return false;
  return [...VERIFIED_CONTEXT_KEYS].every((key) => nonEmptyString(value[key]));
}

function expectedActionShape(value: unknown, config: OAuthTransactionChallengeAdapterConfig): value is Obj {
  const txnKeys = config.require_actor_context ? TXN_ACTION_KEYS_WITH_ACTOR : TXN_ACTION_KEYS_NO_ACTOR;
  return isRecord(value) && exactKeys(value, EXPECTED_KEYS) && value.action_type === config.action_type
    && isRecord(value.oauth_transaction) && exactKeys(value.oauth_transaction, txnKeys)
    && nonEmptyString(value.oauth_transaction.txn)
    && validDetails(value.oauth_transaction.authorization_details)
    && exactVerifiedContext(value.oauth_transaction.verified_context)
    && (!config.require_actor_context || isRecord(value.oauth_transaction.actor));
}

function verifiedContextMatches(value: Obj, config: OAuthTransactionChallengeAdapterConfig): boolean {
  const transaction = value.oauth_transaction as Obj;
  const context = transaction.verified_context as Obj;
  return context.challenge_issuer === config.protected_resource
    && context.challenge_audience === config.authorization_server
    && context.access_token_issuer === config.authorization_server
    && context.access_token_subject === config.oauth_subject
    && context.access_token_audience === config.protected_resource
    && context.access_token_client_id === config.oauth_client_id;
}

function exactExpectedAction(value: unknown, config: OAuthTransactionChallengeAdapterConfig): value is Obj {
  return expectedActionShape(value, config) && verifiedContextMatches(value, config);
}

function fallbackNative(input: Omit<AebAdapterInput, 'profile'>, pins: ParsedPins): AebNativeResult {
  const evidenceDigest = safeDigest(input?.artifact);
  return {
    native_verification: 'FAILED', acceptance: 'INDETERMINATE', evidence_digest: evidenceDigest,
    status_digest: statusDigest(input?.status), evidence_role: pins.config.evidence_role,
    subject: { id: pins.config.subject.id, kind: pins.config.subject.kind },
    replay_unit: evidenceDigest, reasons: [],
  };
}

function reject(result: AebNativeResult, reason: string): AebNativeResult {
  result.acceptance = 'REJECTED'; result.reasons = [reason]; return result;
}

function verifyNative(input: Omit<AebAdapterInput, 'profile'>, pins: ParsedPins): AebNativeResult {
  const result = fallbackNative(input, pins);
  if (safeDigest(input.adapter_config) !== pins.configDigest || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    return reject(result, 'oauth-txn:constructor_pin_mismatch');
  }
  if (!expectedActionShape(input.expected_action, pins.config)) {
    result.reasons = ['oauth-txn:missing_or_ambiguous_exact_action']; return result;
  }
  if (!verifiedContextMatches(input.expected_action, pins.config)) {
    return reject(result, 'oauth-txn:verified_context_mismatch');
  }
  if (!isRecord(input.artifact) || !exactKeys(input.artifact, ARTIFACT_KEYS)) {
    return reject(result, 'oauth-txn:challenge_and_access_token_required');
  }
  const challenge = verifyJwt(input.artifact.challenge_jwt, pins.challengeRoot, 'txn-authz-challenge+jwt');
  const access = verifyJwt(input.artifact.access_token_jwt, pins.accessRoot, 'at+jwt');
  if (!challenge) return reject(result, 'oauth-txn:challenge_invalid');
  if (!access) return reject(result, 'oauth-txn:access_token_invalid');
  const challengeClaims = challenge.claims; const accessClaims = access.claims;
  if (!exactKeys(challengeClaims, CHALLENGE_KEYS, new Set(['reason_uri', 'act']))
      || challengeClaims.iss !== pins.config.protected_resource
      || challengeClaims.aud !== pins.config.authorization_server
      || !Number.isSafeInteger(challengeClaims.iat) || !Number.isSafeInteger(challengeClaims.exp)
      || !nonEmptyString(challengeClaims.jti) || !nonEmptyString(challengeClaims.txn)
      || !validDetails(challengeClaims.authorization_details) || !nonEmptyString(challengeClaims.reason)
      || (challengeClaims.reason_uri !== undefined && !nonEmptyString(challengeClaims.reason_uri))
      || (challengeClaims.act !== undefined && !isRecord(challengeClaims.act))) {
    return reject(result, 'oauth-txn:challenge_claims_invalid');
  }
  const actorOptional = pins.config.require_actor_context ? new Set<string>() : new Set(['act']);
  if (!exactKeys(accessClaims, ACCESS_KEYS, actorOptional)
      || accessClaims.iss !== pins.config.authorization_server
      || accessClaims.sub !== pins.config.oauth_subject
      || accessClaims.aud !== pins.config.protected_resource
      || accessClaims.client_id !== pins.config.oauth_client_id
      || !Number.isSafeInteger(accessClaims.iat) || !Number.isSafeInteger(accessClaims.exp)
      || !nonEmptyString(accessClaims.jti) || !nonEmptyString(accessClaims.txn)
      || !validDetails(accessClaims.authorization_details)
      || (accessClaims.act !== undefined && !isRecord(accessClaims.act))) {
    return reject(result, 'oauth-txn:access_token_claims_invalid');
  }
  if (!pins.config.require_actor_context
      && (challengeClaims.act !== undefined || accessClaims.act !== undefined)) {
    return reject(result, 'oauth-txn:actor_context_requires_material_mapping');
  }
  const expectedTxn = input.expected_action.oauth_transaction as Obj;
  if (challengeClaims.txn !== accessClaims.txn || accessClaims.txn !== expectedTxn.txn) {
    return reject(result, 'oauth-txn:exact_action_mismatch');
  }
  if (pins.config.require_actor_context
      && (safeDigest(challengeClaims.act) !== safeDigest(accessClaims.act)
        || safeDigest(accessClaims.act) !== safeDigest(expectedTxn.actor))) {
    return reject(result, 'oauth-txn:actor_context_mismatch');
  }
  const nowMs = parseInstant(input.now);
  if (!Number.isFinite(nowMs)) { result.reasons = ['oauth-txn:verification_time_invalid']; return result; }
  const now = Math.floor(nowMs / 1000);
  const challengeIat = Number(challengeClaims.iat); const challengeExp = Number(challengeClaims.exp);
  const accessIat = Number(accessClaims.iat); const accessExp = Number(accessClaims.exp);
  if (challengeExp <= challengeIat
      || challengeExp - challengeIat > pins.config.max_challenge_lifetime_seconds
      || challengeIat > now + pins.config.clock_skew_seconds
      || accessIat < challengeIat || accessIat > challengeExp + pins.config.clock_skew_seconds
      || accessExp <= accessIat
      || accessExp - accessIat > pins.config.max_access_token_lifetime_seconds
      || accessIat > now + pins.config.clock_skew_seconds
      || accessExp <= now - pins.config.clock_skew_seconds) {
    return reject(result, 'oauth-txn:time_binding_invalid');
  }
  let details: { verified: boolean; reason: string | null };
  try {
    details = pins.detailsVerifier.verify({
      requested: challengeClaims.authorization_details,
      granted: accessClaims.authorization_details,
      expected: expectedTxn.authorization_details,
    });
  } catch { result.reasons = ['oauth-txn:details_verifier_error']; return result; }
  if (!details || details.verified !== true) {
    return reject(result, `oauth-txn:${nonEmptyString(details?.reason) ? details.reason : 'authorization_details_not_verified'}`);
  }
  result.replay_unit = safeDigest({
    namespace: OAUTH_TXN_CHALLENGE_REPLAY_NAMESPACE,
    protected_resource: challengeClaims.iss,
    transaction: accessClaims.txn,
  });
  result.native_verification = 'VERIFIED';
  const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
  result.acceptance = status.acceptance; result.reasons = status.reasons; return result;
}

export function createOAuthTransactionChallengeActionDefinition(actionType: string, requireActor: boolean): Obj {
  if (!ACTION_TYPE_RE.test(actionType) || typeof requireActor !== 'boolean') {
    throw new TypeError('invalid OAuth transaction action definition');
  }
  return {
    '@version': OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
    native_protocol: OAUTH_TXN_CHALLENGE_DRAFT_REVISION,
    projection: 'oauth-transaction-exact-action-v2', action_type: actionType, suite: 'jcs-sha256',
    semantic_loss_contract: {
      verified_action_fields: [
        'challenge.iss',
        'challenge.aud',
        'challenge.txn',
        'challenge.authorization_details',
        ...(requireActor ? ['challenge.act'] : []),
        'access_token.iss',
        'access_token.sub',
        'access_token.aud',
        'access_token.client_id',
        'access_token.txn',
        'access_token.authorization_details',
        ...(requireActor ? ['access_token.act'] : []),
      ],
      omitted_material_fields: [],
      omitted_nonmaterial_fields: OAUTH_TXN_CHALLENGE_SEMANTIC_OMISSION_BASIS,
    },
    definitions: [{
      action_type: actionType,
      required_fields: [{ name: 'action_type', type: 'string' }, { name: 'oauth_transaction', type: 'object' }],
      optional_fields: [],
    }],
  };
}

function validMapping(profile: AebPinnedProfile, config: OAuthTransactionChallengeAdapterConfig): boolean {
  return isRecord(profile) && profile.version === OAUTH_TXN_CHALLENGE_MAPPING_VERSION
    && profile.mapper_id === OAUTH_TXN_CHALLENGE_MAPPER_ID && isRecord(profile.resolver)
    && profile.resolver.id === OAUTH_TXN_CHALLENGE_MAPPER_ID && profile.resolver.version === '2'
    && typeof profile.resolver.implementation_digest === 'string' && DIGEST_RE.test(profile.resolver.implementation_digest)
    && isRecord(profile.semantic_equivalence)
    && profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
    && profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
    && Array.isArray(profile.semantic_equivalence.omitted_material_fields)
    && profile.semantic_equivalence.omitted_material_fields.length === 0
    && Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
    && safeDigest(profile.semantic_equivalence.omitted_nonmaterial_fields)
      === safeDigest(OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS)
    && isRecord(profile.definition) && exactKeys(profile.definition, MAPPING_KEYS)
    && safeDigest(profile.definition)
      === safeDigest(createOAuthTransactionChallengeActionDefinition(config.action_type, config.require_actor_context));
}

function mapAction(input: AebAdapterInput & { native: AebNativeResult }, pins: ParsedPins): AebMappingResult {
  if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
  }
  if (safeDigest(input.adapter_config) !== pins.configDigest || safeDigest(input.trust_roots) !== pins.rootsDigest) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
  }
  if (!validMapping(input.profile, pins.config) || !exactExpectedAction(input.expected_action, pins.config)) {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_or_action_invalid'] };
  }
  const actionDigest = safeDigest(input.expected_action);
  let computed: unknown;
  try {
    computed = computeCaid(input.expected_action, {
      suite: 'jcs-sha256', definitions: (input.profile.definition as Obj).definitions,
    });
  } catch { computed = null; }
  if (!isRecord(computed) || typeof computed.caid !== 'string'
      || computed.digest !== actionDigest || typeof computed.digest !== 'string') {
    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
  }
  return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}

export function createOAuthTransactionChallengeAebAdapter(
  constructorPins: OAuthTransactionChallengeConstructorPins,
): AebAdapter {
  const pins = parsePins(constructorPins);
  return Object.freeze({
    id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
    version: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      try { return verifyNative(input, pins); } catch {
        const result = fallbackNative(input, pins); result.reasons = ['oauth-txn:unexpected_adapter_error']; return result;
      }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try { return mapAction(input, pins); } catch {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['oauth-txn:unexpected_mapping_error'] };
      }
    },
  });
}
