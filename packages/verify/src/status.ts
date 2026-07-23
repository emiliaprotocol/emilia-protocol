// SPDX-License-Identifier: Apache-2.0
/**
 * EP-STATUS-v1 — closed, signed, current revocation-status evidence.
 *
 * A relying party pins an authority root. That root signs one closed
 * EP-REVOKER-AUTHORITY-v1 certificate delegating a scoped Ed25519 status key.
 * The delegated key signs status artifacts for exact targets. Affirmative
 * non-revocation is useful only before next_update; an effective revocation is
 * terminal and never becomes affirmative merely because it is old.
 *
 * Verification is pure, offline, fail-closed, and uses only node:crypto.
 */
import crypto from 'node:crypto';

type Obj = Record<string, any>;

export const STATUS_VERSION = 'EP-STATUS-v1';
export const STATUS_DOMAIN = `${STATUS_VERSION}\0`;
export const REVOCER_AUTHORITY_VERSION = 'EP-REVOKER-AUTHORITY-v1';
export const REVOCER_AUTHORITY_DOMAIN = `${REVOCER_AUTHORITY_VERSION}\0`;

export const STATUS_TARGET_TYPES = Object.freeze([
  'receipt',
  'commit',
  'delegation',
] as const);

export const STATUS_TARGET_USAGES = Object.freeze([
  'authorization',
  'execution',
  'delegation',
] as const);

export type StatusTargetType = typeof STATUS_TARGET_TYPES[number];
export type StatusTargetUsage = typeof STATUS_TARGET_USAGES[number];
export type StatusState = 'not_revoked' | 'revoked';
export type StatusOutcome = 'current_not_revoked' | 'revoked' | 'indeterminate';

export interface StatusTarget {
  type: StatusTargetType;
  id: string;
  digest: string;
  usage: StatusTargetUsage;
}

export interface RevokerAuthorityPin {
  authority_domain: string;
  authority_id: string;
  key_id: string;
  public_key: string;
}

export interface RevokerAuthorityOptions {
  authorityPin?: RevokerAuthorityPin;
  now?: number | string | Date;
}

export interface StatusVerificationOptions extends RevokerAuthorityOptions {
  certificate?: unknown;
  /** The relying party's previously accepted head, never presenter state. */
  previousStatus?: unknown;
}

export interface RevokerAuthorityVerification {
  valid: boolean;
  checks: {
    structure: boolean;
    authority: boolean;
    scope: boolean;
    validity: boolean;
    signature: boolean;
  };
  reasons: string[];
  certificate_digest: string | null;
}

export interface StatusVerification {
  outcome: StatusOutcome;
  valid: boolean;
  checks: {
    structure: boolean;
    certificate: boolean;
    authority: boolean;
    target: boolean;
    scope: boolean;
    signature: boolean;
    freshness: boolean;
    sequence: boolean;
    terminal: boolean;
  };
  reasons: string[];
  status_digest: string | null;
  sequence: number | null;
  next_update: string | null;
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REVOKER_KEY_ID = /^ep:revoker-key:sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,511}$/;
const AUTHORITY_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

const CERTIFICATE_KEYS = [
  '@version',
  'certificate_id',
  'authority_domain',
  'authority_id',
  'revoker_id',
  'revoker_key',
  'scope',
  'issued_at',
  'expires_at',
  'proof',
] as const;
const REVOKER_KEY_KEYS = ['algorithm', 'key_id', 'public_key'] as const;
const SCOPE_KEYS = ['allowed_target_types', 'allowed_usages'] as const;
const CERTIFICATE_PROOF_KEYS = ['algorithm', 'key_id', 'signature_b64u'] as const;
const STATUS_KEYS = [
  '@version',
  'authority_domain',
  'revoker_authority_digest',
  'target',
  'status',
  'sequence',
  'previous_status_digest',
  'issued_at',
  'next_update',
  'proof',
] as const;
const TARGET_KEYS = ['type', 'id', 'digest', 'usage'] as const;
const STATUS_PROOF_KEYS = ['algorithm', 'key_id', 'signature_b64u'] as const;

function record(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function dataProperties(value: object): boolean {
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
  });
}

function exactObject(value: unknown, required: readonly string[]): value is Obj {
  if (!record(value) || !dataProperties(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === required.length
    && required.every((key) => Object.hasOwn(value, key));
}

function densePlainArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, String(index))) return false;
  }
  return true;
}

function validUnicodeString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** RFC 8785 serialization for JSON data, rejecting non-I-JSON object graphs. */
function canonicalize(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    if (!validUnicodeString(value)) throw new TypeError('JCS input contains an invalid Unicode scalar');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('JCS input contains a non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || value === null || seen.has(value)) {
    throw new TypeError('value is outside the JCS I-JSON profile');
  }
  seen.add(value);
  if (Array.isArray(value)) {
    if (!densePlainArray(value)) throw new TypeError('JCS input contains a non-JSON array');
    return `[${value.map((member) => canonicalize(member, seen)).join(',')}]`;
  }
  if (!record(value) || !dataProperties(value)) {
    throw new TypeError('JCS input contains a non-JSON object');
  }
  return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`).join(',')}}`;
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256')
    .update(canonicalize(value), 'utf8').digest('hex')}`;
}

function safeDigest(value: unknown): string | null {
  try {
    return digest(value);
  } catch {
    return null;
  }
}

function canonicalBase64url(value: unknown, expectedBytes: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0
      || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== expectedBytes || decoded.toString('base64url') !== value) return null;
  return decoded;
}

function loadEd25519Key(value: unknown): crypto.KeyObject | null {
  try {
    const der = canonicalBase64url(value, 44);
    if (!der) return null;
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function revokerKeyId(publicKey: unknown): string | null {
  const der = canonicalBase64url(publicKey, 44);
  if (!der || !loadEd25519Key(publicKey)) return null;
  return `ep:revoker-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function unsigned(value: Obj): Obj {
  const body: Obj = {};
  for (const [key, member] of Object.entries(value)) {
    if (key !== 'proof') body[key] = member;
  }
  return body;
}

function signingBytes(value: Obj, domain: string): Buffer | null {
  try {
    return Buffer.from(`${domain}${canonicalize(unsigned(value))}`, 'utf8');
  } catch {
    return null;
  }
}

function verifyEd25519(value: Obj, domain: string, publicKey: unknown): boolean {
  const key = loadEd25519Key(publicKey);
  const signature = canonicalBase64url(value.proof?.signature_b64u, 64);
  const bytes = signingBytes(value, domain);
  if (!key || !signature || !bytes) return false;
  try {
    return crypto.verify(null, bytes, key, signature);
  } catch {
    return false;
  }
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function authorityDomain(value: unknown): value is string {
  return typeof value === 'string' && AUTHORITY_DOMAIN.test(value);
}

function strictInstantMs(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19)
      !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) return NaN;
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) return NaN;
  return Date.parse(value);
}

function decisionTimeMs(value: unknown): number {
  if (value === undefined) return Date.now();
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  return strictInstantMs(value);
}

function validProof(value: unknown): value is Obj {
  return exactObject(value, STATUS_PROOF_KEYS)
    && value.algorithm === 'Ed25519'
    && typeof value.key_id === 'string'
    && REVOKER_KEY_ID.test(value.key_id)
    && canonicalBase64url(value.signature_b64u, 64) !== null;
}

function validCertificateProof(value: unknown): value is Obj {
  return exactObject(value, CERTIFICATE_PROOF_KEYS)
    && value.algorithm === 'Ed25519'
    && identifier(value.key_id)
    && canonicalBase64url(value.signature_b64u, 64) !== null;
}

function validTarget(value: unknown): value is StatusTarget {
  return exactObject(value, TARGET_KEYS)
    && typeof value.type === 'string'
    && STATUS_TARGET_TYPES.includes(value.type as StatusTargetType)
    && identifier(value.id)
    && typeof value.digest === 'string'
    && DIGEST.test(value.digest)
    && typeof value.usage === 'string'
    && STATUS_TARGET_USAGES.includes(value.usage as StatusTargetUsage);
}

function validScopeArray<T extends string>(
  value: unknown,
  allowed: readonly T[],
): value is T[] {
  return densePlainArray(value)
    && value.length > 0
    && value.length <= allowed.length
    && value.every((member) => typeof member === 'string' && allowed.includes(member as T))
    && new Set(value).size === value.length;
}

function certificateStructure(value: unknown): value is Obj {
  if (!exactObject(value, CERTIFICATE_KEYS)
      || value['@version'] !== REVOCER_AUTHORITY_VERSION
      || !identifier(value.certificate_id)
      || !authorityDomain(value.authority_domain)
      || !identifier(value.authority_id)
      || !identifier(value.revoker_id)
      || !exactObject(value.revoker_key, REVOKER_KEY_KEYS)
      || value.revoker_key.algorithm !== 'Ed25519'
      || typeof value.revoker_key.key_id !== 'string'
      || !REVOKER_KEY_ID.test(value.revoker_key.key_id)
      || typeof value.revoker_key.public_key !== 'string'
      || !loadEd25519Key(value.revoker_key.public_key)
      || revokerKeyId(value.revoker_key.public_key) !== value.revoker_key.key_id
      || !exactObject(value.scope, SCOPE_KEYS)
      || !densePlainArray(value.scope.allowed_target_types)
      || !densePlainArray(value.scope.allowed_usages)
      || typeof value.issued_at !== 'string'
      || typeof value.expires_at !== 'string'
      || !validCertificateProof(value.proof)) return false;
  return true;
}

function certificateScope(value: Obj): boolean {
  return validScopeArray(value.scope.allowed_target_types, STATUS_TARGET_TYPES)
    && validScopeArray(value.scope.allowed_usages, STATUS_TARGET_USAGES);
}

function validAuthorityPin(value: unknown): value is RevokerAuthorityPin {
  return record(value)
    && authorityDomain(value.authority_domain)
    && identifier(value.authority_id)
    && identifier(value.key_id)
    && typeof value.public_key === 'string'
    && loadEd25519Key(value.public_key) !== null;
}

function statusStructure(value: unknown): value is Obj {
  return exactObject(value, STATUS_KEYS)
    && value['@version'] === STATUS_VERSION
    && authorityDomain(value.authority_domain)
    && typeof value.revoker_authority_digest === 'string'
    && DIGEST.test(value.revoker_authority_digest)
    && validTarget(value.target)
    && (value.status === 'not_revoked' || value.status === 'revoked')
    && Number.isSafeInteger(value.sequence)
    && value.sequence >= 0
    && (value.previous_status_digest === null
      || (typeof value.previous_status_digest === 'string'
        && DIGEST.test(value.previous_status_digest)))
    && typeof value.issued_at === 'string'
    && (value.next_update === null || typeof value.next_update === 'string')
    && validProof(value.proof);
}

function targetEqual(left: StatusTarget, right: StatusTarget): boolean {
  return left.type === right.type
    && left.id === right.id
    && left.digest === right.digest
    && left.usage === right.usage;
}

function certificateValidity(value: Obj, at: number): boolean {
  const issuedAt = strictInstantMs(value.issued_at);
  const expiresAt = strictInstantMs(value.expires_at);
  return Number.isFinite(at)
    && Number.isFinite(issuedAt)
    && Number.isFinite(expiresAt)
    && issuedAt < expiresAt
    && at >= issuedAt
    && at < expiresAt;
}

function addReason(reasons: string[], reason: string): void {
  if (!reasons.includes(reason)) reasons.push(reason);
}

function indeterminateStatus(): StatusVerification {
  return {
    outcome: 'indeterminate',
    valid: false,
    checks: {
      structure: false,
      certificate: false,
      authority: false,
      target: false,
      scope: false,
      signature: false,
      freshness: false,
      sequence: false,
      terminal: false,
    },
    reasons: [],
    status_digest: null,
    sequence: null,
    next_update: null,
  };
}

/** Digest of the exact closed, signed revoker-authority certificate envelope. */
export function revokerAuthorityCertificateDigest(certificate: unknown): string {
  return digest(certificate);
}

/** Digest of the exact closed, signed status envelope. */
export function statusArtifactDigest(status: unknown): string {
  return digest(status);
}

function verifyRevokerAuthorityCertificateCore(
  certificate: unknown,
  options: RevokerAuthorityOptions = {},
): RevokerAuthorityVerification {
  const checks = {
    structure: false,
    authority: false,
    scope: false,
    validity: false,
    signature: false,
  };
  const reasons: string[] = [];
  const certificateDigest = safeDigest(certificate);

  if (!certificateStructure(certificate)) {
    addReason(reasons, 'invalid_revoker_authority_structure');
    return { valid: false, checks, reasons, certificate_digest: certificateDigest };
  }
  checks.structure = true;

  if (!certificateScope(certificate)) {
    addReason(reasons, 'invalid_revoker_authority_scope');
  } else {
    checks.scope = true;
  }

  const pin = options.authorityPin;
  if (!validAuthorityPin(pin)
      || certificate.authority_domain !== pin.authority_domain
      || certificate.authority_id !== pin.authority_id
      || certificate.proof.key_id !== pin.key_id) {
    addReason(reasons, 'revoker_authority_pin_mismatch');
  } else {
    checks.authority = true;
  }

  const at = decisionTimeMs(options.now);
  if (!certificateValidity(certificate, at)) {
    addReason(reasons, 'revoker_authority_not_valid_at_time');
  } else {
    checks.validity = true;
  }

  if (!validAuthorityPin(pin)
      || !verifyEd25519(certificate, REVOCER_AUTHORITY_DOMAIN, pin.public_key)) {
    addReason(reasons, 'invalid_revoker_authority_signature');
  } else {
    checks.signature = true;
  }

  return {
    valid: Object.values(checks).every(Boolean),
    checks,
    reasons,
    certificate_digest: certificateDigest,
  };
}

/** Verify one root-signed, time-bounded, target-scoped status-key certificate. */
export function verifyRevokerAuthorityCertificate(
  certificate: unknown,
  options: RevokerAuthorityOptions = {},
): RevokerAuthorityVerification {
  try {
    return verifyRevokerAuthorityCertificateCore(certificate, options);
  } catch {
    return {
      valid: false,
      checks: {
        structure: false,
        authority: false,
        scope: false,
        validity: false,
        signature: false,
      },
      reasons: ['invalid_revoker_authority_input'],
      certificate_digest: null,
    };
  }
}

function previousStatusChecks(
  candidate: Obj,
  previous: unknown,
  certificate: Obj,
  checks: StatusVerification['checks'],
  reasons: string[],
): void {
  if (candidate.sequence === 0) {
    if (candidate.previous_status_digest !== null) {
      addReason(reasons, 'initial_status_has_previous_digest');
      return;
    }
    if (previous === undefined) {
      checks.sequence = true;
      checks.terminal = true;
      return;
    }
  } else if (previous === undefined) {
    addReason(reasons, 'missing_previous_status');
    checks.terminal = true;
    return;
  }

  if (!statusStructure(previous)
      || previous.authority_domain !== candidate.authority_domain
      || previous.revoker_authority_digest !== candidate.revoker_authority_digest
      || !targetEqual(previous.target, candidate.target)
      || previous.proof.key_id !== certificate.revoker_key.key_id
      || !verifyEd25519(previous, STATUS_DOMAIN, certificate.revoker_key.public_key)) {
    addReason(reasons, 'invalid_previous_status');
    return;
  }

  const previousIssuedAt = strictInstantMs(previous.issued_at);
  const previousNextUpdate = previous.next_update === null
    ? NaN : strictInstantMs(previous.next_update);
  if (!Number.isFinite(previousIssuedAt)
      || (previous.status === 'not_revoked'
        && (!Number.isFinite(previousNextUpdate) || previousNextUpdate <= previousIssuedAt))
      || (previous.status === 'revoked' && previous.next_update !== null)) {
    addReason(reasons, 'invalid_previous_status');
    return;
  }

  if (previous.status === 'revoked') {
    addReason(reasons, 'terminal_revocation');
  } else {
    checks.terminal = true;
  }

  if (candidate.sequence !== previous.sequence + 1) {
    addReason(reasons, 'sequence_not_monotonic');
  } else if (candidate.previous_status_digest !== safeDigest(previous)) {
    addReason(reasons, 'previous_status_digest_mismatch');
  } else if (strictInstantMs(candidate.issued_at) <= previousIssuedAt) {
    addReason(reasons, 'status_issued_at_not_monotonic');
  } else {
    checks.sequence = true;
  }
}

function verifyStatusArtifactCore(
  expectedTarget: unknown,
  status: unknown,
  options: StatusVerificationOptions = {},
): StatusVerification {
  const result = indeterminateStatus();
  result.status_digest = safeDigest(status);

  if (!statusStructure(status)) {
    addReason(result.reasons, 'invalid_status_structure');
    return result;
  }
  result.checks.structure = true;
  result.sequence = status.sequence;
  result.next_update = status.next_update;

  if (!validTarget(expectedTarget) || !targetEqual(expectedTarget, status.target)) {
    addReason(result.reasons, 'status_target_mismatch');
  } else {
    result.checks.target = true;
  }

  const certificateAt = strictInstantMs(status.issued_at);
  const certificateResult = verifyRevokerAuthorityCertificate(options.certificate, {
    authorityPin: options.authorityPin,
    now: certificateAt,
  });
  if (!certificateResult.valid || !certificateStructure(options.certificate)) {
    addReason(result.reasons, 'invalid_revoker_authority_certificate');
    for (const reason of certificateResult.reasons) addReason(result.reasons, reason);
    return result;
  }
  const certificate = options.certificate;
  result.checks.certificate = true;

  if (status.authority_domain !== certificate.authority_domain
      || !validAuthorityPin(options.authorityPin)
      || status.authority_domain !== options.authorityPin.authority_domain) {
    addReason(result.reasons, 'status_authority_domain_mismatch');
  } else {
    result.checks.authority = true;
  }

  if (!certificate.scope.allowed_target_types.includes(status.target.type)
      || !certificate.scope.allowed_usages.includes(status.target.usage)) {
    addReason(result.reasons, 'status_target_outside_revoker_scope');
  } else {
    result.checks.scope = true;
  }

  if (status.revoker_authority_digest !== certificateResult.certificate_digest) {
    addReason(result.reasons, 'revoker_authority_digest_mismatch');
    result.checks.certificate = false;
  }

  if (status.proof.key_id !== certificate.revoker_key.key_id
      || !verifyEd25519(status, STATUS_DOMAIN, certificate.revoker_key.public_key)) {
    addReason(result.reasons, 'invalid_status_signature');
  } else {
    result.checks.signature = true;
  }

  const now = decisionTimeMs(options.now);
  const issuedAt = strictInstantMs(status.issued_at);
  const certificateExpiresAt = strictInstantMs(certificate.expires_at);
  if (!Number.isFinite(now) || !Number.isFinite(issuedAt)) {
    addReason(result.reasons, 'invalid_status_time');
  } else if (issuedAt > now) {
    addReason(result.reasons, 'status_not_yet_valid');
  } else if (status.status === 'revoked') {
    if (status.next_update !== null) {
      addReason(result.reasons, 'revoked_status_has_next_update');
    } else {
      result.checks.freshness = true;
    }
  } else {
    const nextUpdate = strictInstantMs(status.next_update);
    if (!Number.isFinite(nextUpdate) || nextUpdate <= issuedAt) {
      addReason(result.reasons, 'invalid_status_window');
    } else if (nextUpdate > certificateExpiresAt) {
      addReason(result.reasons, 'status_window_exceeds_certificate');
    } else if (now >= nextUpdate) {
      addReason(result.reasons, 'status_stale');
    } else {
      result.checks.freshness = true;
    }
  }

  previousStatusChecks(
    status,
    options.previousStatus,
    certificate,
    result.checks,
    result.reasons,
  );

  const valid = Object.values(result.checks).every(Boolean);
  if (!valid) return result;
  result.valid = true;
  result.outcome = status.status === 'revoked' ? 'revoked' : 'current_not_revoked';
  return result;
}

/**
 * Verify current status for one exact target.
 *
 * Sequence > 0 requires the relying party's previously accepted status head.
 * This prevents a presenter from rolling the verifier back to an older signed
 * non-revocation artifact or severing the signed predecessor digest chain.
 */
export function verifyStatusArtifact(
  expectedTarget: unknown,
  status: unknown,
  options: StatusVerificationOptions = {},
): StatusVerification {
  try {
    return verifyStatusArtifactCore(expectedTarget, status, options);
  } catch {
    const result = indeterminateStatus();
    result.status_digest = safeDigest(status);
    addReason(result.reasons, 'invalid_status_input');
    return result;
  }
}
