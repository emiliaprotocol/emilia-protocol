// SPDX-License-Identifier: Apache-2.0
/**
 * Issuer-side builders for the closed EP-REVOKER-AUTHORITY-v1 and
 * EP-STATUS-v1 artifacts verified by packages/verify/src/status.ts.
 *
 * Private key material is intentionally outside this API. Callers inject an
 * async Ed25519 signer backed by their KMS/HSM (or by a test-only closure), and
 * the builders pass it only the exact domain-separated JCS signing bytes.
 */
import crypto from 'node:crypto';

import {
  REVOCER_AUTHORITY_DOMAIN,
  REVOCER_AUTHORITY_VERSION,
  STATUS_DOMAIN,
  STATUS_TARGET_TYPES,
  STATUS_TARGET_USAGES,
  STATUS_VERSION,
  revokerAuthorityCertificateDigest,
  statusArtifactDigest,
  verifyRevokerAuthorityCertificate,
  verifyStatusArtifact,
  type RevokerAuthorityPin,
  type StatusState,
  type StatusTarget,
  type StatusTargetType,
  type StatusTargetUsage,
} from '../../packages/verify/status.js';

type Obj = Record<string, unknown>;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REVOKER_KEY_ID = /^ep:revoker-key:sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,511}$/;
const AUTHORITY_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const RAW_KEY_FIELD = /(?:private[_-]?key|privatekey|pkcs8|secret|seed)/i;

const AUTHORITY_INPUT_KEYS = [
  'certificateId',
  'authorityPin',
  'revokerId',
  'revokerPublicKey',
  'scope',
  'issuedAt',
  'expiresAt',
  'signer',
] as const;
const STATUS_INPUT_KEYS = [
  'authorityPin',
  'certificate',
  'target',
  'status',
  'issuedAt',
  'nextUpdate',
  'previousStatus',
  'signer',
] as const;
const AUTHORITY_PIN_KEYS = ['authority_domain', 'authority_id', 'key_id', 'public_key'] as const;
const SCOPE_KEYS = ['allowed_target_types', 'allowed_usages'] as const;
const TARGET_KEYS = ['type', 'id', 'digest', 'usage'] as const;
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
const STATUS_PROOF_KEYS = ['algorithm', 'key_id', 'signature_b64u'] as const;

export interface StatusSignerContext {
  readonly artifact: 'revoker_authority_certificate' | 'status';
  readonly domain: typeof REVOCER_AUTHORITY_DOMAIN | typeof STATUS_DOMAIN;
  readonly keyId: string;
}

/** Minimal KMS/HSM seam. It deliberately has no private-key property. */
export interface ExternalEd25519Signer {
  readonly algorithm: 'Ed25519';
  readonly keyId: string;
  sign(
    bytes: Uint8Array,
    context: Readonly<StatusSignerContext>,
  ): Promise<string | Uint8Array>;
}

export interface RevokerAuthorityScope {
  readonly allowed_target_types: readonly StatusTargetType[];
  readonly allowed_usages: readonly StatusTargetUsage[];
}

export interface RevokerAuthorityCertificate {
  readonly '@version': typeof REVOCER_AUTHORITY_VERSION;
  readonly certificate_id: string;
  readonly authority_domain: string;
  readonly authority_id: string;
  readonly revoker_id: string;
  readonly revoker_key: Readonly<{
    algorithm: 'Ed25519';
    key_id: string;
    public_key: string;
  }>;
  readonly scope: Readonly<{
    allowed_target_types: readonly StatusTargetType[];
    allowed_usages: readonly StatusTargetUsage[];
  }>;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly proof: Readonly<{
    algorithm: 'Ed25519';
    key_id: string;
    signature_b64u: string;
  }>;
}

export interface StatusArtifact {
  readonly '@version': typeof STATUS_VERSION;
  readonly authority_domain: string;
  readonly revoker_authority_digest: string;
  readonly target: Readonly<StatusTarget>;
  readonly status: StatusState;
  readonly sequence: number;
  readonly previous_status_digest: string | null;
  readonly issued_at: string;
  readonly next_update: string | null;
  readonly proof: Readonly<{
    algorithm: 'Ed25519';
    key_id: string;
    signature_b64u: string;
  }>;
}

export interface BuildRevokerAuthorityCertificateInput {
  readonly certificateId: string;
  readonly authorityPin: RevokerAuthorityPin;
  readonly revokerId: string;
  readonly revokerPublicKey: string;
  readonly scope: RevokerAuthorityScope;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly signer: ExternalEd25519Signer;
}

export interface BuildStatusArtifactInput {
  readonly authorityPin: RevokerAuthorityPin;
  readonly certificate: unknown;
  readonly target: StatusTarget;
  readonly status: StatusState;
  readonly issuedAt: string;
  readonly nextUpdate: string | null;
  /** The issuer's authoritative current head, not presenter-selected state. */
  readonly previousStatus?: unknown;
  readonly signer: ExternalEd25519Signer;
}

export class StatusIssuanceError extends Error {
  readonly code: string;

  constructor(code: string, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'StatusIssuanceError';
    this.code = code;
  }
}

function fail(code: string, message: string, cause?: unknown): never {
  throw new StatusIssuanceError(code, message, cause);
}

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

function closedObject(
  value: unknown,
  label: string,
  allowed: readonly string[],
  required: readonly string[] = allowed,
): asserts value is Obj {
  if (!record(value) || !dataProperties(value)) {
    fail('unsafe_input', `${label} must be a plain data object`);
  }
  const keys = Reflect.ownKeys(value) as string[];
  const unknown = keys.filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    fail('unknown_input', `${label} contains unknown field(s): ${unknown.join(', ')}`);
  }
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) {
    fail('missing_input', `${label} is missing required field(s): ${missing.join(', ')}`);
  }
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

/** RFC 8785 serialization, byte-identical to the status verifier. */
function canonicalize(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    if (!validUnicodeString(value)) fail('unsafe_input', 'JCS input contains invalid Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('unsafe_input', 'JCS input contains a non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object' || value === null || seen.has(value)) {
    fail('unsafe_input', 'value is outside the JCS I-JSON profile');
  }
  seen.add(value);
  if (Array.isArray(value)) {
    if (!densePlainArray(value)) fail('unsafe_input', 'JCS input contains an unsafe array');
    return `[${value.map((member) => canonicalize(member, seen)).join(',')}]`;
  }
  if (!record(value) || !dataProperties(value)) {
    fail('unsafe_input', 'JCS input contains an unsafe object');
  }
  return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`).join(',')}}`;
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

/** Derive the complete, non-truncated EP status-key identifier from SPKI DER. */
export function deriveRevokerKeyId(publicKeyB64u: string): string {
  const der = canonicalBase64url(publicKeyB64u, 44);
  if (!der || !loadEd25519Key(publicKeyB64u)) {
    fail('invalid_revoker_public_key', 'revoker public key must be canonical base64url Ed25519 SPKI DER');
  }
  return `ep:revoker-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
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

function instant(value: unknown, label: string): number {
  const parsed = strictInstantMs(value);
  if (!Number.isFinite(parsed)) {
    fail('invalid_time', `${label} must be a strict RFC 3339 instant`);
  }
  return parsed;
}

function identifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    fail('invalid_identifier', `${label} must be a safe identifier`);
  }
}

function validateAuthorityPin(value: unknown): asserts value is RevokerAuthorityPin {
  closedObject(value, 'authorityPin', AUTHORITY_PIN_KEYS);
  if (typeof value.authority_domain !== 'string' || !AUTHORITY_DOMAIN.test(value.authority_domain)) {
    fail('invalid_authority_pin', 'authorityPin.authority_domain is invalid');
  }
  identifier(value.authority_id, 'authorityPin.authority_id');
  identifier(value.key_id, 'authorityPin.key_id');
  if (typeof value.public_key !== 'string' || !loadEd25519Key(value.public_key)) {
    fail('invalid_authority_pin', 'authorityPin.public_key must be canonical base64url Ed25519 SPKI DER');
  }
}

function validateScope(value: unknown): asserts value is {
  allowed_target_types: StatusTargetType[];
  allowed_usages: StatusTargetUsage[];
} {
  closedObject(value, 'scope', SCOPE_KEYS);
  const validateMembers = <T extends string>(
    members: unknown,
    allowed: readonly T[],
    label: string,
  ): members is T[] => {
    if (!densePlainArray(members) || members.length === 0 || members.length > allowed.length
        || !members.every((member) => typeof member === 'string' && allowed.includes(member as T))
        || new Set(members).size !== members.length) {
      fail('invalid_scope', `${label} must be a non-empty unique subset of the supported values`);
    }
    return true;
  };
  validateMembers(value.allowed_target_types, STATUS_TARGET_TYPES, 'scope.allowed_target_types');
  validateMembers(value.allowed_usages, STATUS_TARGET_USAGES, 'scope.allowed_usages');
}

function validateTarget(value: unknown): asserts value is StatusTarget {
  closedObject(value, 'target', TARGET_KEYS);
  if (typeof value.type !== 'string' || !STATUS_TARGET_TYPES.includes(value.type as StatusTargetType)) {
    fail('invalid_target', 'target.type is unsupported');
  }
  identifier(value.id, 'target.id');
  if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)) {
    fail('invalid_target', 'target.digest must be a lowercase sha256 digest');
  }
  if (typeof value.usage !== 'string' || !STATUS_TARGET_USAGES.includes(value.usage as StatusTargetUsage)) {
    fail('invalid_target', 'target.usage is unsupported');
  }
}

function validateSigner(value: unknown, expectedKeyId: string): asserts value is ExternalEd25519Signer {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    fail('invalid_signer', 'an external Ed25519 signer is required');
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === 'string' && RAW_KEY_FIELD.test(key)) {
      fail('raw_private_key_refused', 'external signer input must not contain private key material');
    }
  }
  const signer = value as Partial<ExternalEd25519Signer>;
  if (signer.algorithm !== 'Ed25519') {
    fail('invalid_signer', 'external signer algorithm must be Ed25519');
  }
  if (typeof signer.keyId !== 'string' || signer.keyId !== expectedKeyId) {
    fail('signer_key_id_mismatch', 'external signer key ID does not match the exact expected key ID');
  }
  if (typeof signer.sign !== 'function') {
    fail('invalid_signer', 'external signer requires async sign(bytes, context)');
  }
}

function signingBytes(value: Obj, domain: string): Buffer {
  return Buffer.from(`${domain}${canonicalize(value)}`, 'utf8');
}

async function signatureFrom(
  signer: ExternalEd25519Signer,
  body: Obj,
  context: StatusSignerContext,
): Promise<string> {
  const bytes = signingBytes(body, context.domain);
  let output: string | Uint8Array;
  try {
    output = await signer.sign(new Uint8Array(bytes), Object.freeze({ ...context }));
  } catch (cause) {
    const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
    fail('signer_failure', `external signer failed${detail}`, cause);
  }

  if (typeof output === 'string') {
    if (!canonicalBase64url(output, 64)) {
      fail('invalid_signature', 'external signer returned a non-canonical Ed25519 signature');
    }
    return output;
  }
  if (!(output instanceof Uint8Array) || output.byteLength !== 64) {
    fail('invalid_signature', 'external signer must return 64 signature bytes or canonical base64url');
  }
  return Buffer.from(output).toString('base64url');
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const member of Object.values(value as Obj)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function targetEqual(left: StatusTarget, right: StatusTarget): boolean {
  return left.type === right.type
    && left.id === right.id
    && left.digest === right.digest
    && left.usage === right.usage;
}

function certificateForStatus(
  certificate: unknown,
  authorityPin: RevokerAuthorityPin,
  issuedAt: string,
): RevokerAuthorityCertificate {
  const result = verifyRevokerAuthorityCertificate(certificate, {
    authorityPin,
    now: issuedAt,
  });
  if (!result.valid) {
    fail(
      'invalid_revoker_authority_certificate',
      `revoker authority certificate is invalid at status issuance time: ${result.reasons.join(', ')}`,
    );
  }
  return certificate as RevokerAuthorityCertificate;
}

function validatePreviousStatus(
  value: unknown,
  target: StatusTarget,
  certificate: RevokerAuthorityCertificate,
  certificateDigest: string,
  issuedAtMs: number,
): asserts value is StatusArtifact {
  closedObject(value, 'previousStatus', STATUS_KEYS);
  if (value['@version'] !== STATUS_VERSION
      || value.authority_domain !== certificate.authority_domain
      || value.revoker_authority_digest !== certificateDigest) {
    fail('invalid_previous_status', 'previousStatus is not bound to the same authority certificate');
  }
  validateTarget(value.target);
  if (!targetEqual(value.target, target)) {
    fail('invalid_previous_status', 'previousStatus is not bound to the exact target');
  }
  if (value.status !== 'not_revoked' && value.status !== 'revoked') {
    fail('invalid_previous_status', 'previousStatus.status is invalid');
  }
  if (!Number.isSafeInteger(value.sequence) || (value.sequence as number) < 0) {
    fail('invalid_previous_status', 'previousStatus.sequence is invalid');
  }
  if (value.previous_status_digest !== null
      && (typeof value.previous_status_digest !== 'string' || !DIGEST.test(value.previous_status_digest))) {
    fail('invalid_previous_status', 'previousStatus.previous_status_digest is invalid');
  }
  const previousIssuedAtMs = instant(value.issued_at, 'previousStatus.issued_at');
  if (issuedAtMs <= previousIssuedAtMs) {
    fail('non_monotonic_status_time', 'issuedAt must be later than previousStatus.issued_at');
  }
  if (value.status === 'revoked') {
    if (value.next_update !== null) {
      fail('invalid_previous_status', 'a revoked previousStatus must have next_update null');
    }
    fail('terminal_revocation', 'cannot issue a successor after a terminal revocation');
  }
  const previousNextUpdateMs = instant(value.next_update, 'previousStatus.next_update');
  if (previousNextUpdateMs <= previousIssuedAtMs) {
    fail('invalid_previous_status', 'previousStatus has an invalid status window');
  }
  closedObject(value.proof, 'previousStatus.proof', STATUS_PROOF_KEYS);
  if (value.proof.algorithm !== 'Ed25519'
      || value.proof.key_id !== certificate.revoker_key.key_id
      || typeof value.proof.signature_b64u !== 'string'
      || !canonicalBase64url(value.proof.signature_b64u, 64)) {
    fail('invalid_previous_status', 'previousStatus proof is invalid');
  }
  const unsignedPrevious: Obj = {};
  for (const [key, member] of Object.entries(value)) {
    if (key !== 'proof') unsignedPrevious[key] = member;
  }
  const previousKey = loadEd25519Key(certificate.revoker_key.public_key);
  const signature = canonicalBase64url(value.proof.signature_b64u, 64);
  if (!previousKey || !signature || !crypto.verify(
    null,
    signingBytes(unsignedPrevious, STATUS_DOMAIN),
    previousKey,
    signature,
  )) {
    fail('invalid_previous_status', 'previousStatus signature is invalid');
  }
}

/** Build and externally sign one closed EP-REVOKER-AUTHORITY-v1 certificate. */
export async function buildRevokerAuthorityCertificate(
  input: BuildRevokerAuthorityCertificateInput,
): Promise<RevokerAuthorityCertificate> {
  closedObject(input, 'certificate input', AUTHORITY_INPUT_KEYS);
  validateAuthorityPin(input.authorityPin);
  identifier(input.certificateId, 'certificateId');
  identifier(input.revokerId, 'revokerId');
  validateScope(input.scope);
  const issuedAtMs = instant(input.issuedAt, 'issuedAt');
  const expiresAtMs = instant(input.expiresAt, 'expiresAt');
  if (issuedAtMs >= expiresAtMs) {
    fail('invalid_certificate_window', 'expiresAt must be later than issuedAt');
  }
  const revokerKeyId = deriveRevokerKeyId(input.revokerPublicKey);
  validateSigner(input.signer, input.authorityPin.key_id);

  const body: Obj = {
    '@version': REVOCER_AUTHORITY_VERSION,
    certificate_id: input.certificateId,
    authority_domain: input.authorityPin.authority_domain,
    authority_id: input.authorityPin.authority_id,
    revoker_id: input.revokerId,
    revoker_key: {
      algorithm: 'Ed25519',
      key_id: revokerKeyId,
      public_key: input.revokerPublicKey,
    },
    scope: {
      allowed_target_types: [...input.scope.allowed_target_types],
      allowed_usages: [...input.scope.allowed_usages],
    },
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
  };
  const signature = await signatureFrom(input.signer, body, {
    artifact: 'revoker_authority_certificate',
    domain: REVOCER_AUTHORITY_DOMAIN,
    keyId: input.authorityPin.key_id,
  });
  const artifact = deepFreeze({
    ...body,
    proof: {
      algorithm: 'Ed25519' as const,
      key_id: input.authorityPin.key_id,
      signature_b64u: signature,
    },
  }) as unknown as RevokerAuthorityCertificate;

  const verification = verifyRevokerAuthorityCertificate(artifact, {
    authorityPin: input.authorityPin,
    now: input.issuedAt,
  });
  if (!verification.valid) {
    fail(
      'certificate_round_trip_failed',
      `issued revoker authority certificate failed verification: ${verification.reasons.join(', ')}`,
    );
  }
  return artifact;
}

/** Build and externally sign one closed, predecessor-bound EP-STATUS-v1 head. */
export async function buildStatusArtifact(
  input: BuildStatusArtifactInput,
): Promise<StatusArtifact> {
  closedObject(
    input,
    'status input',
    STATUS_INPUT_KEYS,
    STATUS_INPUT_KEYS.filter((key) => key !== 'previousStatus'),
  );
  validateAuthorityPin(input.authorityPin);
  validateTarget(input.target);
  if (input.status !== 'not_revoked' && input.status !== 'revoked') {
    fail('invalid_status', 'status must be not_revoked or revoked');
  }
  const issuedAtMs = instant(input.issuedAt, 'issuedAt');
  const certificate = certificateForStatus(input.certificate, input.authorityPin, input.issuedAt);
  const certificateDigest = revokerAuthorityCertificateDigest(certificate);
  if (!certificate.scope.allowed_target_types.includes(input.target.type)
      || !certificate.scope.allowed_usages.includes(input.target.usage)) {
    fail('target_outside_scope', 'target is outside the revoker authority certificate scope');
  }

  if (input.status === 'revoked') {
    if (input.nextUpdate !== null) {
      fail('invalid_status_window', 'terminal revoked status requires nextUpdate null');
    }
  } else {
    const nextUpdateMs = instant(input.nextUpdate, 'nextUpdate');
    if (nextUpdateMs <= issuedAtMs) {
      fail('invalid_status_window', 'nextUpdate must be later than issuedAt');
    }
    const certificateExpiresAtMs = instant(certificate.expires_at, 'certificate.expires_at');
    if (nextUpdateMs > certificateExpiresAtMs) {
      fail('invalid_status_window', 'status window exceeds the revoker authority certificate');
    }
  }

  let sequence = 0;
  let previousStatusDigest: string | null = null;
  if (Object.hasOwn(input, 'previousStatus')) {
    validatePreviousStatus(
      input.previousStatus,
      input.target,
      certificate,
      certificateDigest,
      issuedAtMs,
    );
    if (input.previousStatus.sequence >= Number.MAX_SAFE_INTEGER) {
      fail('sequence_exhausted', 'previousStatus.sequence cannot be incremented safely');
    }
    sequence = input.previousStatus.sequence + 1;
    previousStatusDigest = statusArtifactDigest(input.previousStatus);
  }

  validateSigner(input.signer, certificate.revoker_key.key_id);
  if (!REVOKER_KEY_ID.test(input.signer.keyId)) {
    fail('invalid_signer', 'status signer key ID must be a complete revoker-key digest ID');
  }

  const body: Obj = {
    '@version': STATUS_VERSION,
    authority_domain: certificate.authority_domain,
    revoker_authority_digest: certificateDigest,
    target: {
      type: input.target.type,
      id: input.target.id,
      digest: input.target.digest,
      usage: input.target.usage,
    },
    status: input.status,
    sequence,
    previous_status_digest: previousStatusDigest,
    issued_at: input.issuedAt,
    next_update: input.nextUpdate,
  };
  const signature = await signatureFrom(input.signer, body, {
    artifact: 'status',
    domain: STATUS_DOMAIN,
    keyId: certificate.revoker_key.key_id,
  });
  const artifact = deepFreeze({
    ...body,
    proof: {
      algorithm: 'Ed25519' as const,
      key_id: certificate.revoker_key.key_id,
      signature_b64u: signature,
    },
  }) as unknown as StatusArtifact;

  const verification = verifyStatusArtifact(input.target, artifact, {
    authorityPin: input.authorityPin,
    certificate,
    previousStatus: input.previousStatus,
    now: input.issuedAt,
  });
  const expectedOutcome = input.status === 'revoked' ? 'revoked' : 'current_not_revoked';
  if (!verification.valid || verification.outcome !== expectedOutcome) {
    fail(
      'status_round_trip_failed',
      `issued status artifact failed verification: ${verification.reasons.join(', ')}`,
    );
  }
  return artifact;
}
