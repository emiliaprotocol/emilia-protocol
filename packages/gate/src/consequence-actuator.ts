// SPDX-License-Identifier: Apache-2.0

/**
 * Complete-mediation boundary for provider effects.
 *
 * Gate presents a short-lived signed execution envelope. The actuator verifies
 * every binding under immutable local pins, atomically reserves the envelope,
 * and only then enters a provider callback that owns its credential. Provider
 * credentials are deliberately absent from every public type in this module.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSignature,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';

export const CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION =
  'EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1';
export const CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM = 'Ed25519';
export const CONSEQUENCE_ACTUATOR_SIGNATURE_DOMAIN =
  'EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1';
export const DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS = 60_000;
export const DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS = 2_000;
export const CONSEQUENCE_ACTUATOR_STORE_TABLE =
  'public.consequence_actuator_envelopes';
export const CONSEQUENCE_ACTUATOR_EXECUTOR_ROLE =
  'consequence_actuator_executor';
export const CONSEQUENCE_ACTUATOR_STORE_OWNER_ROLE =
  'consequence_actuator_store_owner';
export const CONSEQUENCE_ACTUATOR_SQL = deepFreeze({
  reserve: `SELECT envelope_digest
FROM consequence_actuator_private.reserve_envelope(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
  $7::text, $8::text, $9::text, $10::timestamptz, $11::timestamptz,
  $12::text
)`,
  consume: `SELECT envelope_digest
FROM consequence_actuator_private.consume_envelope(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
  $7::text, $8::text, $9::text, $10::text, $11::text
)`,
});

const MAX_CONFIGURED_TTL_MS = 5 * 60_000;
const MAX_CLOCK_SKEW_MS = 30_000;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CAID_PATTERN =
  /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ENVELOPE_KEYS = ['payload', 'signature'] as const;
const PAYLOAD_KEYS = [
  '@version',
  'issuer_id',
  'tenant_id',
  'attempt_id',
  'action_digest',
  'caid',
  'provider_account_id',
  'target_digest',
  'operation',
  'idempotency_key',
  'nonce',
  'issued_at',
  'expires_at',
] as const;
const SIGNATURE_KEYS = ['algorithm', 'key_id', 'value'] as const;

type KeyMaterial = KeyObject | string | Buffer;

export interface ConsequenceExecutionEnvelopePayload {
  '@version': typeof CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION;
  issuer_id: string;
  tenant_id: string;
  attempt_id: string;
  action_digest: string;
  caid: string;
  provider_account_id: string;
  target_digest: string;
  operation: string;
  idempotency_key: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface ConsequenceExecutionEnvelopeSignature {
  algorithm: typeof CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM;
  key_id: string;
  value: string;
}

export interface SignedConsequenceExecutionEnvelope {
  payload: ConsequenceExecutionEnvelopePayload;
  signature: ConsequenceExecutionEnvelopeSignature;
}

export interface ConsequenceActuatorPins {
  tenantId: string;
  caid: string;
  providerAccountId: string;
  targetDigest: string;
  operation: string;
  envelopeIssuerId: string;
  envelopeKeyId: string;
  envelopePublicKey: KeyMaterial;
  maxEnvelopeTtlMs?: number;
  clockSkewMs?: number;
}

export interface VisibleConsequenceActuatorPins {
  readonly tenantId: string;
  readonly caid: string;
  readonly providerAccountId: string;
  readonly targetDigest: string;
  readonly operation: string;
  readonly envelopeIssuerId: string;
  readonly envelopeKeyId: string;
  readonly envelopePublicKeyFingerprint: string;
  readonly maxEnvelopeTtlMs: number;
  readonly clockSkewMs: number;
}

export interface ConsequenceActuatorReservation {
  readonly tenantId: string;
  readonly attemptId: string;
  readonly actionDigest: string;
  readonly caid: string;
  readonly providerAccountId: string;
  readonly targetDigest: string;
  readonly operation: string;
  readonly idempotencyKey: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly envelopeDigest: string;
}

export type ConsequenceActuatorOutcome = 'COMMITTED' | 'INDETERMINATE';

export interface ConsequenceActuatorConsumption
  extends ConsequenceActuatorReservation {
  readonly outcome: ConsequenceActuatorOutcome;
}

export interface ConsequenceActuatorStore {
  /** Explicit marker for the built-in non-production test store. */
  readonly testOnly?: true;
  readonly durable: boolean;
  readonly atomic: boolean;
  readonly ownershipFenced: boolean;
  readonly permanentConsumption: boolean;
  reserve(reservation: ConsequenceActuatorReservation): Promise<boolean>;
  consume(consumption: ConsequenceActuatorConsumption): Promise<boolean>;
}

export interface ConsequenceActuatorPgQueryResult {
  readonly rowCount: number | null;
  readonly rows: readonly unknown[];
}

/**
 * A dedicated pool wrapper must label the login principal configured in its
 * connection string. PostgreSQL independently enforces that SESSION_USER is a
 * tenant-mapped member of consequence_actuator_executor.
 */
export interface DedicatedConsequenceActuatorExecutorPool {
  readonly principal: string;
  query(
    text: string,
    values: readonly unknown[],
  ): Promise<ConsequenceActuatorPgQueryResult>;
}

export interface PostgresConsequenceActuatorStoreOptions {
  readonly tenantId: string;
  readonly executorPrincipal: string;
  readonly executorPool: DedicatedConsequenceActuatorExecutorPool;
}

export interface ConsequenceActuatorExecutionInput {
  envelope: unknown;
  attemptId: string;
  actionDigest: string;
  idempotencyKey: string;
}

export type ConsequenceActuatorRefusalReason =
  | 'malformed_envelope'
  | 'unsupported_version'
  | 'signer_key_mismatch'
  | 'issuer_mismatch'
  | 'tenant_mismatch'
  | 'caid_mismatch'
  | 'provider_account_mismatch'
  | 'target_mismatch'
  | 'operation_mismatch'
  | 'attempt_mismatch'
  | 'action_digest_mismatch'
  | 'idempotency_key_mismatch'
  | 'envelope_not_yet_valid'
  | 'envelope_expired'
  | 'envelope_ttl_exceeded'
  | 'signature_invalid'
  | 'store_reserve_failed'
  | 'envelope_replayed'
  | 'provider_outcome_indeterminate'
  | 'store_consume_unconfirmed';

export type ConsequenceActuatorExecutionResult<TResult> =
  | {
      readonly ok: true;
      readonly invoked: true;
      readonly result: TResult;
      readonly envelopeDigest: string;
    }
  | {
      readonly ok: false;
      readonly invoked: boolean;
      readonly reason: ConsequenceActuatorRefusalReason;
      readonly envelopeDigest?: string;
    };

export type ConsequenceEnvelopeVerification =
  | {
      readonly ok: true;
      readonly payload: Readonly<ConsequenceExecutionEnvelopePayload>;
      readonly envelopeDigest: string;
    }
  | {
      readonly ok: false;
      readonly reason: Exclude<
        ConsequenceActuatorRefusalReason,
        | 'store_reserve_failed'
        | 'envelope_replayed'
        | 'provider_outcome_indeterminate'
        | 'store_consume_unconfirmed'
      >;
    };

interface NormalizedPins {
  visible: VisibleConsequenceActuatorPins;
  verificationKey: KeyObject;
}

interface VerifyExpectedBinding {
  attemptId: string;
  actionDigest: string;
  idempotencyKey: string;
}

interface VerifyOptions {
  pins: ConsequenceActuatorPins;
  expected: VerifyExpectedBinding;
  now?: number | (() => number);
}

interface ConsequenceActuatorOptions<TResult> {
  pins: ConsequenceActuatorPins;
  store: ConsequenceActuatorStore;
  readonly testOnly?: true;
  perform: (
    binding: Readonly<ConsequenceExecutionEnvelopePayload>,
  ) => TResult | Promise<TResult>;
  now?: number | (() => number);
}

interface SignEnvelopeOptions {
  privateKey: KeyMaterial;
  keyId: string;
}

export interface MemoryConsequenceActuatorSnapshot
  extends ConsequenceActuatorReservation {
  readonly state: 'RESERVED' | 'CONSUMED';
  readonly outcome: ConsequenceActuatorOutcome | null;
  readonly reservedAt: string;
  readonly consumedAt: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && keys.every((key) => typeof key === 'string' && expected.includes(key));
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value;
  const stack: object[] = [value];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === 'object') stack.push(child);
    }
    Object.freeze(current);
  }
  return value;
}

function canonicalClone(value: unknown): {
  canonical: string;
  value: unknown;
} {
  const canonical = canonicalize(value);
  return {
    canonical,
    value: deepFreeze(JSON.parse(canonical)),
  };
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string'
    && IDENTIFIER_PATTERN.test(value)
    && Buffer.byteLength(value, 'utf8') <= 256;
}

function validDigest(value: unknown): value is string {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function canonicalInstant(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) return null;
  return new Date(milliseconds).toISOString() === value ? milliseconds : null;
}

function decodeCanonicalBase64Url(
  value: unknown,
  minimumBytes: number,
  maximumBytes: number,
): Buffer | null {
  if (typeof value !== 'string' || !BASE64URL_PATTERN.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  if (
    bytes.length < minimumBytes
    || bytes.length > maximumBytes
    || bytes.toString('base64url') !== value
  ) {
    return null;
  }
  return bytes;
}

function nowMilliseconds(now: number | (() => number) | undefined): number {
  const value = typeof now === 'function' ? now() : (now ?? Date.now());
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(
      'consequence actuator clock must return a non-negative safe integer',
    );
  }
  return value;
}

function normalizePrivateKey(value: KeyMaterial): KeyObject {
  const key =
    typeof value === 'object' && value !== null && 'type' in value
      ? value as KeyObject
      : createPrivateKey(value);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('execution envelopes require an Ed25519 private key');
  }
  return key;
}

function isKeyObject(value: KeyMaterial): value is KeyObject {
  return typeof value === 'object'
    && value !== null
    && 'type' in value
    && ['private', 'public', 'secret'].includes((value as KeyObject).type);
}

function normalizePublicKey(value: KeyMaterial): KeyObject {
  let imported: KeyObject;
  if (isKeyObject(value)) {
    if (value.type !== 'public') {
      throw new TypeError(
        'the actuator must receive a public verification key',
      );
    }
    imported = value;
  } else {
    imported = createPublicKey(value);
  }
  if (
    imported.type !== 'public'
    || imported.asymmetricKeyType !== 'ed25519'
  ) {
    throw new TypeError('the actuator verification pin must be Ed25519');
  }
  const der = imported.export({ type: 'spki', format: 'der' });
  return createPublicKey({ key: Buffer.from(der), type: 'spki', format: 'der' });
}

function publicKeyFingerprint(key: KeyObject): string {
  const der = key.export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

function signatureInput(canonicalPayload: string): Buffer {
  return Buffer.concat([
    Buffer.from(CONSEQUENCE_ACTUATOR_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalPayload, 'utf8'),
  ]);
}

function validatePayloadShape(
  value: unknown,
): value is ConsequenceExecutionEnvelopePayload {
  if (!isRecord(value) || !exactKeys(value, PAYLOAD_KEYS)) return false;
  const issuedAt = canonicalInstant(value.issued_at);
  const expiresAt = canonicalInstant(value.expires_at);
  return value['@version'] === CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION
    && validIdentifier(value.issuer_id)
    && validIdentifier(value.tenant_id)
    && validIdentifier(value.attempt_id)
    && validDigest(value.action_digest)
    && typeof value.caid === 'string'
    && CAID_PATTERN.test(value.caid)
    && validIdentifier(value.provider_account_id)
    && validDigest(value.target_digest)
    && validIdentifier(value.operation)
    && validIdentifier(value.idempotency_key)
    && decodeCanonicalBase64Url(value.nonce, 16, 64) !== null
    && issuedAt !== null
    && expiresAt !== null
    && expiresAt > issuedAt;
}

function normalizePins(pins: ConsequenceActuatorPins): NormalizedPins {
  if (!isRecord(pins)) {
    throw new TypeError('consequence actuator pins are required');
  }
  if (
    !validIdentifier(pins.tenantId)
    || typeof pins.caid !== 'string'
    || !CAID_PATTERN.test(pins.caid)
    || !validIdentifier(pins.providerAccountId)
    || !validDigest(pins.targetDigest)
    || !validIdentifier(pins.operation)
    || !validIdentifier(pins.envelopeIssuerId)
    || !validIdentifier(pins.envelopeKeyId)
  ) {
    throw new TypeError('consequence actuator pins are malformed');
  }
  const maxEnvelopeTtlMs =
    pins.maxEnvelopeTtlMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS;
  const clockSkewMs =
    pins.clockSkewMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS;
  if (
    !Number.isSafeInteger(maxEnvelopeTtlMs)
    || maxEnvelopeTtlMs < 1
    || maxEnvelopeTtlMs > MAX_CONFIGURED_TTL_MS
  ) {
    throw new TypeError(
      'maxEnvelopeTtlMs must be between 1 millisecond and 5 minutes',
    );
  }
  if (
    !Number.isSafeInteger(clockSkewMs)
    || clockSkewMs < 0
    || clockSkewMs > MAX_CLOCK_SKEW_MS
  ) {
    throw new TypeError('clockSkewMs must be between 0 and 30 seconds');
  }
  const verificationKey = normalizePublicKey(pins.envelopePublicKey);
  const visible = deepFreeze({
    tenantId: pins.tenantId,
    caid: pins.caid,
    providerAccountId: pins.providerAccountId,
    targetDigest: pins.targetDigest,
    operation: pins.operation,
    envelopeIssuerId: pins.envelopeIssuerId,
    envelopeKeyId: pins.envelopeKeyId,
    envelopePublicKeyFingerprint: publicKeyFingerprint(verificationKey),
    maxEnvelopeTtlMs,
    clockSkewMs,
  });
  return { visible, verificationKey };
}

function verifyWithNormalizedPins(
  envelope: unknown,
  pins: NormalizedPins,
  expected: VerifyExpectedBinding,
  now: number | (() => number) | undefined,
): ConsequenceEnvelopeVerification {
  let cloned: unknown;
  let canonicalEnvelope: string;
  try {
    const result = canonicalClone(envelope);
    cloned = result.value;
    canonicalEnvelope = result.canonical;
  } catch {
    return { ok: false, reason: 'malformed_envelope' };
  }
  if (!isRecord(cloned) || !exactKeys(cloned, ENVELOPE_KEYS)) {
    return { ok: false, reason: 'malformed_envelope' };
  }
  if (!isRecord(cloned.payload)) {
    return { ok: false, reason: 'malformed_envelope' };
  }
  if (cloned.payload['@version'] !== CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION) {
    return { ok: false, reason: 'unsupported_version' };
  }
  if (!validatePayloadShape(cloned.payload)) {
    return { ok: false, reason: 'malformed_envelope' };
  }
  if (
    !isRecord(cloned.signature)
    || !exactKeys(cloned.signature, SIGNATURE_KEYS)
    || cloned.signature.algorithm !== CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM
    || !validIdentifier(cloned.signature.key_id)
  ) {
    return { ok: false, reason: 'malformed_envelope' };
  }
  const signatureBytes = decodeCanonicalBase64Url(
    cloned.signature.value,
    64,
    64,
  );
  if (signatureBytes === null) {
    return { ok: false, reason: 'malformed_envelope' };
  }

  const payload = cloned.payload;
  const signature = cloned.signature;
  if (signature.key_id !== pins.visible.envelopeKeyId) {
    return { ok: false, reason: 'signer_key_mismatch' };
  }

  const canonicalPayload = canonicalize(payload);
  let validSignature = false;
  try {
    validSignature = verify(
      null,
      signatureInput(canonicalPayload),
      pins.verificationKey,
      signatureBytes,
    );
  } catch {
    validSignature = false;
  }
  if (!validSignature) {
    return { ok: false, reason: 'signature_invalid' };
  }

  if (payload.issuer_id !== pins.visible.envelopeIssuerId) {
    return { ok: false, reason: 'issuer_mismatch' };
  }
  if (payload.tenant_id !== pins.visible.tenantId) {
    return { ok: false, reason: 'tenant_mismatch' };
  }
  if (payload.caid !== pins.visible.caid) {
    return { ok: false, reason: 'caid_mismatch' };
  }
  if (payload.provider_account_id !== pins.visible.providerAccountId) {
    return { ok: false, reason: 'provider_account_mismatch' };
  }
  if (payload.target_digest !== pins.visible.targetDigest) {
    return { ok: false, reason: 'target_mismatch' };
  }
  if (payload.operation !== pins.visible.operation) {
    return { ok: false, reason: 'operation_mismatch' };
  }
  if (payload.attempt_id !== expected.attemptId) {
    return { ok: false, reason: 'attempt_mismatch' };
  }
  if (payload.action_digest !== expected.actionDigest) {
    return { ok: false, reason: 'action_digest_mismatch' };
  }
  if (payload.idempotency_key !== expected.idempotencyKey) {
    return { ok: false, reason: 'idempotency_key_mismatch' };
  }

  let currentTime: number;
  try {
    currentTime = nowMilliseconds(now);
  } catch {
    return { ok: false, reason: 'malformed_envelope' };
  }
  const issuedAt = Date.parse(payload.issued_at);
  const expiresAt = Date.parse(payload.expires_at);
  if (issuedAt > currentTime + pins.visible.clockSkewMs) {
    return { ok: false, reason: 'envelope_not_yet_valid' };
  }
  if (expiresAt <= currentTime) {
    return { ok: false, reason: 'envelope_expired' };
  }
  if (expiresAt - issuedAt > pins.visible.maxEnvelopeTtlMs) {
    return { ok: false, reason: 'envelope_ttl_exceeded' };
  }

  return {
    ok: true,
    payload,
    envelopeDigest: `sha256:${createHash('sha256')
      .update(canonicalEnvelope)
      .digest('hex')}`,
  };
}

function reservationFrom(
  payload: Readonly<ConsequenceExecutionEnvelopePayload>,
  envelopeDigest: string,
): ConsequenceActuatorReservation {
  return deepFreeze({
    tenantId: payload.tenant_id,
    attemptId: payload.attempt_id,
    actionDigest: payload.action_digest,
    caid: payload.caid,
    providerAccountId: payload.provider_account_id,
    targetDigest: payload.target_digest,
    operation: payload.operation,
    idempotencyKey: payload.idempotency_key,
    nonce: payload.nonce,
    issuedAt: payload.issued_at,
    expiresAt: payload.expires_at,
    envelopeDigest,
  });
}

function refusal(
  reason: ConsequenceActuatorRefusalReason,
  invoked: boolean,
  envelopeDigest?: string,
): ConsequenceActuatorExecutionResult<never> {
  return deepFreeze({
    ok: false,
    invoked,
    reason,
    ...(envelopeDigest === undefined ? {} : { envelopeDigest }),
  });
}

/** Create a closed Ed25519 execution envelope for an already-authorized effect. */
export function signConsequenceExecutionEnvelope(
  payload: ConsequenceExecutionEnvelopePayload,
  options: SignEnvelopeOptions,
): SignedConsequenceExecutionEnvelope {
  const cloned = canonicalClone(payload);
  if (!validatePayloadShape(cloned.value)) {
    throw new TypeError('execution envelope payload is malformed');
  }
  if (!validIdentifier(options?.keyId)) {
    throw new TypeError('execution envelope keyId is malformed');
  }
  const signature = sign(
    null,
    signatureInput(cloned.canonical),
    normalizePrivateKey(options.privateKey),
  ).toString('base64url');
  return deepFreeze({
    payload: cloned.value,
    signature: {
      algorithm: CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM,
      key_id: options.keyId,
      value: signature,
    },
  });
}

/** Verify an envelope without invoking a provider or mutating replay state. */
export function verifyConsequenceExecutionEnvelope(
  envelope: unknown,
  options: VerifyOptions,
): ConsequenceEnvelopeVerification {
  try {
    return verifyWithNormalizedPins(
      envelope,
      normalizePins(options.pins),
      options.expected,
      options.now,
    );
  } catch {
    return { ok: false, reason: 'malformed_envelope' };
  }
}

// ===========================================================================
// EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v2 -- the hybrid (Ed25519 + ML-DSA-65) envelope
// ===========================================================================
// REFERENCE-PATTERN MIGRATION, following the five moves in "PATTERN: the
// reference hybrid migration" (EP-REVOCATION-v2 is the template) in
// docs/protocol/pq-hybrid-program.md:
//   1. VERSION BUMP, NOT A FIELD BUMP. signConsequenceExecutionEnvelope /
//      verifyConsequenceExecutionEnvelope above, and the ConsequenceActuator
//      class's synchronous execute() path, are UNCHANGED. v2 is a distinct
//      `@version` marker and a distinct `proof` shape (`{ required_algorithms,
//      signatures }` instead of the flat `{ algorithm, key_id, value }`), so
//      a v1 actuator refuses a v2 envelope on shape/version BEFORE
//      inspecting any signature.
//   2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
//      array ({ alg, sig, key_id? }), reused verbatim from
//      packages/verify/src/pq-signature-agility.ts.
//   3. ANTI-STRIPPING BYTES. `required_algorithms` is INSIDE the signed
//      bytes (consequenceEnvelopeV2SigningInput); the verifier rebuilds them
//      from the REGISTERED set and the PRESENTED payload, never from what
//      the proof claims.
//   4. V1 COMPATIBILITY. The v1 signing/verification stays synchronous and
//      untouched; v2 is a SEPARATE async entry point (ML-DSA verification is
//      async). This v2 pair verifies the ENVELOPE only -- it deliberately
//      does not extend the stateful ConsequenceActuator/store reserve-consume
//      machinery, which is an operational concern independent of signature
//      algorithm; a caller wiring a v2 envelope into that machinery verifies
//      it first with verifyConsequenceExecutionEnvelopeV2 and then reserves
//      under the SAME atomic-store discipline the v1 path already enforces.
//   5. NAMED REFUSALS. Nothing throws on caller input; an absent ML-DSA
//      backend is a refusal, never a skipped check and never a pass on the
//      surviving classical leg.

export const CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION =
  'EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v2';
export const CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);
const PROOF_V2_KEYS = ['required_algorithms', 'key_id', 'pq_key_id', 'signatures'] as const;

export interface ConsequenceExecutionEnvelopePayloadV2 {
  '@version': typeof CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION;
  issuer_id: string;
  tenant_id: string;
  attempt_id: string;
  action_digest: string;
  caid: string;
  provider_account_id: string;
  target_digest: string;
  operation: string;
  idempotency_key: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface ConsequenceExecutionEnvelopeProofV2 {
  required_algorithms: readonly string[];
  key_id: string;
  pq_key_id: string;
  signatures: AgileSignature[];
}

export interface SignedConsequenceExecutionEnvelopeV2 {
  payload: ConsequenceExecutionEnvelopePayloadV2;
  proof: ConsequenceExecutionEnvelopeProofV2;
}

export interface ConsequenceActuatorPinsV2 {
  tenantId: string;
  caid: string;
  providerAccountId: string;
  targetDigest: string;
  operation: string;
  envelopeIssuerId: string;
  envelopeKeyId: string;
  envelopePublicKey: KeyMaterial;
  envelopePqKeyId: string;
  /** ML-DSA-65 raw public key (1952 bytes), Uint8Array or base64url. */
  envelopePqPublicKey: Uint8Array | string;
  maxEnvelopeTtlMs?: number;
  clockSkewMs?: number;
}

export type ConsequenceEnvelopeVerificationV2 =
  | {
      readonly ok: true;
      readonly payload: Readonly<ConsequenceExecutionEnvelopePayloadV2>;
      readonly envelopeDigest: string;
    }
  | {
      readonly ok: false;
      readonly reason: string;
    };

function algorithmSetMatchesConsequenceV2(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS[i]);
}

function validatePayloadShapeV2(
  value: unknown,
): value is ConsequenceExecutionEnvelopePayloadV2 {
  if (!isRecord(value) || !exactKeys(value, PAYLOAD_KEYS)) return false;
  const issuedAt = canonicalInstant(value.issued_at);
  const expiresAt = canonicalInstant(value.expires_at);
  return value['@version'] === CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION
    && validIdentifier(value.issuer_id)
    && validIdentifier(value.tenant_id)
    && validIdentifier(value.attempt_id)
    && validDigest(value.action_digest)
    && typeof value.caid === 'string'
    && CAID_PATTERN.test(value.caid)
    && validIdentifier(value.provider_account_id)
    && validDigest(value.target_digest)
    && validIdentifier(value.operation)
    && validIdentifier(value.idempotency_key)
    && decodeCanonicalBase64Url(value.nonce, 16, 64) !== null
    && issuedAt !== null
    && expiresAt !== null
    && expiresAt > issuedAt;
}

/**
 * Bytes BOTH legs sign: the domain tag, the canonical payload, and the
 * committed required-algorithm set. Recomputed independently by the verifier
 * from the PRESENTED payload and the REGISTERED set.
 */
function consequenceEnvelopeV2SigningInput(
  canonicalPayload: string,
  requiredAlgorithms: readonly string[] = CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesConsequenceV2(requiredAlgorithms)) {
    throw new Error('consequenceEnvelopeV2SigningInput: algorithm set is not the registered EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v2 set');
  }
  return Buffer.concat([
    Buffer.from(CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalize({ required_algorithms: [...requiredAlgorithms] }), 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalPayload, 'utf8'),
  ]);
}

/** Create a closed hybrid (Ed25519 + ML-DSA-65) execution envelope for an already-authorized effect. */
export async function signConsequenceExecutionEnvelopeV2(
  payload: ConsequenceExecutionEnvelopePayloadV2,
  options: {
    privateKey: KeyMaterial;
    keyId: string;
    /** ML-DSA-65 raw secret key (4032 bytes), Uint8Array or base64url. */
    pqPrivateKey: Uint8Array | string;
    pqKeyId: string;
  } & AgilityOptions,
): Promise<SignedConsequenceExecutionEnvelopeV2> {
  const cloned = canonicalClone(payload);
  if (!validatePayloadShapeV2(cloned.value)) {
    throw new TypeError('hybrid execution envelope payload is malformed');
  }
  if (!validIdentifier(options?.keyId) || !validIdentifier(options?.pqKeyId)) {
    throw new TypeError('hybrid execution envelope keyId/pqKeyId is malformed');
  }
  const bytes = consequenceEnvelopeV2SigningInput(cloned.canonical);
  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: normalizePrivateKey(options.privateKey), key_id: options.keyId },
    { alg: 'ML-DSA-65', private_key: options.pqPrivateKey, key_id: options.pqKeyId },
  ], options);
  return deepFreeze({
    payload: cloned.value,
    proof: {
      required_algorithms: [...CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS],
      key_id: options.keyId,
      pq_key_id: options.pqKeyId,
      signatures,
    },
  });
}

/**
 * FAIL-CLOSED hybrid verify of one envelope, without invoking a provider or
 * mutating replay state. A v2 envelope NEVER verifies on one leg alone; an
 * absent ML-DSA backend is a refusal, never a skipped check and never a pass
 * on the surviving classical leg.
 */
export async function verifyConsequenceExecutionEnvelopeV2(
  envelope: unknown,
  options: {
    pins: ConsequenceActuatorPinsV2;
    expected: VerifyExpectedBinding;
    now?: number | (() => number);
  } & AgilityOptions,
): Promise<ConsequenceEnvelopeVerificationV2> {
  try {
    const pins = options.pins;
    if (!isRecord(pins)) throw new TypeError('consequence actuator pins are required');
    if (!validIdentifier(pins.tenantId)
        || typeof pins.caid !== 'string' || !CAID_PATTERN.test(pins.caid)
        || !validIdentifier(pins.providerAccountId)
        || !validDigest(pins.targetDigest)
        || !validIdentifier(pins.operation)
        || !validIdentifier(pins.envelopeIssuerId)
        || !validIdentifier(pins.envelopeKeyId)
        || !validIdentifier(pins.envelopePqKeyId)) {
      return { ok: false, reason: 'malformed_envelope' };
    }
    const maxEnvelopeTtlMs = pins.maxEnvelopeTtlMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS;
    const clockSkewMs = pins.clockSkewMs ?? DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS;
    if (!Number.isSafeInteger(maxEnvelopeTtlMs) || maxEnvelopeTtlMs < 1 || maxEnvelopeTtlMs > MAX_CONFIGURED_TTL_MS
        || !Number.isSafeInteger(clockSkewMs) || clockSkewMs < 0 || clockSkewMs > MAX_CLOCK_SKEW_MS) {
      return { ok: false, reason: 'malformed_envelope' };
    }
    const verificationKey = normalizePublicKey(pins.envelopePublicKey);

    let cloned: unknown;
    let canonicalEnvelope: string;
    try {
      const result = canonicalClone(envelope);
      cloned = result.value;
      canonicalEnvelope = result.canonical;
    } catch {
      return { ok: false, reason: 'malformed_envelope' };
    }
    if (!isRecord(cloned) || !exactKeys(cloned, ['payload', 'proof'])) {
      return { ok: false, reason: 'malformed_envelope' };
    }
    if (!isRecord(cloned.payload) || cloned.payload['@version'] !== CONSEQUENCE_ACTUATOR_ENVELOPE_V2_VERSION) {
      return { ok: false, reason: 'unsupported_version' };
    }
    if (!validatePayloadShapeV2(cloned.payload)) {
      return { ok: false, reason: 'malformed_envelope' };
    }
    const proof = cloned.proof;
    if (!isRecord(proof) || !exactKeys(proof, PROOF_V2_KEYS)
        || !algorithmSetMatchesConsequenceV2(proof.required_algorithms)
        || !Array.isArray(proof.signatures)
        || proof.key_id !== pins.envelopeKeyId
        || proof.pq_key_id !== pins.envelopePqKeyId) {
      return { ok: false, reason: 'malformed_envelope' };
    }
    const presented = new Set<string>();
    for (const s of proof.signatures as AgileSignature[]) {
      if (!s || typeof s !== 'object' || typeof s.alg !== 'string') return { ok: false, reason: 'malformed_envelope' };
      if (presented.has(s.alg)) return { ok: false, reason: 'malformed_envelope' };
      presented.add(s.alg);
    }
    for (const alg of CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return { ok: false, reason: 'signature_invalid' };
    }
    for (const alg of presented) {
      if (!(CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return { ok: false, reason: 'malformed_envelope' };
      }
    }

    const payload = cloned.payload;
    const canonicalPayload = canonicalize(payload);
    let bytes: Buffer;
    try {
      bytes = consequenceEnvelopeV2SigningInput(canonicalPayload);
    } catch {
      return { ok: false, reason: 'malformed_envelope' };
    }
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(bytes),
        proof.signatures,
        [
          { alg: 'Ed25519', public_key: verificationKey },
          { alg: 'ML-DSA-65', public_key: pins.envelopePqPublicKey },
        ],
        { ...options, policy: 'hybrid_all', requiredAlgorithms: [...CONSEQUENCE_ACTUATOR_V2_REQUIRED_ALGORITHMS] },
      );
    } catch {
      setResult = null;
    }
    if (setResult?.verified !== true) {
      const reason = String(setResult?.reason ?? 'signature_set_unverified');
      return {
        ok: false,
        reason: reason.includes('pq_backend_unavailable') ? 'pq_backend_unavailable' : 'signature_invalid',
      };
    }

    if (payload.issuer_id !== pins.envelopeIssuerId) return { ok: false, reason: 'issuer_mismatch' };
    if (payload.tenant_id !== pins.tenantId) return { ok: false, reason: 'tenant_mismatch' };
    if (payload.caid !== pins.caid) return { ok: false, reason: 'caid_mismatch' };
    if (payload.provider_account_id !== pins.providerAccountId) return { ok: false, reason: 'provider_account_mismatch' };
    if (payload.target_digest !== pins.targetDigest) return { ok: false, reason: 'target_mismatch' };
    if (payload.operation !== pins.operation) return { ok: false, reason: 'operation_mismatch' };
    if (payload.attempt_id !== options.expected.attemptId) return { ok: false, reason: 'attempt_mismatch' };
    if (payload.action_digest !== options.expected.actionDigest) return { ok: false, reason: 'action_digest_mismatch' };
    if (payload.idempotency_key !== options.expected.idempotencyKey) return { ok: false, reason: 'idempotency_key_mismatch' };

    let currentTime: number;
    try {
      currentTime = nowMilliseconds(options.now);
    } catch {
      return { ok: false, reason: 'malformed_envelope' };
    }
    const issuedAt = Date.parse(payload.issued_at);
    const expiresAt = Date.parse(payload.expires_at);
    if (issuedAt > currentTime + clockSkewMs) return { ok: false, reason: 'envelope_not_yet_valid' };
    if (expiresAt <= currentTime) return { ok: false, reason: 'envelope_expired' };
    if (expiresAt - issuedAt > maxEnvelopeTtlMs) return { ok: false, reason: 'envelope_ttl_exceeded' };

    return {
      ok: true,
      payload,
      envelopeDigest: `sha256:${createHash('sha256').update(canonicalEnvelope).digest('hex')}`,
    };
  } catch {
    return { ok: false, reason: 'malformed_envelope' };
  }
}

/**
 * Credential-owning actuator. `perform` captures the provider credential in
 * the actuator process; callers cannot submit or replace that credential.
 */
export class ConsequenceActuator<TResult = unknown> {
  readonly pins: VisibleConsequenceActuatorPins;

  readonly #normalizedPins: NormalizedPins;
  readonly #reserve: ConsequenceActuatorStore['reserve'];
  readonly #consume: ConsequenceActuatorStore['consume'];
  readonly #perform: (
    binding: Readonly<ConsequenceExecutionEnvelopePayload>,
  ) => TResult | Promise<TResult>;
  readonly #now: number | (() => number) | undefined;

  constructor(options: ConsequenceActuatorOptions<TResult>) {
    if (
      !isRecord(options)
      || !isRecord(options.store)
      || typeof options.store.reserve !== 'function'
      || typeof options.store.consume !== 'function'
      || typeof options.perform !== 'function'
    ) {
      throw new TypeError(
        'consequence actuator requires reserve/consume storage and a provider callback',
      );
    }
    const productionCapable = options.store.durable === true
      && options.store.atomic === true
      && options.store.ownershipFenced === true
      && options.store.permanentConsumption === true;
    const explicitTestStore = options.store.testOnly === true
      && options.testOnly === true;
    if (!productionCapable && !explicitTestStore) {
      throw new TypeError(
        'consequence actuator requires durable, atomic, ownership-fenced storage with permanent consumption; a non-production store requires testOnly: true',
      );
    }
    this.#normalizedPins = normalizePins(options.pins);
    this.pins = this.#normalizedPins.visible;
    this.#reserve = options.store.reserve.bind(options.store);
    this.#consume = options.store.consume.bind(options.store);
    this.#perform = options.perform;
    this.#now = options.now;
    Object.freeze(this);
  }

  async execute(
    input: ConsequenceActuatorExecutionInput,
  ): Promise<ConsequenceActuatorExecutionResult<TResult>> {
    const verified = verifyWithNormalizedPins(
      input?.envelope,
      this.#normalizedPins,
      {
        attemptId: input?.attemptId,
        actionDigest: input?.actionDigest,
        idempotencyKey: input?.idempotencyKey,
      },
      this.#now,
    );
    if (!verified.ok) {
      return refusal(verified.reason, false);
    }
    const reservation = reservationFrom(
      verified.payload,
      verified.envelopeDigest,
    );
    let reserved = false;
    try {
      reserved = await this.#reserve(reservation);
    } catch {
      return refusal(
        'store_reserve_failed',
        false,
        verified.envelopeDigest,
      );
    }
    if (reserved !== true) {
      return refusal(
        'envelope_replayed',
        false,
        verified.envelopeDigest,
      );
    }

    let providerResult: TResult;
    try {
      providerResult = await this.#perform(verified.payload);
    } catch {
      try {
        const consumed = await this.#consume(
          deepFreeze({ ...reservation, outcome: 'INDETERMINATE' as const }),
        );
        if (consumed !== true) {
          return refusal(
            'store_consume_unconfirmed',
            true,
            verified.envelopeDigest,
          );
        }
      } catch {
        return refusal(
          'store_consume_unconfirmed',
          true,
          verified.envelopeDigest,
        );
      }
      return refusal(
        'provider_outcome_indeterminate',
        true,
        verified.envelopeDigest,
      );
    }

    try {
      const consumed = await this.#consume(
        deepFreeze({ ...reservation, outcome: 'COMMITTED' as const }),
      );
      if (consumed !== true) {
        return refusal(
          'store_consume_unconfirmed',
          true,
          verified.envelopeDigest,
        );
      }
    } catch {
      return refusal(
        'store_consume_unconfirmed',
        true,
        verified.envelopeDigest,
      );
    }
    return deepFreeze({
      ok: true,
      invoked: true,
      result: providerResult,
      envelopeDigest: verified.envelopeDigest,
    });
  }
}

function reservationKey(
  tenantId: string,
  nonce: string,
): string {
  return canonicalize([tenantId, nonce]);
}

function idempotencyKey(
  reservation: ConsequenceActuatorReservation,
): string {
  return canonicalize([
    reservation.tenantId,
    reservation.providerAccountId,
    reservation.operation,
    reservation.idempotencyKey,
  ]);
}

function sameReservation(
  left: ConsequenceActuatorReservation,
  right: ConsequenceActuatorReservation,
): boolean {
  const identity = (value: ConsequenceActuatorReservation) => ({
    tenantId: value.tenantId,
    attemptId: value.attemptId,
    actionDigest: value.actionDigest,
    caid: value.caid,
    providerAccountId: value.providerAccountId,
    targetDigest: value.targetDigest,
    operation: value.operation,
    idempotencyKey: value.idempotencyKey,
    nonce: value.nonce,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    envelopeDigest: value.envelopeDigest,
  });
  return canonicalize(identity(left)) === canonicalize(identity(right));
}

/**
 * Race-safe, process-local reference store for tests. Map mutations occur
 * before each async method yields, so concurrent calls have one reservation
 * winner. Production must use the RPC-only durable store from the migration.
 */
export class MemoryConsequenceActuatorStore
implements ConsequenceActuatorStore {
  readonly testOnly = true as const;
  readonly durable = false;
  readonly atomic = true;
  readonly ownershipFenced = false;
  readonly permanentConsumption = false;

  readonly #records = new Map<string, MemoryConsequenceActuatorSnapshot>();
  readonly #idempotency = new Map<string, string>();
  readonly #now: number | (() => number) | undefined;

  constructor(options: { now?: number | (() => number) } = {}) {
    this.#now = options.now;
  }

  async reserve(
    reservation: ConsequenceActuatorReservation,
  ): Promise<boolean> {
    const key = reservationKey(reservation.tenantId, reservation.nonce);
    const operationKey = idempotencyKey(reservation);
    if (this.#records.has(key) || this.#idempotency.has(operationKey)) {
      return false;
    }
    const reservedAt = new Date(nowMilliseconds(this.#now)).toISOString();
    const snapshot = deepFreeze({
      ...reservation,
      state: 'RESERVED' as const,
      outcome: null,
      reservedAt,
      consumedAt: null,
    });
    this.#records.set(key, snapshot);
    this.#idempotency.set(operationKey, key);
    return true;
  }

  async consume(
    consumption: ConsequenceActuatorConsumption,
  ): Promise<boolean> {
    const key = reservationKey(consumption.tenantId, consumption.nonce);
    const current = this.#records.get(key);
    if (
      current === undefined
      || current.state !== 'RESERVED'
      || !sameReservation(current, consumption)
      || !['COMMITTED', 'INDETERMINATE'].includes(consumption.outcome)
    ) {
      return false;
    }
    this.#records.set(key, deepFreeze({
      ...current,
      state: 'CONSUMED' as const,
      outcome: consumption.outcome,
      consumedAt: new Date(nowMilliseconds(this.#now)).toISOString(),
    }));
    return true;
  }

  snapshot(
    tenantId: string,
    nonce: string,
  ): MemoryConsequenceActuatorSnapshot | null {
    const snapshot = this.#records.get(reservationKey(tenantId, nonce));
    if (snapshot === undefined) return null;
    return canonicalClone(snapshot).value as MemoryConsequenceActuatorSnapshot;
  }

  get size(): number {
    return this.#records.size;
  }
}

export function createMemoryConsequenceActuatorStore(
  options: { now?: number | (() => number) } = {},
): MemoryConsequenceActuatorStore {
  return new MemoryConsequenceActuatorStore(options);
}

const FORBIDDEN_EXECUTOR_PRINCIPALS = new Set([
  'anon',
  'authenticated',
  'postgres',
  'service_role',
  CONSEQUENCE_ACTUATOR_EXECUTOR_ROLE,
  CONSEQUENCE_ACTUATOR_STORE_OWNER_ROLE,
]);

function validStoreBinding(
  reservation: ConsequenceActuatorReservation,
): boolean {
  const issuedAt = canonicalInstant(reservation?.issuedAt);
  const expiresAt = canonicalInstant(reservation?.expiresAt);
  return validIdentifier(reservation?.tenantId)
    && validIdentifier(reservation?.attemptId)
    && validDigest(reservation?.actionDigest)
    && typeof reservation?.caid === 'string'
    && CAID_PATTERN.test(reservation.caid)
    && validIdentifier(reservation?.providerAccountId)
    && validDigest(reservation?.targetDigest)
    && validIdentifier(reservation?.operation)
    && validIdentifier(reservation?.idempotencyKey)
    && decodeCanonicalBase64Url(reservation?.nonce, 16, 64) !== null
    && issuedAt !== null
    && expiresAt !== null
    && expiresAt > issuedAt
    && validDigest(reservation?.envelopeDigest);
}

function exactPostgresAcknowledgement(
  result: ConsequenceActuatorPgQueryResult,
  expectedEnvelopeDigest: string,
): boolean {
  if (
    result !== null
    && typeof result === 'object'
    && result.rowCount === 0
    && Array.isArray(result.rows)
    && result.rows.length === 0
  ) {
    return false;
  }
  if (
    result === null
    || typeof result !== 'object'
    || result.rowCount !== 1
    || !Array.isArray(result.rows)
    || result.rows.length !== 1
    || !isRecord(result.rows[0])
    || result.rows[0].envelope_digest !== expectedEnvelopeDigest
  ) {
    throw new Error(
      'consequence actuator store returned an ambiguous acknowledgement',
    );
  }
  return true;
}

/**
 * Production adapter for the RPC-only PostgreSQL store. The supplied pool must
 * be dedicated to one tenant-mapped executor login; the adapter never emits
 * direct table SQL.
 */
export class PostgresConsequenceActuatorStore
implements ConsequenceActuatorStore {
  readonly durable = true;
  readonly atomic = true;
  readonly ownershipFenced = true;
  readonly permanentConsumption = true;
  readonly tenantId: string;
  readonly executorPrincipal: string;

  readonly #query: DedicatedConsequenceActuatorExecutorPool['query'];

  constructor(options: PostgresConsequenceActuatorStoreOptions) {
    if (
      !isRecord(options)
      || !validIdentifier(options.tenantId)
      || !validIdentifier(options.executorPrincipal)
      || FORBIDDEN_EXECUTOR_PRINCIPALS.has(options.executorPrincipal)
      || !isRecord(options.executorPool)
      || options.executorPool.principal !== options.executorPrincipal
      || typeof options.executorPool.query !== 'function'
    ) {
      throw new TypeError(
        'a dedicated tenant executor principal and matching pool are required',
      );
    }
    this.tenantId = options.tenantId;
    this.executorPrincipal = options.executorPrincipal;
    this.#query = options.executorPool.query.bind(options.executorPool);
    Object.freeze(this);
  }

  async reserve(
    reservation: ConsequenceActuatorReservation,
  ): Promise<boolean> {
    if (
      !validStoreBinding(reservation)
      || reservation.tenantId !== this.tenantId
    ) {
      throw new TypeError(
        'consequence actuator reservation does not match the store tenant',
      );
    }
    const result = await this.#query(
      CONSEQUENCE_ACTUATOR_SQL.reserve,
      [
        reservation.tenantId,
        reservation.attemptId,
        reservation.actionDigest,
        reservation.caid,
        reservation.providerAccountId,
        reservation.targetDigest,
        reservation.operation,
        reservation.idempotencyKey,
        reservation.nonce,
        reservation.issuedAt,
        reservation.expiresAt,
        reservation.envelopeDigest,
      ],
    );
    return exactPostgresAcknowledgement(result, reservation.envelopeDigest);
  }

  async consume(
    consumption: ConsequenceActuatorConsumption,
  ): Promise<boolean> {
    if (
      !validStoreBinding(consumption)
      || consumption.tenantId !== this.tenantId
      || !['COMMITTED', 'INDETERMINATE'].includes(consumption.outcome)
    ) {
      throw new TypeError(
        'consequence actuator consumption does not match the store tenant',
      );
    }
    const result = await this.#query(
      CONSEQUENCE_ACTUATOR_SQL.consume,
      [
        consumption.tenantId,
        consumption.attemptId,
        consumption.actionDigest,
        consumption.caid,
        consumption.providerAccountId,
        consumption.targetDigest,
        consumption.operation,
        consumption.idempotencyKey,
        consumption.nonce,
        consumption.envelopeDigest,
        consumption.outcome,
      ],
    );
    return exactPostgresAcknowledgement(result, consumption.envelopeDigest);
  }
}

export function createPostgresConsequenceActuatorStore(
  options: PostgresConsequenceActuatorStoreOptions,
): PostgresConsequenceActuatorStore {
  return new PostgresConsequenceActuatorStore(options);
}
