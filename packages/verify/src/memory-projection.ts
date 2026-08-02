// SPDX-License-Identifier: Apache-2.0
/**
 * MEMORY-PROJECTION-RECORD-v1.
 *
 * Provider-neutral producer and verifier for
 * draft-ferro-schrock-memory-projection-record-00.
 *
 * The envelope verifier proves the closed record shape, adapter signature,
 * key status, freshness, and nonclaims. The full verifier additionally
 * rehashes the exact request, policy, trust snapshot, source objects,
 * fragments, and complete projection bytes, and delegates native source
 * verification to the source-profile implementation selected by the relying
 * party.
 */
import crypto from 'node:crypto';

type Obj = Record<string, any>;

export const MEMORY_PROJECTION_RECORD_VERSION = 'MEMORY-PROJECTION-RECORD-v1';
export const MEMORY_PROJECTION_RECORD_DOMAIN = 'MEMORY-PROJECTION-RECORD-v1\0';

export const MEMORY_PROJECTION_NONCLAIMS = Object.freeze({
  model_use: 'NOT_ESTABLISHED',
  action_linkage: 'NOT_ESTABLISHED',
  action_authorization: 'NOT_ESTABLISHED',
  execution_outcome: 'NOT_ESTABLISHED',
});

export type MemoryProjectionTrust = 'self' | 'trusted' | 'unverified';
export type MemoryProjectionAuthorship = 'signed' | 'attested' | 'unknown';

export interface MemoryProjectionAdapterKey {
  public_key_spki_b64u: string;
  status: 'active' | 'revoked' | 'superseded';
  valid_from: string;
  valid_to: string;
  revoked_at: string | null;
}

export interface MemoryProjectionDeliveredInput {
  formatVersion: number;
  sealedObjectBytes: Uint8Array;
  contextFragmentBytes: Uint8Array;
  derivedTrust: MemoryProjectionTrust;
  authorship: MemoryProjectionAuthorship;
  authorKeyIdB64u: string | null;
  custodyPresent: boolean;
}

export interface MemoryProjectionProducerInput {
  sourceProfile: string;
  projectionId: string;
  createdAt: string;
  adapter: {
    id: string;
    keyId: string;
  };
  selectionContext: {
    recallRequestBytes: Uint8Array;
    selectionPolicyBytes: Uint8Array;
    trustSnapshotBytes: Uint8Array;
    trustEvaluatedAt: string;
    contextFrameProfile: string;
  };
  delivered: MemoryProjectionDeliveredInput[];
  exclusions: {
    authenticationFailed: number;
    schemaInvalid: number;
    policyFiltered: number;
    contextLimit: number;
  };
  privateKey: crypto.KeyLike;
}

export interface MemoryProjectionVerificationPolicy {
  adapterKeys: Record<string, MemoryProjectionAdapterKey>;
  verificationTime: string;
  maxProjectionAgeSec: number;
  maxTrustAgeSec: number;
  expectedSourceProfile?: string;
  expectedContextFrameProfile?: string;
}

export interface MemoryProjectionNativeSourceResult {
  valid: true;
  formatVersion: number;
  sealedObjectDigest: string;
  derivedTrust: MemoryProjectionTrust;
  authorship: MemoryProjectionAuthorship;
  authorKeyIdB64u: string | null;
  custodyPresent: boolean;
}

export interface MemoryProjectionVerificationMaterial {
  recallRequestBytes: Uint8Array;
  selectionPolicyBytes: Uint8Array;
  trustSnapshotBytes: Uint8Array;
  sourceObjectBytesByPosition: Uint8Array[];
  fragmentBytesByPosition: Uint8Array[];
  projectionBytes: Uint8Array;
  verifySourceEntry: (input: {
    sourceProfile: string;
    position: number;
    sourceObjectBytes: Uint8Array;
    deliveredEntry: Readonly<Obj>;
  }) => MemoryProjectionNativeSourceResult;
}

export interface MemoryProjectionIdRegistry {
  /**
   * Atomically register one projection identifier.
   * Return false when it was already registered.
   */
  register(projectionId: string): boolean;
}

export class MemoryProjectionVerificationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'MemoryProjectionVerificationError';
    this.code = code;
  }
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
const RECORD_KEYS = new Set([
  '@version',
  'source_profile',
  'projection_id',
  'created_at',
  'adapter',
  'selection_context',
  'delivered',
  'exclusions',
  'projection',
  'nonclaims',
  'proof',
]);
const ADAPTER_KEYS = new Set(['id', 'key_id']);
const SELECTION_KEYS = new Set([
  'recall_request_digest',
  'selection_policy_digest',
  'trust_snapshot_digest',
  'trust_evaluated_at',
  'context_frame_profile',
]);
const DELIVERED_KEYS = new Set([
  'position',
  'object',
  'context_fragment_digest',
  'derived_trust',
  'authorship',
  'author_key_id_b64u',
  'custody_present',
]);
const OBJECT_KEYS = new Set(['format_version', 'sealed_object_digest']);
const EXCLUSION_KEYS = new Set(['total', 'by_reason']);
const EXCLUSION_REASON_KEYS = new Set([
  'authentication_failed',
  'schema_invalid',
  'policy_filtered',
  'context_limit',
]);
const PROJECTION_KEYS = new Set(['encoding', 'byte_length', 'digest']);
const NONCLAIM_KEYS = new Set([
  'model_use',
  'action_linkage',
  'action_authorization',
  'execution_outcome',
]);
const PROOF_KEYS = new Set(['alg', 'key_id', 'signature_b64u']);

function fail(code: string, message: string): never {
  throw new MemoryProjectionVerificationError(code, message);
}

function isDataObject(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, expected: Set<string>, path: string): asserts value is Obj {
  if (!isDataObject(value)) fail('record_invalid', `${path} must be a plain data object`);
  const keys = Object.keys(value);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) {
    fail('record_invalid', `${path} has an unknown, missing, or duplicated semantic member`);
  }
}

function safeInteger(value: unknown, path: string, minimum = 0): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || Object.is(value, -0)) {
    fail('record_invalid', `${path} must be a safe integer >= ${minimum}`);
  }
}

function boundedString(value: unknown, path: string, maximum = 1024): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum
      || /[\u0000-\u001f\u007f]/.test(value) || hasUnpairedSurrogate(value)) {
    fail('record_invalid', `${path} must be a bounded I-JSON string`);
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function absoluteUri(value: unknown, path: string): asserts value is string {
  boundedString(value, path, 2048);
  try {
    const parsed = new URL(value);
    if (!parsed.protocol) throw new Error('missing scheme');
  } catch {
    fail('record_invalid', `${path} must be an absolute URI`);
  }
}

function instantMs(value: unknown, path: string): number {
  if (typeof value !== 'string') fail('record_invalid', `${path} must be a UTC RFC 3339 timestamp`);
  const match = value.match(RFC3339_UTC);
  if (!match) fail('record_invalid', `${path} must be a UTC RFC 3339 timestamp`);
  const [, year, month, day, hour, minute, second] = match;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
    fail('record_invalid', `${path} must be a real UTC calendar instant`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail('record_invalid', `${path} must be a UTC RFC 3339 timestamp`);
  return parsed;
}

function digest(value: unknown, path: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    fail('record_invalid', `${path} must be a lowercase SHA-256 digest`);
  }
}

function canonicalBase64url(value: unknown, path: string, exactBytes?: number): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL.test(value)) {
    fail('record_invalid', `${path} must be unpadded base64url`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (exactBytes !== undefined && bytes.length !== exactBytes)) {
    fail('record_invalid', `${path} must be canonical unpadded base64url`);
  }
}

function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    if (hasUnpairedSurrogate(value)) fail('record_invalid', 'signed record contains invalid Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      fail('record_invalid', 'signed record numbers must be safe integers');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (!isDataObject(value)) fail('record_invalid', 'signed record must be I-JSON data');
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(',')}}`;
}

function digestBytes(bytes: Uint8Array): string {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function unsignedRecord(record: Obj): Obj {
  const { proof: _proof, ...unsigned } = record;
  return unsigned;
}

function signingBytes(record: Obj): Buffer {
  return Buffer.concat([
    Buffer.from(MEMORY_PROJECTION_RECORD_DOMAIN, 'utf8'),
    Buffer.from(canonicalize(unsignedRecord(record)), 'utf8'),
  ]);
}

function keyObject(publicKeySpkiB64u: unknown): crypto.KeyObject {
  canonicalBase64url(publicKeySpkiB64u, 'adapter key');
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeySpkiB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    if (key.asymmetricKeyType !== 'ed25519') {
      fail('adapter_key_invalid', 'adapter key must be Ed25519');
    }
    return key;
  } catch (error) {
    if (error instanceof MemoryProjectionVerificationError) throw error;
    fail('adapter_key_invalid', 'adapter key must be canonical Ed25519 SPKI');
  }
}

function validateAdapterKey(
  entry: unknown,
  createdAt: number,
  verificationTime: number,
): crypto.KeyObject {
  const keys = new Set(['public_key_spki_b64u', 'status', 'valid_from', 'valid_to', 'revoked_at']);
  exactKeys(entry, keys, 'adapter key');
  if (!['active', 'revoked', 'superseded'].includes(entry.status)) {
    fail('adapter_key_invalid', 'adapter key status is invalid');
  }
  const validFrom = instantMs(entry.valid_from, 'adapter key valid_from');
  const validTo = instantMs(entry.valid_to, 'adapter key valid_to');
  const revokedAt = entry.revoked_at === null
    ? null
    : instantMs(entry.revoked_at, 'adapter key revoked_at');
  if (validFrom > validTo) fail('adapter_key_invalid', 'adapter key validity interval is inverted');
  if (createdAt < validFrom || createdAt > validTo) {
    fail('adapter_key_inactive', 'adapter key was not valid when the projection was created');
  }
  if (entry.status === 'revoked' && revokedAt !== null && verificationTime >= revokedAt) {
    fail('adapter_key_revoked', 'adapter key is revoked at verification time');
  }
  if (entry.status !== 'active' || verificationTime < validFrom || verificationTime > validTo) {
    fail('adapter_key_inactive', 'adapter key is not current at verification time');
  }
  return keyObject(entry.public_key_spki_b64u);
}

function validateDeliveredEntry(entry: unknown, position: number): asserts entry is Obj {
  const path = `record.delivered[${position}]`;
  exactKeys(entry, DELIVERED_KEYS, path);
  if (entry.position !== position) {
    fail('delivered_order_invalid', `${path}.position must equal ${position}`);
  }
  exactKeys(entry.object, OBJECT_KEYS, `${path}.object`);
  safeInteger(entry.object.format_version, `${path}.object.format_version`, 1);
  digest(entry.object.sealed_object_digest, `${path}.object.sealed_object_digest`);
  digest(entry.context_fragment_digest, `${path}.context_fragment_digest`);
  if (!['self', 'trusted', 'unverified'].includes(entry.derived_trust)) {
    fail('record_invalid', `${path}.derived_trust is invalid`);
  }
  if (!['signed', 'attested', 'unknown'].includes(entry.authorship)) {
    fail('record_invalid', `${path}.authorship is invalid`);
  }
  if (entry.author_key_id_b64u !== null) {
    canonicalBase64url(entry.author_key_id_b64u, `${path}.author_key_id_b64u`);
  }
  if (typeof entry.custody_present !== 'boolean') {
    fail('record_invalid', `${path}.custody_present must be boolean`);
  }
  if (entry.authorship === 'attested' && entry.custody_present !== true) {
    fail('source_result_invalid', `${path}: attested authorship requires custody`);
  }
  if (entry.derived_trust === 'unverified') {
    if (entry.authorship !== 'unknown' || entry.author_key_id_b64u !== null) {
      fail('source_result_invalid', `${path}: unverified content must not report an author`);
    }
  } else if (entry.authorship === 'unknown' || entry.author_key_id_b64u === null) {
    fail('source_result_invalid', `${path}: verified content must report an author`);
  }
}

function validateRecordShape(record: unknown): {
  value: Obj;
  createdAt: number;
  trustEvaluatedAt: number;
} {
  exactKeys(record, RECORD_KEYS, 'record');
  if (record['@version'] !== MEMORY_PROJECTION_RECORD_VERSION) {
    fail('version_unsupported', `record @version must be ${MEMORY_PROJECTION_RECORD_VERSION}`);
  }
  boundedString(record.source_profile, 'record.source_profile', 512);
  absoluteUri(record.projection_id, 'record.projection_id');
  const createdAt = instantMs(record.created_at, 'record.created_at');

  exactKeys(record.adapter, ADAPTER_KEYS, 'record.adapter');
  absoluteUri(record.adapter.id, 'record.adapter.id');
  boundedString(record.adapter.key_id, 'record.adapter.key_id', 512);

  exactKeys(record.selection_context, SELECTION_KEYS, 'record.selection_context');
  digest(record.selection_context.recall_request_digest, 'record.selection_context.recall_request_digest');
  digest(record.selection_context.selection_policy_digest, 'record.selection_context.selection_policy_digest');
  digest(record.selection_context.trust_snapshot_digest, 'record.selection_context.trust_snapshot_digest');
  const trustEvaluatedAt = instantMs(
    record.selection_context.trust_evaluated_at,
    'record.selection_context.trust_evaluated_at',
  );
  boundedString(
    record.selection_context.context_frame_profile,
    'record.selection_context.context_frame_profile',
    1024,
  );

  if (!Array.isArray(record.delivered)) fail('record_invalid', 'record.delivered must be an array');
  record.delivered.forEach(validateDeliveredEntry);

  exactKeys(record.exclusions, EXCLUSION_KEYS, 'record.exclusions');
  safeInteger(record.exclusions.total, 'record.exclusions.total');
  exactKeys(record.exclusions.by_reason, EXCLUSION_REASON_KEYS, 'record.exclusions.by_reason');
  let total = 0;
  for (const reason of EXCLUSION_REASON_KEYS) {
    safeInteger(record.exclusions.by_reason[reason], `record.exclusions.by_reason.${reason}`);
    total += record.exclusions.by_reason[reason];
  }
  if (total !== record.exclusions.total) {
    fail('exclusion_count_mismatch', 'record.exclusions.total must equal the four reason counters');
  }

  exactKeys(record.projection, PROJECTION_KEYS, 'record.projection');
  if (record.projection.encoding !== 'utf-8') {
    fail('record_invalid', 'record.projection.encoding must be utf-8');
  }
  safeInteger(record.projection.byte_length, 'record.projection.byte_length');
  digest(record.projection.digest, 'record.projection.digest');

  exactKeys(record.nonclaims, NONCLAIM_KEYS, 'record.nonclaims');
  for (const [key, expected] of Object.entries(MEMORY_PROJECTION_NONCLAIMS)) {
    if (record.nonclaims[key] !== expected) {
      fail('nonclaim_invalid', `record.nonclaims.${key} must be ${expected}`);
    }
  }

  exactKeys(record.proof, PROOF_KEYS, 'record.proof');
  if (record.proof.alg !== 'Ed25519') fail('record_invalid', 'record.proof.alg must be Ed25519');
  boundedString(record.proof.key_id, 'record.proof.key_id', 512);
  canonicalBase64url(record.proof.signature_b64u, 'record.proof.signature_b64u', 64);
  if (record.proof.key_id !== record.adapter.key_id) {
    fail('proof_key_mismatch', 'record.proof.key_id must equal record.adapter.key_id');
  }

  // Traverse the complete record once so no unsafe number or invalid Unicode
  // can enter the JCS signature boundary through an otherwise unchecked field.
  canonicalize(record);
  return { value: record, createdAt, trustEvaluatedAt };
}

function normalizePolicy(policy: MemoryProjectionVerificationPolicy): {
  verificationTime: number;
  maxProjectionAgeSec: number;
  maxTrustAgeSec: number;
} {
  if (!isDataObject(policy)) fail('verification_policy_invalid', 'verification policy is required');
  const verificationTime = instantMs(policy.verificationTime, 'verificationTime');
  safeInteger(policy.maxProjectionAgeSec, 'maxProjectionAgeSec');
  safeInteger(policy.maxTrustAgeSec, 'maxTrustAgeSec');
  if (!isDataObject(policy.adapterKeys)) {
    fail('verification_policy_invalid', 'adapterKeys must be a pinned key directory');
  }
  return {
    verificationTime,
    maxProjectionAgeSec: policy.maxProjectionAgeSec,
    maxTrustAgeSec: policy.maxTrustAgeSec,
  };
}

/**
 * Verify the closed signed envelope without requiring plaintext memory,
 * request, policy, trust-snapshot, fragment, or projection bytes.
 *
 * This is the correct boundary for a downstream Gate that receives only the
 * adapter's signed commitments. It does not claim those commitment preimages
 * were independently rehashed.
 */
export function verifyMemoryProjectionRecordV1Envelope(
  record: unknown,
  policy: MemoryProjectionVerificationPolicy,
): {
  valid: true;
  verification_scope: 'SIGNED_ENVELOPE_ONLY';
  projection_id: string;
  projection_digest: string;
  delivered_count: number;
  excluded_count: number;
  created_at: string;
  trust_evaluated_at: string;
} {
  const { value, createdAt, trustEvaluatedAt } = validateRecordShape(record);
  const normalized = normalizePolicy(policy);
  if (policy.expectedSourceProfile !== undefined
      && value.source_profile !== policy.expectedSourceProfile) {
    fail('source_profile_mismatch', 'record source profile is not pinned by the relying party');
  }
  if (policy.expectedContextFrameProfile !== undefined
      && value.selection_context.context_frame_profile !== policy.expectedContextFrameProfile) {
    fail('context_frame_profile_mismatch', 'record context-frame profile is not pinned');
  }
  const projectionAge = (normalized.verificationTime - createdAt) / 1000;
  if (projectionAge < 0) fail('projection_from_future', 'record creation time is in the future');
  if (projectionAge > normalized.maxProjectionAgeSec) {
    fail('projection_stale', 'record creation time is outside relying-party freshness policy');
  }
  const trustAge = (normalized.verificationTime - trustEvaluatedAt) / 1000;
  if (trustAge < 0) fail('trust_snapshot_from_future', 'trust evaluation time is in the future');
  if (trustAge > normalized.maxTrustAgeSec) {
    fail('trust_snapshot_stale', 'trust evaluation is outside relying-party freshness policy');
  }
  if (trustEvaluatedAt > createdAt) {
    fail('trust_snapshot_from_future', 'trust evaluation cannot occur after record creation');
  }

  const pinned = policy.adapterKeys[value.adapter.key_id];
  if (pinned === undefined) {
    fail('adapter_key_not_pinned', 'record adapter key is not pinned by the relying party');
  }
  const key = validateAdapterKey(pinned, createdAt, normalized.verificationTime);
  const signatureValid = crypto.verify(
    null,
    signingBytes(value),
    key,
    Buffer.from(value.proof.signature_b64u, 'base64url'),
  );
  if (!signatureValid) fail('signature_invalid', 'record signature is invalid');

  return {
    valid: true,
    verification_scope: 'SIGNED_ENVELOPE_ONLY',
    projection_id: value.projection_id,
    projection_digest: value.projection.digest,
    delivered_count: value.delivered.length,
    excluded_count: value.exclusions.total,
    created_at: value.created_at,
    trust_evaluated_at: value.selection_context.trust_evaluated_at,
  };
}

/**
 * Fully verify every commitment preimage and native source result.
 */
export function verifyMemoryProjectionRecordV1(
  record: unknown,
  material: MemoryProjectionVerificationMaterial,
  policy: MemoryProjectionVerificationPolicy,
  options: {
    projectionIdRegistry?: MemoryProjectionIdRegistry;
    requireSingleUse?: boolean;
  } = {},
): {
  valid: true;
  verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS';
  projection_id: string;
  projection_digest: string;
  delivered_count: number;
  excluded_count: number;
} {
  const envelope = verifyMemoryProjectionRecordV1Envelope(record, policy);
  const value = record as Obj;
  if (!isDataObject(material)) {
    fail('verification_material_missing', 'complete verification material is required');
  }
  const bytes = (candidate: unknown, path: string): Buffer => {
    if (!(candidate instanceof Uint8Array)) {
      fail('verification_material_missing', `${path} must be exact bytes`);
    }
    return Buffer.from(candidate);
  };
  if (typeof material.verifySourceEntry !== 'function') {
    fail('native_source_verifier_missing', 'a source-profile native verifier is required');
  }

  if (digestBytes(bytes(material.recallRequestBytes, 'recallRequestBytes'))
      !== value.selection_context.recall_request_digest) {
    fail('recall_request_digest_mismatch', 'recall request bytes do not match the record');
  }
  if (digestBytes(bytes(material.selectionPolicyBytes, 'selectionPolicyBytes'))
      !== value.selection_context.selection_policy_digest) {
    fail('selection_policy_digest_mismatch', 'selection policy bytes do not match the record');
  }
  if (digestBytes(bytes(material.trustSnapshotBytes, 'trustSnapshotBytes'))
      !== value.selection_context.trust_snapshot_digest) {
    fail('trust_snapshot_digest_mismatch', 'trust snapshot bytes do not match the record');
  }

  const sourceObjects = material.sourceObjectBytesByPosition;
  const fragments = material.fragmentBytesByPosition;
  if (!Array.isArray(sourceObjects) || sourceObjects.length !== value.delivered.length) {
    fail('source_object_material_mismatch', 'source-object material must match delivered length');
  }
  if (!Array.isArray(fragments) || fragments.length !== value.delivered.length) {
    fail('fragment_material_mismatch', 'fragment material must match delivered length');
  }

  const exactFragments: Buffer[] = [];
  for (let position = 0; position < value.delivered.length; position += 1) {
    const entry = value.delivered[position];
    const sourceObjectBytes = bytes(sourceObjects[position], `sourceObjectBytesByPosition[${position}]`);
    const fragmentBytes = bytes(fragments[position], `fragmentBytesByPosition[${position}]`);
    if (digestBytes(sourceObjectBytes) !== entry.object.sealed_object_digest) {
      fail('source_object_digest_mismatch', `source object ${position} does not match its commitment`);
    }
    if (digestBytes(fragmentBytes) !== entry.context_fragment_digest) {
      fail('fragment_digest_mismatch', `fragment ${position} does not match its commitment`);
    }
    const native = material.verifySourceEntry({
      sourceProfile: value.source_profile,
      position,
      sourceObjectBytes,
      deliveredEntry: entry,
    });
    if (!isDataObject(native) || native.valid !== true
        || native.formatVersion !== entry.object.format_version
        || native.sealedObjectDigest !== entry.object.sealed_object_digest
        || native.derivedTrust !== entry.derived_trust
        || native.authorship !== entry.authorship
        || native.authorKeyIdB64u !== entry.author_key_id_b64u
        || native.custodyPresent !== entry.custody_present) {
      fail('native_source_result_mismatch', `source-profile result ${position} does not match the record`);
    }
    exactFragments.push(fragmentBytes);
  }

  const projectionBytes = bytes(material.projectionBytes, 'projectionBytes');
  const concatenated = Buffer.concat(exactFragments);
  if (concatenated.length !== projectionBytes.length
      || !crypto.timingSafeEqual(concatenated, projectionBytes)) {
    fail('projection_fragment_concatenation_mismatch', 'fragments do not concatenate to projection bytes');
  }
  if (projectionBytes.length !== value.projection.byte_length) {
    fail('projection_length_mismatch', 'projection bytes do not match record byte_length');
  }
  if (digestBytes(projectionBytes) !== value.projection.digest) {
    fail('projection_digest_mismatch', 'projection bytes do not match record digest');
  }

  if (options.requireSingleUse) {
    if (!options.projectionIdRegistry) {
      fail('projection_registry_missing', 'single-use verification requires an atomic projection registry');
    }
    if (!options.projectionIdRegistry.register(value.projection_id)) {
      fail('projection_replay', 'projection identifier was already registered');
    }
  }

  return {
    valid: true,
    verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS',
    projection_id: envelope.projection_id,
    projection_digest: envelope.projection_digest,
    delivered_count: envelope.delivered_count,
    excluded_count: envelope.excluded_count,
  };
}

/**
 * Construct and sign one v1 record from exact source and projection bytes.
 */
export function createMemoryProjectionRecordV1(input: MemoryProjectionProducerInput): {
  record: Obj;
  verificationMaterial: Omit<MemoryProjectionVerificationMaterial, 'verifySourceEntry'>;
} {
  if (!isDataObject(input)) fail('producer_input_invalid', 'producer input is required');
  if (!Array.isArray(input.delivered)) {
    fail('producer_input_invalid', 'producer delivered entries are required');
  }
  const recallRequestBytes = Buffer.from(input.selectionContext.recallRequestBytes);
  const selectionPolicyBytes = Buffer.from(input.selectionContext.selectionPolicyBytes);
  const trustSnapshotBytes = Buffer.from(input.selectionContext.trustSnapshotBytes);
  const sourceObjectBytesByPosition = input.delivered.map((entry) => Buffer.from(entry.sealedObjectBytes));
  const fragmentBytesByPosition = input.delivered.map((entry) => Buffer.from(entry.contextFragmentBytes));
  const projectionBytes = Buffer.concat(fragmentBytesByPosition);
  const byReason = {
    authentication_failed: input.exclusions.authenticationFailed,
    schema_invalid: input.exclusions.schemaInvalid,
    policy_filtered: input.exclusions.policyFiltered,
    context_limit: input.exclusions.contextLimit,
  };
  for (const [reason, count] of Object.entries(byReason)) safeInteger(count, `exclusions.${reason}`);

  const unsigned: Obj = {
    '@version': MEMORY_PROJECTION_RECORD_VERSION,
    source_profile: input.sourceProfile,
    projection_id: input.projectionId,
    created_at: input.createdAt,
    adapter: {
      id: input.adapter.id,
      key_id: input.adapter.keyId,
    },
    selection_context: {
      recall_request_digest: digestBytes(recallRequestBytes),
      selection_policy_digest: digestBytes(selectionPolicyBytes),
      trust_snapshot_digest: digestBytes(trustSnapshotBytes),
      trust_evaluated_at: input.selectionContext.trustEvaluatedAt,
      context_frame_profile: input.selectionContext.contextFrameProfile,
    },
    delivered: input.delivered.map((entry, position) => ({
      position,
      object: {
        format_version: entry.formatVersion,
        sealed_object_digest: digestBytes(sourceObjectBytesByPosition[position]),
      },
      context_fragment_digest: digestBytes(fragmentBytesByPosition[position]),
      derived_trust: entry.derivedTrust,
      authorship: entry.authorship,
      author_key_id_b64u: entry.authorKeyIdB64u,
      custody_present: entry.custodyPresent,
    })),
    exclusions: {
      total: Object.values(byReason).reduce((sum, count) => sum + count, 0),
      by_reason: byReason,
    },
    projection: {
      encoding: 'utf-8',
      byte_length: projectionBytes.length,
      digest: digestBytes(projectionBytes),
    },
    nonclaims: { ...MEMORY_PROJECTION_NONCLAIMS },
  };
  // Validate the complete unsigned body by temporarily supplying a correctly
  // shaped proof. Signature verification itself occurs after signing.
  validateRecordShape({
    ...unsigned,
    proof: {
      alg: 'Ed25519',
      key_id: input.adapter.keyId,
      signature_b64u: Buffer.alloc(64).toString('base64url'),
    },
  });
  const signature = crypto.sign(
    null,
    Buffer.concat([
      Buffer.from(MEMORY_PROJECTION_RECORD_DOMAIN, 'utf8'),
      Buffer.from(canonicalize(unsigned), 'utf8'),
    ]),
    input.privateKey,
  );
  const record = {
    ...unsigned,
    proof: {
      alg: 'Ed25519',
      key_id: input.adapter.keyId,
      signature_b64u: signature.toString('base64url'),
    },
  };
  return {
    record,
    verificationMaterial: {
      recallRequestBytes,
      selectionPolicyBytes,
      trustSnapshotBytes,
      sourceObjectBytesByPosition,
      fragmentBytesByPosition,
      projectionBytes,
    },
  };
}

export function memoryProjectionRecordDigest(record: unknown): string {
  validateRecordShape(record);
  return digestBytes(Buffer.from(canonicalize(record), 'utf8'));
}

export default Object.freeze({
  MEMORY_PROJECTION_RECORD_VERSION,
  MEMORY_PROJECTION_RECORD_DOMAIN,
  createMemoryProjectionRecordV1,
  verifyMemoryProjectionRecordV1Envelope,
  verifyMemoryProjectionRecordV1,
  memoryProjectionRecordDigest,
});
