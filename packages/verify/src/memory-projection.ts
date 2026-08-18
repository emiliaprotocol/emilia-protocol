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

import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgilityOptions,
} from './pq-signature-agility.js';

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

// ===========================================================================
// EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 -- an EP-side, DETACHED hybrid
// co-signature over an UNCHANGED MEMORY-PROJECTION-RECORD-v1
// ===========================================================================
/**
 * THE WIRE ABOVE IS NOT EP'S TO BUMP, AND IS NOT BUMPED HERE.
 *
 * MEMORY-PROJECTION-RECORD-v1 is the wire format of
 * draft-ferro-schrock-memory-projection-record-00, co-authored with Andrea
 * Ferro. Everything above this line is byte-for-byte unchanged: the closed
 * record shape, the `proof: { alg, key_id, signature_b64u }` object, the
 * `alg: 'Ed25519'` pin, `MEMORY_PROJECTION_RECORD_DOMAIN`, the producer, and
 * both verifiers. No `@version` was bumped and no member was added, because a
 * unilateral change to a co-authored wire is not a migration, it is a fork.
 *
 * WHAT A -01 OF THE JOINT DRAFT WOULD NEED, precisely, for a real in-record
 * hybrid migration (this is the ask to take to the co-author, not something
 * this file can decide):
 *
 *   a. `proof` becomes SET-SHAPED: `{ required_algorithms: [...],
 *      signatures: [{ alg, sig, key_id }] }`. That changes the closed proof
 *      key set, so it is a wire-format change.
 *   b. The draft needs a REGISTERED value for the post-quantum `proof.alg`.
 *      The draft today admits only `Ed25519`. This repository can trace exactly
 *      one ML-DSA-65 algorithm identifier, and it is the COSE one (-49, RFC
 *      9964, see packages/verify/src/aeb-mcgraw-delegation-adapter.ts); there
 *      is no JSON/JOSE-side identifier here to reuse, so the draft must name
 *      its own or normatively reference one.
 *   c. `required_algorithms` must be a SIGNED top-level record member (inside
 *      the JCS boundary that `signingBytes` covers), not a member of `proof`,
 *      or the set is not committed and leg-stripping is only detected by
 *      relying-party policy.
 *   d. `@version` becomes `MEMORY-PROJECTION-RECORD-v2`, because (a) and (c)
 *      change the shape, and the v1 verifier must refuse a v2 record on the
 *      version marker.
 *   e. `apertomemory-context.ts` moves in lockstep: it re-checks
 *      `record.proof.alg !== 'Ed25519'` and the 64-byte signature length
 *      independently of this module.
 *
 * WHAT THIS SECTION IS INSTEAD. A purely ADDITIVE, EP-owned, DETACHED
 * co-signature. It travels beside a v1 record, never inside it. A producer that
 * emits one is still emitting an ordinary v1 record that every existing
 * ApertoMemory and EP verifier accepts unchanged; a verifier that ignores it
 * loses nothing it had.
 *
 * THE HONEST LIMIT, stated before the API rather than after it. The v1 record's
 * own signed bytes do not commit to any algorithm set, and this co-signature
 * cannot retroactively make them. So:
 *   - A relying party that requires the co-signature gets a real hybrid
 *     guarantee over the exact record bytes, because both legs sign a
 *     commitment to those bytes AND to the required set.
 *   - A relying party that does NOT ask for it sees a valid v1 record and has
 *     gained nothing. Requiring the PQ leg here is a PIN, not a property of the
 *     artifact. This profile makes the pin available; it cannot make a verifier
 *     that never asks for it.
 *   - This is the same shape and the same limit as EP-COMMIT-HYBRID-v1
 *     (lib/commit-hybrid.ts), and it is stated the same way on purpose.
 *
 * Opt-in. Not deployed, default, or certified anywhere.
 */

export const MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION = 'EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1';
export const MEMORY_PROJECTION_PQ_COSIGNATURE_DOMAIN = `${MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const COSIGNATURE_KEYS = new Set([
  '@version', 'record_version', 'projection_id', 'record_signing_bytes_sha256',
  'record_proof_signature_b64u', 'proof',
]);
const COSIGNATURE_PROOF_KEYS = new Set([
  'profile', 'required_algorithms', 'key_id', 'public_key', 'pq_key_id', 'pq_public_key', 'signatures',
]);

export interface MemoryProjectionPqCosignatureBody {
  '@version': typeof MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION;
  record_version: typeof MEMORY_PROJECTION_RECORD_VERSION;
  projection_id: string;
  /** sha256 over the EXACT bytes the v1 record's own Ed25519 proof covers. */
  record_signing_bytes_sha256: string;
  /** The exact v1 `proof.signature_b64u` this co-signature is bound to. */
  record_proof_signature_b64u: string;
}

export interface MemoryProjectionPqCosignature extends MemoryProjectionPqCosignatureBody {
  proof: {
    profile: string;
    required_algorithms: string[];
    key_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    pq_key_id: string;
    /** ML-DSA-65 base64url raw 1952-byte public key. */
    pq_public_key: string;
    signatures: Array<{ alg: string; sig: string; key_id?: string }>;
  };
}

export interface MemoryProjectionPqCosignaturePin {
  key_id: string;
  public_key: string;
  pq_key_id: string;
  pq_public_key: string;
}

export interface MemoryProjectionPqCosignatureSigner {
  key_id: string;
  private_key: crypto.KeyObject;
  public_key: string;
  pq_key_id: string;
  pq_secret_key: Uint8Array | string;
  pq_public_key: string;
}

export interface MemoryProjectionPqCosignatureResult {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
}

function pqCosignatureSetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS[i]);
}

/**
 * The bytes BOTH legs sign: the domain tag, the co-signature body, and the
 * REGISTERED algorithm set. The verifier rebuilds these from the body it
 * re-derived and the REGISTERED set, never from what the co-signature claims.
 */
export function memoryProjectionPqCosignatureSigningBytes(
  body: MemoryProjectionPqCosignatureBody,
  requiredAlgorithms: readonly string[] = MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS,
): Buffer {
  if (!pqCosignatureSetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('memoryProjectionPqCosignatureSigningBytes: algorithm set is not the registered EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1 set');
  }
  return Buffer.concat([
    Buffer.from(MEMORY_PROJECTION_PQ_COSIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(canonicalize({ ...body, required_algorithms: [...requiredAlgorithms] }), 'utf8'),
  ]);
}

/**
 * Derive the co-signature body from an UNCHANGED v1 record. Throws a
 * MemoryProjectionVerificationError if the record is not a valid v1 record --
 * a co-signature is never minted over something that is not one.
 */
export function memoryProjectionPqCosignatureBody(record: unknown): MemoryProjectionPqCosignatureBody {
  validateRecordShape(record);
  const value = record as Obj;
  return {
    '@version': MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION,
    record_version: MEMORY_PROJECTION_RECORD_VERSION,
    projection_id: String(value.projection_id),
    record_signing_bytes_sha256: digestBytes(signingBytes(value)),
    record_proof_signature_b64u: String((value.proof as Obj).signature_b64u),
  };
}

/**
 * Sign a detached hybrid co-signature over an unchanged v1 record. Issuer-side
 * misuse throws; an unavailable ML-DSA backend throws rather than emitting a
 * one-legged co-signature.
 */
export async function signMemoryProjectionPqCosignature(
  record: unknown,
  signer: MemoryProjectionPqCosignatureSigner,
  options: AgilityOptions = {},
): Promise<MemoryProjectionPqCosignature> {
  if (!signer || typeof signer !== 'object'
      || typeof signer.key_id !== 'string' || signer.key_id.length === 0
      || typeof signer.pq_key_id !== 'string' || signer.pq_key_id.length === 0
      || !(signer.private_key instanceof crypto.KeyObject)
      || signer.private_key.type !== 'private'
      || signer.private_key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('Ed25519 + ML-DSA-65 memory-projection co-signer required');
  }
  const body = memoryProjectionPqCosignatureBody(record);
  const signatures = await signAgileSet(
    new Uint8Array(memoryProjectionPqCosignatureSigningBytes(body)),
    [
      { alg: 'Ed25519', private_key: signer.private_key, key_id: signer.key_id },
      { alg: 'ML-DSA-65', private_key: signer.pq_secret_key, key_id: signer.pq_key_id },
    ],
    options,
  );
  return {
    ...body,
    proof: {
      profile: MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION,
      required_algorithms: [...MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS],
      key_id: signer.key_id,
      public_key: String(signer.public_key),
      pq_key_id: signer.pq_key_id,
      pq_public_key: String(signer.pq_public_key),
      signatures: signatures.map((s) => ({ alg: s.alg, sig: s.sig, key_id: s.key_id })),
    },
  };
}

/**
 * verifyMemoryProjectionPqCosignature -- FAIL-CLOSED. Never throws on caller
 * input. The co-signature is checked AGAINST the record the relying party
 * holds: the body is re-derived from that record, so a co-signature minted over
 * a different record cannot be presented for this one.
 *
 * This does NOT verify the v1 record itself. Run
 * verifyMemoryProjectionRecordV1Envelope (or the full verifier) for that; this
 * is strictly the additional post-quantum leg.
 */
export async function verifyMemoryProjectionPqCosignature(
  record: unknown,
  cosignature: unknown,
  pin: MemoryProjectionPqCosignaturePin | null | undefined,
  options: AgilityOptions = {},
): Promise<MemoryProjectionPqCosignatureResult> {
  const checks: Record<string, boolean> = {
    structure: true,
    version: true,
    algorithm_set: true,
    legs_present: true,
    cosigner_key_pinned: true,
    bound_to_record: true,
    signature_valid: true,
  };
  const errors: string[] = [];
  const fail_ = (key: string, msg: string) => { checks[key] = false; errors.push(msg); };
  const done = (): MemoryProjectionPqCosignatureResult =>
    ({ valid: Object.values(checks).every(Boolean), checks, errors });

  if (!isDataObject(cosignature)) {
    fail_('structure', 'no co-signature presented (fail-closed)');
    fail_('signature_valid', 'no co-signature presented (fail-closed)');
    return done();
  }
  if (cosignature['@version'] !== MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION) {
    fail_('version', `unsupported version: ${String(cosignature['@version'])}`);
  }
  const keys = Object.keys(cosignature);
  if (keys.length !== COSIGNATURE_KEYS.size || keys.some((k) => !COSIGNATURE_KEYS.has(k))
      || !isDataObject(cosignature.proof)) {
    fail_('structure', `co-signature must use the exact closed ${MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION} schema`);
    fail_('signature_valid', 'co-signature shape refused before any signature was inspected');
    return done();
  }
  const proof = cosignature.proof as Obj;
  const proofKeys = Object.keys(proof);
  if (proofKeys.length !== COSIGNATURE_PROOF_KEYS.size
      || proofKeys.some((k) => !COSIGNATURE_PROOF_KEYS.has(k))
      || proof.profile !== MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION) {
    fail_('structure', 'co-signature proof must use the exact closed schema and profile marker');
  }
  if (!pqCosignatureSetMatchesRegistered(proof.required_algorithms)) {
    fail_('algorithm_set',
      `proof.required_algorithms must be exactly ${JSON.stringify([...MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
  }

  const signatures = Array.isArray(proof.signatures) ? proof.signatures as Obj[] : null;
  if (!signatures || signatures.length === 0) {
    fail_('legs_present', 'proof.signatures must carry one signature per required algorithm');
  } else {
    const presented = new Set<string>();
    let malformed = false;
    for (const s of signatures) {
      if (!isDataObject(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        fail_('legs_present', 'each proof.signatures entry must be { alg, sig, key_id? }');
        malformed = true;
        break;
      }
      if (presented.has(s.alg)) {
        fail_('legs_present', `duplicate signature for algorithm "${s.alg}"`);
        malformed = true;
        break;
      }
      presented.add(s.alg);
    }
    if (!malformed) {
      for (const alg of MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) fail_('legs_present', `missing required ${alg} signature (leg stripped)`);
      }
      for (const alg of presented) {
        if (!(MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
          fail_('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
        }
      }
    }
  }

  const pinnedEd = pin && typeof pin.public_key === 'string' ? pin.public_key : '';
  const pinnedPq = pin && typeof pin.pq_public_key === 'string' ? pin.pq_public_key : '';
  if (!pinnedEd || !pinnedPq || typeof pin?.key_id !== 'string' || typeof pin?.pq_key_id !== 'string') {
    fail_('cosigner_key_pinned',
      'a pinned Ed25519 + ML-DSA-65 co-signer key pair is required (identified but not trusted)');
  } else {
    let edOk = false;
    try {
      const k = crypto.createPublicKey({
        key: Buffer.from(pinnedEd, 'base64url'), format: 'der', type: 'spki',
      });
      edOk = k.asymmetricKeyType === 'ed25519';
    } catch { edOk = false; }
    if (!edOk) fail_('cosigner_key_pinned', 'pinned Ed25519 co-signer key is not a canonical Ed25519 SPKI');
    if (Buffer.from(pinnedPq, 'base64url').length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
      fail_('cosigner_key_pinned', `pinned ML-DSA-65 key must be ${ML_DSA_65_PUBLIC_KEY_BYTES} raw bytes, base64url`);
    }
    if (proof.public_key !== pinnedEd || proof.pq_public_key !== pinnedPq
        || proof.key_id !== pin.key_id || proof.pq_key_id !== pin.pq_key_id) {
      fail_('cosigner_key_pinned', 'presented co-signer key material != pinned key material (key substitution)');
    }
  }

  // Re-derive the body from the record the RELYING PARTY holds. A co-signature
  // minted over a different record cannot be replayed onto this one, and the
  // exact v1 proof signature is part of the binding, so a re-signed record with
  // identical body bytes is still a different artifact.
  let expectedBody: MemoryProjectionPqCosignatureBody | null = null;
  try {
    expectedBody = memoryProjectionPqCosignatureBody(record);
  } catch {
    expectedBody = null;
  }
  if (!expectedBody) {
    fail_('bound_to_record', 'the presented record is not a valid MEMORY-PROJECTION-RECORD-v1');
    fail_('signature_valid', 'no valid record to bind the co-signature to');
    return done();
  }
  if (cosignature.record_version !== expectedBody.record_version
      || cosignature.projection_id !== expectedBody.projection_id
      || cosignature.record_signing_bytes_sha256 !== expectedBody.record_signing_bytes_sha256
      || cosignature.record_proof_signature_b64u !== expectedBody.record_proof_signature_b64u) {
    fail_('bound_to_record', 'co-signature does not bind the presented record');
  }

  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(memoryProjectionPqCosignatureSigningBytes(
        expectedBody, MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS,
      )),
      signatures ?? [],
      [
        { alg: 'Ed25519', public_key: pinnedEd, key_id: pin?.key_id },
        { alg: 'ML-DSA-65', public_key: pinnedPq, key_id: pin?.pq_key_id },
      ],
      {
        ...options,
        policy: 'hybrid_all',
        requiredAlgorithms: [...MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS],
      },
    );
  } catch {
    setResult = null;
  }
  if (setResult?.verified !== true) {
    fail_('signature_valid',
      `co-signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${String(setResult?.reason ?? 'signature_set_unverified')})`);
  }

  return done();
}
