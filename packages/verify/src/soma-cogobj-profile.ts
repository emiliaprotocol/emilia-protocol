// SPDX-License-Identifier: Apache-2.0
/** SOMA/COGOBJ payload adapter for EP-PORTABLE-STATE-HANDOFF-v0.1. */
import { canonicalizeStrictJson } from './strict-json.js';
import {
  PORTABLE_STATE_LIMITS,
  stateHandoffDigest,
  type StateDigest,
  type StateObjectDescriptor,
  type StatePayloadAdapter,
  type StateSensitivity,
  type StateDisposition,
} from './portable-state-handoff.js';

export const SOMA_COGOBJ_VERSION = 'SOMA-COGOBJ-v0.1';
export const SOMA_COGOBJ_PAYLOAD_PROFILE = 'EP-STATE-PAYLOAD-SOMA-COGOBJ-v0.1';

type Obj = Record<string, unknown>;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const B64U = /^[A-Za-z0-9_-]+$/;

export interface SomaCogobj {
  '@version': typeof SOMA_COGOBJ_VERSION;
  object_id: string;
  domain: string;
  schema_uri: string;
  snapshot: {
    asserted_at: string;
    source_mutability: 'IMMUTABLE' | 'MUTABLE' | 'UNKNOWN';
    observed_at: string | null;
    freshness_basis_digest: StateDigest | null;
  };
  sensitivity: StateSensitivity;
  protection: {
    mode: 'PLAINTEXT' | 'OPAQUE-CIPHERTEXT';
    profile: string | null;
    key_reference_digest: StateDigest | null;
  };
  disposition: StateDisposition;
  origin: {
    assertion_class: 'operator-pinned' | 'approver-supplied' | 'agent-generated' | 'imported' | 'derived';
    issuer: string;
    asserted_at: string;
    source_digest: StateDigest | null;
    transform_id: string | null;
  };
  lineage: {
    generation: number;
    predecessor_digest: StateDigest | null;
  };
  authority_semantics: 'NONE';
  content: unknown;
}

const OBJECT_KEYS = new Set([
  '@version', 'object_id', 'domain', 'schema_uri', 'snapshot', 'sensitivity',
  'protection', 'disposition', 'origin', 'lineage', 'authority_semantics', 'content',
]);
const SNAPSHOT_KEYS = new Set(['asserted_at', 'source_mutability', 'observed_at', 'freshness_basis_digest']);
const PROTECTION_KEYS = new Set(['mode', 'profile', 'key_reference_digest']);
const ORIGIN_KEYS = new Set(['assertion_class', 'issuer', 'asserted_at', 'source_digest', 'transform_id']);
const LINEAGE_KEYS = new Set(['generation', 'predecessor_digest']);
const CIPHERTEXT_KEYS = new Set(['ciphertext_b64u']);

function object(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exact(value: unknown, keys: Set<string>): value is Obj {
  if (!object(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.size && actual.every((key) => keys.has(key));
}

function text(value: unknown, max = 2048): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function time(value: unknown): value is string {
  if (!text(value, 64)) return false;
  const match = RFC3339_UTC.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= days[month - 1];
}

function digest(value: unknown): value is StateDigest {
  return typeof value === 'string' && SHA256.test(value);
}

function base64url(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || !B64U.test(value) || value.length % 4 === 1) return false;
  try { return Buffer.from(value, 'base64url').toString('base64url') === value; } catch { return false; }
}

export function validateSomaCogobj(value: unknown): { valid: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const add = (entry: string) => { if (!reasons.includes(entry)) reasons.push(entry); };
  if (!exact(value, OBJECT_KEYS)
      || value['@version'] !== SOMA_COGOBJ_VERSION
      || !text(value.object_id)
      || !text(value.domain)
      || !text(value.schema_uri)
      || !exact(value.snapshot, SNAPSHOT_KEYS)
      || !time(value.snapshot.asserted_at)
      || !['IMMUTABLE', 'MUTABLE', 'UNKNOWN'].includes(value.snapshot.source_mutability as string)
      || !(value.snapshot.observed_at === null || time(value.snapshot.observed_at))
      || !(value.snapshot.freshness_basis_digest === null || digest(value.snapshot.freshness_basis_digest))
      || !['OPEN', 'PROTECTED', 'VAULT'].includes(value.sensitivity as string)
      || !exact(value.protection, PROTECTION_KEYS)
      || !['PLAINTEXT', 'OPAQUE-CIPHERTEXT'].includes(value.protection.mode as string)
      || !(value.protection.profile === null || text(value.protection.profile))
      || !(value.protection.key_reference_digest === null || digest(value.protection.key_reference_digest))
      || !['ACTIVE', 'TOMBSTONE'].includes(value.disposition as string)
      || !exact(value.origin, ORIGIN_KEYS)
      || !['operator-pinned', 'approver-supplied', 'agent-generated', 'imported', 'derived']
        .includes(value.origin.assertion_class as string)
      || !text(value.origin.issuer)
      || !time(value.origin.asserted_at)
      || !(value.origin.source_digest === null || digest(value.origin.source_digest))
      || !(value.origin.transform_id === null || text(value.origin.transform_id))
      || !exact(value.lineage, LINEAGE_KEYS)
      || !Number.isSafeInteger(value.lineage.generation)
      || (value.lineage.generation as number) < 0
      || !(value.lineage.predecessor_digest === null || digest(value.lineage.predecessor_digest))
      || value.authority_semantics !== 'NONE') {
    add('soma_cogobj_schema_invalid');
    return { valid: false, reasons };
  }

  const snapshotPair = value.snapshot.observed_at === null
    ? value.snapshot.freshness_basis_digest === null
    : value.snapshot.freshness_basis_digest !== null;
  if (!snapshotPair) add('snapshot_freshness_pair_invalid');
  if (value.snapshot.observed_at !== null
      && Date.parse(value.snapshot.observed_at) > Date.parse(value.snapshot.asserted_at)) {
    add('snapshot_observation_after_assertion');
  }
  if (Date.parse(value.origin.asserted_at) > Date.parse(value.snapshot.asserted_at)) {
    add('origin_assertion_after_snapshot');
  }
  if (value.lineage.generation === 0 && value.lineage.predecessor_digest !== null) add('lineage_root_invalid');
  if ((value.lineage.generation as number) > 0 && value.lineage.predecessor_digest === null) add('lineage_predecessor_missing');
  if (value.disposition === 'TOMBSTONE') {
    if (value.content !== null) add('tombstone_content_present');
  } else if (value.protection.mode === 'OPAQUE-CIPHERTEXT') {
    if (!text(value.protection.profile)
        || !digest(value.protection.key_reference_digest)
        || !exact(value.content, CIPHERTEXT_KEYS)
        || !base64url(value.content.ciphertext_b64u)) add('ciphertext_envelope_invalid');
  } else if (value.protection.profile !== null || value.protection.key_reference_digest !== null) {
    add('plaintext_protection_metadata_invalid');
  }
  if (value.sensitivity === 'VAULT' && value.disposition === 'ACTIVE'
      && value.protection.mode !== 'OPAQUE-CIPHERTEXT') add('vault_plaintext_prohibited');
  try {
    canonicalizeStrictJson(value.content, {
      maxDepth: PORTABLE_STATE_LIMITS.max_depth,
      maxNodes: PORTABLE_STATE_LIMITS.max_nodes,
      maxStringBytes: PORTABLE_STATE_LIMITS.max_string_bytes,
    });
  } catch {
    add('soma_content_not_strict_json');
  }
  return { valid: reasons.length === 0, reasons };
}

export const somaCogobjPayloadAdapter: StatePayloadAdapter = Object.freeze({
  profile: SOMA_COGOBJ_PAYLOAD_PROFILE,
  validateObject(value: unknown, descriptor: Readonly<StateObjectDescriptor>) {
    const checked = validateSomaCogobj(value);
    if (!checked.valid) return { status: 'REFUSED' as const, reasons: checked.reasons };
    const cogobj = value as SomaCogobj;
    const matches = cogobj.object_id === descriptor.object_id
      && cogobj.schema_uri === descriptor.schema_uri
      && cogobj.snapshot.asserted_at === descriptor.snapshot_at
      && cogobj.sensitivity === descriptor.sensitivity
      && cogobj.disposition === descriptor.disposition
      && cogobj.lineage.generation === descriptor.generation
      && cogobj.lineage.predecessor_digest === descriptor.predecessor_digest
      && stateHandoffDigest(cogobj) === descriptor.object_digest;
    return matches
      ? { status: 'VALID' as const }
      : { status: 'REFUSED' as const, reasons: ['payload_descriptor_mismatch'] };
  },
});
