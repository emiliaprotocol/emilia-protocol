// SPDX-License-Identifier: Apache-2.0
/**
 * Independent Continuum/SOMA producer for EP-PORTABLE-STATE-HANDOFF-v0.1.
 *
 * This producer intentionally imports no EMILIA verifier code. Its separate
 * canonicalizer, descriptor builder, and signature path make byte-level drift
 * visible in the reciprocal round-trip test.
 */
import crypto from 'node:crypto';

const MANIFEST_VERSION = 'EP-STATE-HANDOFF-MANIFEST-v0.1';
const SIGNATURE_PROFILE = 'EP-SIG-AGILITY-v1';
const AUTHORITY_PROFILE = 'EP-STATE-HANDOFF-AUTHORITY-v0.1';
const PAYLOAD_PROFILE = 'EP-STATE-PAYLOAD-SOMA-COGOBJ-v0.1';
const COGOBJ_VERSION = 'SOMA-COGOBJ-v0.1';
const DOMAIN = `${MANIFEST_VERSION}\0`;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;
const LIMITS = Object.freeze({ maxDepth: 64, maxNodes: 100_000, maxStringBytes: 16 * 1024 * 1024 });

function rejectUnpairedSurrogate(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError(`${path}: unpaired surrogate`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new TypeError(`${path}: unpaired surrogate`);
  }
}

function canonical(
  value,
  path = '$',
  ancestors = new Set(),
  state = { nodes: 0, stringBytes: 0 },
  depth = 0,
) {
  state.nodes += 1;
  if (state.nodes > LIMITS.maxNodes) throw new TypeError(`${path}: node count exceeds ${LIMITS.maxNodes}`);
  if (depth > LIMITS.maxDepth) throw new TypeError(`${path}: depth exceeds ${LIMITS.maxDepth}`);
  if (value === null) return 'null';
  if (typeof value === 'string') {
    rejectUnpairedSurrogate(value, path);
    state.stringBytes += Buffer.byteLength(value, 'utf8');
    if (state.stringBytes > LIMITS.maxStringBytes) {
      throw new TypeError(`${path}: string bytes exceed ${LIMITS.maxStringBytes}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError(`${path}: unsafe number`);
    return JSON.stringify(value);
  }
  if (typeof value !== 'object') throw new TypeError(`${path}: not strict JSON`);
  if (ancestors.has(value)) throw new TypeError(`${path}: cyclic value`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      const expectedKeys = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
      if (ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))
          || ownKeys.length !== expectedKeys.size) {
        throw new TypeError(`${path}: sparse array or extra member`);
      }
      const entries = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
          throw new TypeError(`${path}[${index}]: accessor or missing member`);
        }
        entries.push(canonical(
          descriptor.value,
          `${path}[${index}]`,
          ancestors,
          state,
          depth + 1,
        ));
      }
      return `[${entries.join(',')}]`;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError(`${path}: non-plain object`);
    const keys = Reflect.ownKeys(value);
    const stringKeys = keys.filter((key) => typeof key === 'string');
    if (stringKeys.length !== keys.length) throw new TypeError(`${path}: symbol member`);
    return `{${stringKeys.sort().map((key) => {
      rejectUnpairedSurrogate(key, `${path}: member name`);
      state.stringBytes += Buffer.byteLength(key, 'utf8');
      if (state.stringBytes > LIMITS.maxStringBytes) {
        throw new TypeError(`${path}.${key}: string bytes exceed ${LIMITS.maxStringBytes}`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError(`${path}.${key}: accessor or hidden member`);
      }
      return `${JSON.stringify(key)}:${canonical(
        descriptor.value,
        `${path}.${key}`,
        ancestors,
        state,
        depth + 1,
      )}`;
    }).join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`;
}

function text(value, name, maximum = 2048) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum
      || /[\u0000-\u001f\u007f]/.test(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function time(value, name) {
  text(value, name, 64);
  const match = RFC3339.exec(value);
  if (!match) throw new TypeError(`${name} is not RFC 3339 UTC`);
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > (days[month - 1] ?? 0)
      || hour > 23 || minute > 59 || second > 59) {
    throw new TypeError(`${name} is not RFC 3339 UTC`);
  }
  return value;
}

function digestOrNull(value, name) {
  if (value !== null && (typeof value !== 'string' || !SHA256.test(value))) throw new TypeError(`${name} is invalid`);
  return value;
}

function normalizeCogobj(input) {
  const object = {
    '@version': COGOBJ_VERSION,
    object_id: text(input?.object_id, 'object_id'),
    domain: text(input?.domain, 'domain'),
    schema_uri: text(input?.schema_uri, 'schema_uri'),
    snapshot: {
      asserted_at: time(input?.snapshot?.asserted_at, 'snapshot.asserted_at'),
      source_mutability: input?.snapshot?.source_mutability,
      observed_at: input?.snapshot?.observed_at,
      freshness_basis_digest: input?.snapshot?.freshness_basis_digest,
    },
    sensitivity: input?.sensitivity,
    protection: {
      mode: input?.protection?.mode,
      profile: input?.protection?.profile,
      key_reference_digest: input?.protection?.key_reference_digest,
    },
    disposition: input?.disposition,
    origin: {
      assertion_class: input?.origin?.assertion_class,
      issuer: text(input?.origin?.issuer, 'origin.issuer'),
      asserted_at: time(input?.origin?.asserted_at, 'origin.asserted_at'),
      source_digest: digestOrNull(input?.origin?.source_digest, 'origin.source_digest'),
      transform_id: input?.origin?.transform_id,
    },
    lineage: {
      generation: input?.lineage?.generation,
      predecessor_digest: digestOrNull(input?.lineage?.predecessor_digest, 'lineage.predecessor_digest'),
    },
    authority_semantics: input?.authority_semantics,
    content: structuredClone(input?.content),
  };
  if (!['IMMUTABLE', 'MUTABLE', 'UNKNOWN'].includes(object.snapshot.source_mutability)) {
    throw new TypeError('snapshot.source_mutability is invalid');
  }
  if (object.snapshot.observed_at !== null) time(object.snapshot.observed_at, 'snapshot.observed_at');
  digestOrNull(object.snapshot.freshness_basis_digest, 'snapshot.freshness_basis_digest');
  if ((object.snapshot.observed_at === null) !== (object.snapshot.freshness_basis_digest === null)) {
    throw new TypeError('snapshot freshness pair is invalid');
  }
  if (object.snapshot.observed_at !== null
      && Date.parse(object.snapshot.observed_at) > Date.parse(object.snapshot.asserted_at)) {
    throw new TypeError('snapshot observation is after assertion');
  }
  if (Date.parse(object.origin.asserted_at) > Date.parse(object.snapshot.asserted_at)) {
    throw new TypeError('origin assertion is after snapshot');
  }
  if (!['OPEN', 'PROTECTED', 'VAULT'].includes(object.sensitivity)) throw new TypeError('sensitivity is invalid');
  if (!['ACTIVE', 'TOMBSTONE'].includes(object.disposition)) throw new TypeError('disposition is invalid');
  if (!['PLAINTEXT', 'OPAQUE-CIPHERTEXT'].includes(object.protection.mode)) throw new TypeError('protection mode is invalid');
  if (object.protection.profile !== null) text(object.protection.profile, 'protection.profile');
  digestOrNull(object.protection.key_reference_digest, 'protection.key_reference_digest');
  if (!['operator-pinned', 'approver-supplied', 'agent-generated', 'imported', 'derived']
    .includes(object.origin.assertion_class)) throw new TypeError('origin.assertion_class is invalid');
  if (object.origin.transform_id !== null) text(object.origin.transform_id, 'origin.transform_id');
  if (!Number.isSafeInteger(object.lineage.generation) || object.lineage.generation < 0) {
    throw new TypeError('lineage.generation is invalid');
  }
  if (object.lineage.generation === 0 && object.lineage.predecessor_digest !== null) {
    throw new TypeError('root predecessor is invalid');
  }
  if (object.lineage.generation > 0 && object.lineage.predecessor_digest === null) {
    throw new TypeError('non-root predecessor is missing');
  }
  if (object.authority_semantics !== 'NONE') throw new TypeError('authority_semantics must be NONE');
  if (object.disposition === 'TOMBSTONE' && object.content !== null) throw new TypeError('tombstone content must be null');
  if (object.sensitivity === 'VAULT' && object.disposition === 'ACTIVE'
      && object.protection.mode !== 'OPAQUE-CIPHERTEXT') throw new TypeError('VAULT plaintext is prohibited');
  canonical(object.content);
  return object;
}

export async function exportPortableSomaState(input) {
  for (const field of [
    'handoff_id', 'source_agent', 'source_boundary_id', 'recipient_agent',
    'recipient_boundary_id', 'relying_party_id', 'nonce',
  ]) {
    text(input?.[field], field, field === 'nonce' ? 256 : 2048);
  }
  for (const field of ['created_at', 'snapshot_at', 'expires_at']) time(input?.[field], field);
  if (Date.parse(input.snapshot_at) > Date.parse(input.created_at)
      || Date.parse(input.created_at) >= Date.parse(input.expires_at)) throw new TypeError('time order is invalid');
  if (!Array.isArray(input.objects) || input.objects.length === 0 || input.objects.length > 4096) {
    throw new TypeError('objects must contain 1..4096 members');
  }
  if (!Array.isArray(input.optional_object_ids)) throw new TypeError('optional_object_ids must be an array');
  const optional = new Set(input.optional_object_ids);
  if (optional.size !== input.optional_object_ids.length) throw new TypeError('duplicate optional object id');
  const objects = input.objects.map(normalizeCogobj).sort((left, right) => left.object_id.localeCompare(right.object_id));
  if (new Set(objects.map((entry) => entry.object_id)).size !== objects.length) throw new TypeError('duplicate object id');
  if (objects.some((entry) => Date.parse(entry.snapshot.asserted_at) > Date.parse(input.snapshot_at))) {
    throw new TypeError('object snapshot is after manifest cut');
  }
  for (const id of optional) if (!objects.some((entry) => entry.object_id === id)) throw new TypeError('unknown optional object');

  const descriptors = objects.map((object, position) => ({
    position,
    object_id: object.object_id,
    object_digest: digest(object),
    media_type: 'application/soma-cogobj+json',
    schema_uri: object.schema_uri,
    required: !optional.has(object.object_id),
    snapshot_at: object.snapshot.asserted_at,
    sensitivity: object.sensitivity,
    disposition: object.disposition,
    generation: object.lineage.generation,
    predecessor_digest: object.lineage.predecessor_digest,
  }));
  const indexDigest = digest(descriptors);
  const sourceActions = ['agent.state.export.1'];
  if (descriptors.some((entry) => entry.sensitivity === 'VAULT')) sourceActions.push('agent.state.key-release.1');
  const scopeDigest = digest({
    transfer_mode: 'COPY',
    payload_profile: PAYLOAD_PROFILE,
    source_agent: input.source_agent,
    source_boundary_id: input.source_boundary_id,
    recipient_agent: input.recipient_agent,
    recipient_boundary_id: input.recipient_boundary_id,
    relying_party_id: input.relying_party_id,
    index_digest: indexDigest,
  });
  const unsigned = {
    '@version': MANIFEST_VERSION,
    handoff_id: input.handoff_id,
    transfer_mode: 'COPY',
    payload_profile: PAYLOAD_PROFILE,
    source_agent: input.source_agent,
    source_boundary_id: input.source_boundary_id,
    recipient_agent: input.recipient_agent,
    recipient_boundary_id: input.recipient_boundary_id,
    relying_party_id: input.relying_party_id,
    created_at: input.created_at,
    snapshot_at: input.snapshot_at,
    expires_at: input.expires_at,
    nonce: input.nonce,
    index: { ordered_object_ids: descriptors.map((entry) => entry.object_id), index_digest: indexDigest },
    objects: descriptors,
    scope_digest: scopeDigest,
    authority: {
      profile: AUTHORITY_PROFILE,
      source_actions: sourceActions,
      recipient_action: 'agent.state.import.1',
    },
    nonclaims: {
      source_truth: 'NOT_ESTABLISHED',
      authority_transfer: 'PROHIBITED',
      source_population_completeness: 'NOT_ESTABLISHED',
      physical_erasure: 'NOT_ESTABLISHED',
      trusted_time: 'NOT_ESTABLISHED',
    },
    signature_policy: { profile: SIGNATURE_PROFILE, required_algorithms: ['Ed25519'] },
  };
  text(input?.signer?.key_id, 'signer.key_id');
  if (!input?.signer?.private_key) throw new TypeError('signer.private_key is required');
  const signature = crypto.sign(
    null,
    Buffer.concat([Buffer.from(DOMAIN, 'utf8'), Buffer.from(canonical(unsigned), 'utf8')]),
    input.signer.private_key,
  ).toString('base64url');
  return {
    manifest: {
      ...unsigned,
      signatures: [{ alg: 'Ed25519', sig: signature, key_id: input.signer.key_id }],
    },
    objects,
    source_authority_evidence: {},
  };
}

export const independentDigest = digest;
