// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { canonicalize } from '../../lib/canonical-json.js';

export const TRUST_RESULT_DOMAIN = Buffer.from(
  'AMEM-EMILIA-TRUST-CUSTODY-RESULT-v0\0',
  'utf8',
);
export const PROJECTION_DOMAIN = Buffer.from(
  'AMEM-EMILIA-PROJECTION-RECORD-v0\0',
  'utf8',
);

const NONCLAIMS = Object.freeze({
  model_use: 'NOT_ESTABLISHED',
  action_linkage: 'NOT_ESTABLISHED',
  action_authorization: 'NOT_ESTABLISHED',
  execution_outcome: 'NOT_ESTABLISHED',
});

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function fail(message) {
  throw new Error(message);
}

function object(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${path} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, path) {
  const actual = Object.keys(object(value, path)).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
    fail(`${path} fields must be exactly: ${wanted.join(', ')}`);
  }
}

function oneOf(value, allowed, path) {
  if (!allowed.includes(value)) fail(`${path} must be one of: ${allowed.join(', ')}`);
}

function nonEmpty(value, path) {
  if (typeof value !== 'string' || value.length === 0) fail(`${path} must be a non-empty string`);
}

function integer(value, path, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${path} must be a safe integer >= ${minimum}`);
  }
}

function dateTime(value, path) {
  if (typeof value !== 'string' || !DATE_TIME_RE.test(value) || Number.isNaN(Date.parse(value))) {
    fail(`${path} must be an RFC 3339 UTC timestamp`);
  }
}

function digest(value, path) {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    fail(`${path} must be a lowercase sha256 digest`);
  }
}

function urn(value, path) {
  if (typeof value !== 'string' || !/^urn:[A-Za-z0-9][A-Za-z0-9:.\-]+$/.test(value)) {
    fail(`${path} must be a URN`);
  }
}

function b64uBytes(value, length, path) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail(`${path} must be unpadded base64url`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== length || decoded.toString('base64url') !== value) {
    fail(`${path} must encode exactly ${length} bytes`);
  }
}

function nullableB64u(value, length, path) {
  if (value !== null) b64uBytes(value, length, path);
}

function validateObjectRef(value, path) {
  exactKeys(value, ['format_version', 'sealed_object_digest'], path);
  if (value.format_version !== 2) fail(`${path}.format_version must be 2`);
  digest(value.sealed_object_digest, `${path}.sealed_object_digest`);
}

function validateAdapter(value, path) {
  exactKeys(value, ['id', 'key_id'], path);
  urn(value.id, `${path}.id`);
  nonEmpty(value.key_id, `${path}.key_id`);
}

function validateNonclaims(value, path) {
  exactKeys(value, Object.keys(NONCLAIMS), path);
  for (const [key, expected] of Object.entries(NONCLAIMS)) {
    if (value[key] !== expected) fail(`${path}.${key} must be ${expected}`);
  }
}

function recordWithoutProof(record) {
  const { proof: _proof, ...unsigned } = record;
  return unsigned;
}

function signingInput(domain, record) {
  return Buffer.concat([domain, Buffer.from(canonicalize(recordWithoutProof(record)), 'utf8')]);
}

function publicKeyFor(pinnedKeys, keyId) {
  const encoded = pinnedKeys instanceof Map ? pinnedKeys.get(keyId) : pinnedKeys?.[keyId];
  if (typeof encoded !== 'string') fail(`proof.key_id ${keyId} is not pinned by the relying party`);
  try {
    return crypto.createPublicKey({ key: Buffer.from(encoded, 'base64url'), format: 'der', type: 'spki' });
  } catch {
    fail(`pinned adapter key ${keyId} is not a valid SPKI Ed25519 key`);
  }
}

function validateAndVerifyProof(record, domain, pinnedKeys) {
  exactKeys(record.proof, ['alg', 'key_id', 'signature_b64u'], 'proof');
  if (record.proof.alg !== 'Ed25519') fail('proof.alg must be Ed25519');
  nonEmpty(record.proof.key_id, 'proof.key_id');
  b64uBytes(record.proof.signature_b64u, 64, 'proof.signature_b64u');
  if (record.proof.key_id !== record.adapter.key_id) {
    fail('proof.key_id must equal adapter.key_id');
  }
  const publicKey = publicKeyFor(pinnedKeys, record.proof.key_id);
  const valid = crypto.verify(
    null,
    signingInput(domain, record),
    publicKey,
    Buffer.from(record.proof.signature_b64u, 'base64url'),
  );
  if (!valid) fail('record signature is invalid');
}

function validateTrustAuthorship({
  derivedTrust,
  trustBasis,
  authorship,
  authorKey,
  signerKey,
  ownerKey,
  custody,
  path,
}) {
  oneOf(derivedTrust, ['self', 'trusted', 'unverified'], `${path}.derived_trust`);
  oneOf(trustBasis, ['owner_key', 'accepted_key', 'none'], `${path}.trust_basis`);
  oneOf(authorship, ['signed', 'attested', 'unknown'], `${path}.authorship`);

  if (custody.present) {
    if (derivedTrust === 'self') fail(`${path}: a resealed custody result cannot derive self trust`);
    if (derivedTrust === 'trusted') {
      if (signerKey !== ownerKey) {
        fail(`${path}: honoured custody must be signed by the vault owner key`);
      }
      if (trustBasis !== 'accepted_key' || authorship !== 'attested') {
        fail(`${path}: trusted custody requires accepted_key and attested authorship`);
      }
      if (!custody.proven_author_key_id_b64u || authorKey !== custody.proven_author_key_id_b64u) {
        fail(`${path}: attested custody must report the proven author key`);
      }
    } else {
      if (trustBasis !== 'none' || authorship !== 'unknown' || authorKey !== null) {
        fail(`${path}: unverified custody must not report an author`);
      }
    }
    return;
  }

  if (authorship === 'attested') fail(`${path}: attested authorship requires custody`);
  if (derivedTrust === 'self') {
    if (trustBasis !== 'owner_key' || authorship !== 'signed' || signerKey !== ownerKey || authorKey !== signerKey) {
      fail(`${path}: self trust requires a direct owner signature and owner authorship`);
    }
  } else if (derivedTrust === 'trusted') {
    if (trustBasis !== 'accepted_key' || authorship !== 'signed' || authorKey !== signerKey) {
      fail(`${path}: trusted direct authorship requires an accepted signer key`);
    }
  } else if (trustBasis !== 'none' || authorship !== 'unknown' || authorKey !== null) {
    fail(`${path}: unverified content must not report an author`);
  }
}

function validateCustody(value, path) {
  exactKeys(
    value,
    [
      'present',
      'from_format_version',
      'claimed_author_key_id_b64u',
      'proven_author_key_id_b64u',
    ],
    path,
  );
  if (typeof value.present !== 'boolean') fail(`${path}.present must be boolean`);
  nullableB64u(value.claimed_author_key_id_b64u, 8, `${path}.claimed_author_key_id_b64u`);
  nullableB64u(value.proven_author_key_id_b64u, 8, `${path}.proven_author_key_id_b64u`);
  if (value.present) {
    if (value.from_format_version !== null) {
      integer(value.from_format_version, `${path}.from_format_version`, 1);
    }
  } else if (
    value.from_format_version !== null ||
    value.claimed_author_key_id_b64u !== null ||
    value.proven_author_key_id_b64u !== null
  ) {
    fail(`${path}: custody details must be null when custody is absent`);
  }
}

export function verifyTrustCustodyResult(record, { adapterKeys } = {}) {
  exactKeys(
    record,
    [
      '@version',
      'source_profile',
      'record_id',
      'recorded_at',
      'adapter',
      'object',
      'verification',
      'trust_context',
      'ai_boundary',
      'nonclaims',
      'proof',
    ],
    'record',
  );
  if (record['@version'] !== 'AMEM-TRUST-CUSTODY-RESULT-v0') fail('unexpected trust result version');
  if (record.source_profile !== 'draft-ferro-apertomemory-02') fail('unexpected source profile');
  urn(record.record_id, 'record.record_id');
  dateTime(record.recorded_at, 'record.recorded_at');
  validateAdapter(record.adapter, 'record.adapter');
  validateObjectRef(record.object, 'record.object');

  exactKeys(
    record.verification,
    [
      'signature_verified',
      'signer_key_id_b64u',
      'derived_trust',
      'trust_basis',
      'authorship',
      'author_key_id_b64u',
      'claimed_author_key_id_b64u',
      'custody',
    ],
    'record.verification',
  );
  if (record.verification.signature_verified !== true) {
    fail('record.verification.signature_verified must be true for an emitted result');
  }
  b64uBytes(record.verification.signer_key_id_b64u, 8, 'record.verification.signer_key_id_b64u');
  nullableB64u(record.verification.author_key_id_b64u, 8, 'record.verification.author_key_id_b64u');
  nullableB64u(
    record.verification.claimed_author_key_id_b64u,
    8,
    'record.verification.claimed_author_key_id_b64u',
  );
  validateCustody(record.verification.custody, 'record.verification.custody');

  exactKeys(
    record.trust_context,
    ['evaluated_at', 'owner_key_id_b64u', 'keyring_snapshot_digest', 'accepted_key_ids_digest'],
    'record.trust_context',
  );
  dateTime(record.trust_context.evaluated_at, 'record.trust_context.evaluated_at');
  b64uBytes(record.trust_context.owner_key_id_b64u, 8, 'record.trust_context.owner_key_id_b64u');
  digest(record.trust_context.keyring_snapshot_digest, 'record.trust_context.keyring_snapshot_digest');
  digest(record.trust_context.accepted_key_ids_digest, 'record.trust_context.accepted_key_ids_digest');

  validateTrustAuthorship({
    derivedTrust: record.verification.derived_trust,
    trustBasis: record.verification.trust_basis,
    authorship: record.verification.authorship,
    authorKey: record.verification.author_key_id_b64u,
    signerKey: record.verification.signer_key_id_b64u,
    ownerKey: record.trust_context.owner_key_id_b64u,
    custody: record.verification.custody,
    path: 'record.verification',
  });

  if (
    record.verification.claimed_author_key_id_b64u !==
    record.verification.custody.claimed_author_key_id_b64u
  ) {
    fail('record.verification claimed author must match the custody claimed author');
  }

  exactKeys(
    record.ai_boundary,
    ['eligible_to_cross', 'crossing_label', 'excluded_object_count', 'validation_flags'],
    'record.ai_boundary',
  );
  if (typeof record.ai_boundary.eligible_to_cross !== 'boolean') {
    fail('record.ai_boundary.eligible_to_cross must be boolean');
  }
  oneOf(
    record.ai_boundary.crossing_label,
    ['self', 'trusted-data', 'unverified-data', 'withheld'],
    'record.ai_boundary.crossing_label',
  );
  integer(record.ai_boundary.excluded_object_count, 'record.ai_boundary.excluded_object_count');
  if (!Array.isArray(record.ai_boundary.validation_flags)) {
    fail('record.ai_boundary.validation_flags must be an array');
  }
  const flags = new Set();
  for (const [i, flag] of record.ai_boundary.validation_flags.entries()) {
    nonEmpty(flag, `record.ai_boundary.validation_flags[${i}]`);
    if (flags.has(flag)) fail('record.ai_boundary.validation_flags must be unique');
    flags.add(flag);
  }
  const expectedLabel = record.ai_boundary.eligible_to_cross
    ? { self: 'self', trusted: 'trusted-data', unverified: 'unverified-data' }[
        record.verification.derived_trust
      ]
    : 'withheld';
  if (record.ai_boundary.crossing_label !== expectedLabel) {
    fail(`record.ai_boundary.crossing_label must be ${expectedLabel}`);
  }

  validateNonclaims(record.nonclaims, 'record.nonclaims');
  validateAndVerifyProof(record, TRUST_RESULT_DOMAIN, adapterKeys);
  return { valid: true, record_id: record.record_id, derived_trust: record.verification.derived_trust };
}

function validateDeliveredEntry(entry, index) {
  const path = `record.delivered[${index}]`;
  exactKeys(
    entry,
    [
      'position',
      'object',
      'context_fragment_digest',
      'derived_trust',
      'authorship',
      'author_key_id_b64u',
      'custody_present',
    ],
    path,
  );
  if (entry.position !== index) fail(`${path}.position must equal ${index}`);
  validateObjectRef(entry.object, `${path}.object`);
  digest(entry.context_fragment_digest, `${path}.context_fragment_digest`);
  oneOf(entry.derived_trust, ['self', 'trusted', 'unverified'], `${path}.derived_trust`);
  oneOf(entry.authorship, ['signed', 'attested', 'unknown'], `${path}.authorship`);
  nullableB64u(entry.author_key_id_b64u, 8, `${path}.author_key_id_b64u`);
  if (typeof entry.custody_present !== 'boolean') fail(`${path}.custody_present must be boolean`);
  if (entry.authorship === 'attested' && !entry.custody_present) {
    fail(`${path}: attested authorship requires custody`);
  }
  if (entry.derived_trust === 'unverified') {
    if (entry.authorship !== 'unknown' || entry.author_key_id_b64u !== null) {
      fail(`${path}: unverified content must not report an author`);
    }
  } else if (entry.authorship === 'unknown' || entry.author_key_id_b64u === null) {
    fail(`${path}: verified content must report authorship and an author key`);
  }
}

function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function verifyProjectionRecord(
  record,
  { adapterKeys, projectionBytes, fragmentBytesByPosition } = {},
) {
  exactKeys(
    record,
    [
      '@version',
      'profile_status',
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
    ],
    'record',
  );
  if (record['@version'] !== 'AMEM-PROJECTION-RECORD-v0') fail('unexpected projection version');
  if (record.profile_status !== 'EMILIA_DISCUSSION_INPUT_NOT_APERTOMEMORY_CONFORMANCE') {
    fail('projection profile status must preserve its discussion-only boundary');
  }
  if (record.source_profile !== 'draft-ferro-apertomemory-02') fail('unexpected source profile');
  urn(record.projection_id, 'record.projection_id');
  dateTime(record.created_at, 'record.created_at');
  validateAdapter(record.adapter, 'record.adapter');

  exactKeys(
    record.selection_context,
    [
      'recall_request_digest',
      'selection_policy_digest',
      'keyring_snapshot_digest',
      'trust_evaluated_at',
      'context_frame_profile',
    ],
    'record.selection_context',
  );
  digest(record.selection_context.recall_request_digest, 'record.selection_context.recall_request_digest');
  digest(record.selection_context.selection_policy_digest, 'record.selection_context.selection_policy_digest');
  digest(record.selection_context.keyring_snapshot_digest, 'record.selection_context.keyring_snapshot_digest');
  dateTime(record.selection_context.trust_evaluated_at, 'record.selection_context.trust_evaluated_at');
  if (record.selection_context.context_frame_profile !== 'AMEM-CONTEXT-FRAME-v0') {
    fail('record.selection_context.context_frame_profile must be AMEM-CONTEXT-FRAME-v0');
  }

  if (!Array.isArray(record.delivered)) fail('record.delivered must be an array');
  record.delivered.forEach(validateDeliveredEntry);

  exactKeys(record.exclusions, ['total', 'by_reason'], 'record.exclusions');
  integer(record.exclusions.total, 'record.exclusions.total');
  exactKeys(
    record.exclusions.by_reason,
    ['authentication_failed', 'schema_invalid', 'policy_filtered', 'context_limit'],
    'record.exclusions.by_reason',
  );
  let excludedTotal = 0;
  for (const key of ['authentication_failed', 'schema_invalid', 'policy_filtered', 'context_limit']) {
    integer(record.exclusions.by_reason[key], `record.exclusions.by_reason.${key}`);
    excludedTotal += record.exclusions.by_reason[key];
  }
  if (excludedTotal !== record.exclusions.total) {
    fail('record.exclusions.total must equal the sum of by_reason counts');
  }

  exactKeys(record.projection, ['encoding', 'byte_length', 'digest'], 'record.projection');
  if (record.projection.encoding !== 'utf-8') fail('record.projection.encoding must be utf-8');
  integer(record.projection.byte_length, 'record.projection.byte_length');
  digest(record.projection.digest, 'record.projection.digest');

  if (projectionBytes !== undefined) {
    const bytes = Buffer.from(projectionBytes);
    if (bytes.length !== record.projection.byte_length) fail('projection bytes do not match byte_length');
    if (sha256(bytes) !== record.projection.digest) fail('projection bytes do not match projection.digest');
  }
  if (fragmentBytesByPosition !== undefined) {
    if (!Array.isArray(fragmentBytesByPosition) || fragmentBytesByPosition.length !== record.delivered.length) {
      fail('fragment verification material must match delivered length');
    }
    for (const [i, bytes] of fragmentBytesByPosition.entries()) {
      if (sha256(Buffer.from(bytes)) !== record.delivered[i].context_fragment_digest) {
        fail(`fragment bytes at position ${i} do not match context_fragment_digest`);
      }
    }
  }

  validateNonclaims(record.nonclaims, 'record.nonclaims');
  validateAndVerifyProof(record, PROJECTION_DOMAIN, adapterKeys);
  return {
    valid: true,
    projection_id: record.projection_id,
    delivered_count: record.delivered.length,
    excluded_count: record.exclusions.total,
  };
}

export function signRecord(recordWithoutSignature, privateKey, domain) {
  if ('proof' in recordWithoutSignature) fail('signRecord input must not already contain proof');
  const signature = crypto.sign(
    null,
    Buffer.concat([domain, Buffer.from(canonicalize(recordWithoutSignature), 'utf8')]),
    privateKey,
  );
  return {
    ...recordWithoutSignature,
    proof: {
      alg: 'Ed25519',
      key_id: recordWithoutSignature.adapter.key_id,
      signature_b64u: signature.toString('base64url'),
    },
  };
}

export function signTrustCustodyResult(recordWithoutSignature, privateKey) {
  return signRecord(recordWithoutSignature, privateKey, TRUST_RESULT_DOMAIN);
}

export function signProjectionRecord(recordWithoutSignature, privateKey) {
  return signRecord(recordWithoutSignature, privateKey, PROJECTION_DOMAIN);
}

export function sha256Digest(bytes) {
  return sha256(Buffer.from(bytes));
}
