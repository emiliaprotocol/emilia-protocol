// SPDX-License-Identifier: Apache-2.0
/**
 * Cedulon Decision Token -> AEB adapter, launch profile v0.1.
 *
 * Source semantics are pinned to draft-dogru-cedulon-04 and Cedulon v0.7.0.
 * This adapter is intentionally stricter than the v0.7.0 helper surface:
 * it verifies only against the relying-party-pinned PDP key and checks the
 * actual COSE_Sign1 unprotected map is empty before accepting the token.
 */
import crypto from 'node:crypto';

export const ADAPTER_ID = 'cedulon:decision-token';
export const ADAPTER_VERSION = '0.1.0';
export const ARTIFACT_VERSION = 'CEDULON-DECISION-TOKEN-AEB-INPUT-v0.1';
export const CONTENT_TYPE = 'application/cedulon-decision+cbor';
export const ACTION_TYPE = 'cedulon.payment.attempt.1';

const COSE_ALG_ED25519 = -19;
const COSE_HDR_ALG = 1;
const COSE_HDR_CONTENT_TYPE = 3;
const COSE_HDR_KID = 4;
const CLAIM_REQUEST_HASH = -70301;
const CLAIM_POLICY_HASH = -70302;
const CLAIM_EXPIRY_MS = -70303;
const CLAIM_NONCE = -70304;
const CLAIM_SINGLE_USE_ID = -70305;
const HEX_256_RE = /^[0-9a-f]{64}$/;
const AMOUNT_RE = /^(?:0|[1-9][0-9]*)$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const MAX_CBOR_BYTES = 65_536;
const MAX_CBOR_DEPTH = 16;
const MAX_CBOR_ELEMENTS = 4_096;
const MAX_CBOR_STRING = 16_384;

export const ACTION_DEFINITION = Object.freeze({
  action_type: ACTION_TYPE,
  status: 'active',
  risk_class: 'irreversible-financial',
  summary: 'Attempt one Cedulon-gated payment using the exact six fields evaluated by the PDP.',
  required_fields: [
    { name: 'amount', type: 'amount-string', notes: 'minor units; Cedulon decimal string syntax' },
    { name: 'currency', type: 'string' },
    { name: 'payee', type: 'string' },
    { name: 'tool', type: 'string' },
    { name: 'nonce', type: 'string' },
    { name: 'manifest_hash', type: 'string', notes: 'lowercase hexadecimal SHA-256 of signed manifest COSE bytes' },
  ],
  optional_fields: [],
  digest_notes: 'All six Cedulon requestHash fields are material. This v0.1 subset refuses null tool or manifestHash.',
  references: ['draft-dogru-cedulon-04 Sections 7.1, 8, and 16.6'],
});

export const MAPPING_DEFINITION = Object.freeze({
  '@version': 'CEDULON-DECISION-TOKEN-TO-CAID-v0.1',
  native_protocol: 'draft-dogru-cedulon-04',
  native_artifact: 'Decision Token',
  source_media_type: CONTENT_TYPE,
  source_profile: 'Cedulon-v0.7.0-compatible-strict-subset',
  projection: 'six-field-request',
  action_type: ACTION_TYPE,
  suite: 'jcs-sha256',
  field_map: [
    { source: 'request.amount', target: 'amount', transform: 'copy' },
    { source: 'request.currency', target: 'currency', transform: 'copy' },
    { source: 'request.payee', target: 'payee', transform: 'copy' },
    { source: 'request.tool', target: 'tool', transform: 'copy' },
    { source: 'request.nonce', target: 'nonce', transform: 'copy' },
    { source: 'request.manifestHash', target: 'manifest_hash', transform: 'copy' },
  ],
  definitions: [ACTION_DEFINITION],
});

const RESOLVER_DESCRIPTOR = Object.freeze({
  implementation: 'cedulon:decision-token-to-payment-attempt',
  version: ADAPTER_VERSION,
});

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function assertUnicodeScalarString(value) {
  if (typeof value !== 'string') throw new TypeError('string required');
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('lone surrogate');
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError('lone surrogate');
    }
  }
}

export function canonicalizeJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) throw new TypeError('safe integer required');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(',')}]`;
  if (isObject(value) && Object.getPrototypeOf(value) === Object.prototype) {
    if (Object.getOwnPropertySymbols(value).length !== 0) throw new TypeError('symbol member refused');
    return `{${Object.keys(value).sort().map((key) => {
      assertUnicodeScalarString(key);
      return `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`;
    }).join(',')}}`;
  }
  throw new TypeError('JSON value required');
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest();
}

export function digestJson(value) {
  return `sha256:${sha256Bytes(Buffer.from(canonicalizeJson(value), 'utf8')).toString('hex')}`;
}

function bytesEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function cborHead(major, value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('invalid CBOR length');
  const high = major << 5;
  if (value < 24) return Buffer.from([high | value]);
  if (value < 256) return Buffer.from([high | 24, value]);
  if (value < 65_536) {
    const out = Buffer.alloc(3);
    out[0] = high | 25;
    out.writeUInt16BE(value, 1);
    return out;
  }
  if (value <= 0xffffffff) {
    const out = Buffer.alloc(5);
    out[0] = high | 26;
    out.writeUInt32BE(value, 1);
    return out;
  }
  const out = Buffer.alloc(9);
  out[0] = high | 27;
  out.writeBigUInt64BE(BigInt(value), 1);
  return out;
}

function compareEncodedKeys(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

export function encodeCbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === false) return Buffer.from([0xf4]);
  if (value === true) return Buffer.from([0xf5]);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('CBOR safe integer required');
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === 'string') {
    assertUnicodeScalarString(value);
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHead(2, bytes.length), bytes]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(encodeCbor)]);
  }
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, entryValue]) => ({
      key: encodeCbor(key),
      value: encodeCbor(entryValue),
    })).sort((a, b) => compareEncodedKeys(a.key, b.key));
    return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap((entry) => [entry.key, entry.value])]);
  }
  throw new TypeError('unsupported CBOR value');
}

function readLength(reader, additional) {
  const remaining = () => reader.bytes.length - reader.offset;
  if (additional < 24) return additional;
  if (additional === 24) {
    if (remaining() < 1) throw new TypeError('cbor_eof');
    const value = reader.bytes[reader.offset++];
    if (value < 24) throw new TypeError('cbor_non_canonical');
    return value;
  }
  if (additional === 25) {
    if (remaining() < 2) throw new TypeError('cbor_eof');
    const value = reader.bytes.readUInt16BE(reader.offset);
    reader.offset += 2;
    if (value < 256) throw new TypeError('cbor_non_canonical');
    return value;
  }
  if (additional === 26) {
    if (remaining() < 4) throw new TypeError('cbor_eof');
    const value = reader.bytes.readUInt32BE(reader.offset);
    reader.offset += 4;
    if (value < 65_536) throw new TypeError('cbor_non_canonical');
    return value;
  }
  if (additional === 27) {
    if (remaining() < 8) throw new TypeError('cbor_eof');
    const value = reader.bytes.readBigUInt64BE(reader.offset);
    reader.offset += 8;
    if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError('cbor_non_canonical');
    return Number(value);
  }
  throw new TypeError('cbor_indefinite_or_reserved');
}

function readCbor(reader, depth) {
  if (depth > MAX_CBOR_DEPTH) throw new TypeError('cbor_too_deep');
  const initial = reader.bytes[reader.offset++];
  if (initial === undefined) throw new TypeError('cbor_eof');
  if (initial === 0xf4) return false;
  if (initial === 0xf5) return true;
  if (initial === 0xf6) return null;
  const major = initial >> 5;
  if (major > 5) throw new TypeError('cbor_unsupported');
  const length = readLength(reader, initial & 31);
  if (major === 0) return length;
  if (major === 1) return -1 - length;
  if (major === 2 || major === 3) {
    if (length > MAX_CBOR_STRING || reader.offset + length > reader.bytes.length) throw new TypeError('cbor_too_large_or_eof');
    const bytes = reader.bytes.subarray(reader.offset, reader.offset + length);
    reader.offset += length;
    if (major === 2) return Buffer.from(bytes);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }
  if (length > MAX_CBOR_ELEMENTS) throw new TypeError('cbor_too_many_elements');
  if (major === 4) {
    const values = [];
    for (let index = 0; index < length; index += 1) values.push(readCbor(reader, depth + 1));
    return values;
  }
  const entries = new Map();
  const encodedKeys = new Set();
  for (let index = 0; index < length; index += 1) {
    const keyStart = reader.offset;
    const key = readCbor(reader, depth + 1);
    const keyEncoding = reader.bytes.subarray(keyStart, reader.offset).toString('hex');
    if (encodedKeys.has(keyEncoding)) throw new TypeError('cbor_duplicate_key');
    encodedKeys.add(keyEncoding);
    entries.set(key, readCbor(reader, depth + 1));
  }
  return entries;
}

export function decodeCbor(bytes) {
  const input = Buffer.from(bytes);
  if (input.length > MAX_CBOR_BYTES) throw new TypeError('cbor_too_large');
  const reader = { bytes: input, offset: 0 };
  const value = readCbor(reader, 0);
  if (reader.offset !== input.length) throw new TypeError('cbor_trailing');
  if (!bytesEqual(encodeCbor(value), input)) throw new TypeError('cbor_non_canonical');
  return value;
}

function mapExact(map, keys) {
  return map instanceof Map && map.size === keys.length && keys.every((key) => map.has(key));
}

function strictHex(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || value !== value.toLowerCase() || !/^[0-9a-f]+$/.test(value)) {
    throw new TypeError('lowercase hexadecimal required');
  }
  const bytes = Buffer.from(value, 'hex');
  if (bytes.toString('hex') !== value) throw new TypeError('invalid hexadecimal');
  return bytes;
}

function strictSpki(value) {
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) throw new TypeError('base64url SPKI required');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw new TypeError('non-canonical base64url');
  const key = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  const canonical = key.export({ type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ed25519' || !bytesEqual(bytes, canonical)) throw new TypeError('Ed25519 SPKI required');
  return { bytes, key };
}

function pemSpki(value) {
  if (typeof value !== 'string') throw new TypeError('PEM key required');
  const key = crypto.createPublicKey(value);
  const bytes = key.export({ type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('Ed25519 key required');
  return { bytes, key };
}

function requestDocument(request) {
  if (!exactKeys(request, ['amount', 'currency', 'payee', 'tool', 'nonce', 'manifestHash'])
      || typeof request.amount !== 'string' || !AMOUNT_RE.test(request.amount)
      || typeof request.currency !== 'string' || request.currency.length === 0
      || typeof request.payee !== 'string' || request.payee.length === 0
      || !((typeof request.tool === 'string' && request.tool.length > 0) || request.tool === null)
      || typeof request.nonce !== 'string' || request.nonce.length < 16
      || !((typeof request.manifestHash === 'string' && HEX_256_RE.test(request.manifestHash)) || request.manifestHash === null)) {
    throw new TypeError('invalid Cedulon six-field request');
  }
  return {
    amount: request.amount,
    currency: request.currency,
    payee: request.payee,
    tool: request.tool,
    nonce: request.nonce,
    manifestHash: request.manifestHash,
  };
}

function claimObject(map) {
  const keys = [CLAIM_REQUEST_HASH, CLAIM_POLICY_HASH, CLAIM_EXPIRY_MS, CLAIM_NONCE, CLAIM_SINGLE_USE_ID];
  if (!mapExact(map, keys)) throw new TypeError('decision_claim_map_not_closed');
  const claims = {
    requestHash: map.get(CLAIM_REQUEST_HASH),
    policyHash: map.get(CLAIM_POLICY_HASH),
    expiryMs: map.get(CLAIM_EXPIRY_MS),
    nonce: map.get(CLAIM_NONCE),
    singleUseId: map.get(CLAIM_SINGLE_USE_ID),
  };
  if (!HEX_256_RE.test(claims.requestHash ?? '') || !HEX_256_RE.test(claims.policyHash ?? '')
      || !Number.isSafeInteger(claims.expiryMs) || claims.expiryMs < 0
      || typeof claims.nonce !== 'string' || claims.nonce.length < 16
      || typeof claims.singleUseId !== 'string' || claims.singleUseId.length === 0) {
    throw new TypeError('decision_claim_types_invalid');
  }
  return claims;
}

function decodeDecisionToken(coseHex) {
  const bytes = strictHex(coseHex);
  const cose = decodeCbor(bytes);
  if (!Array.isArray(cose) || cose.length !== 4
      || !Buffer.isBuffer(cose[0]) || !(cose[1] instanceof Map)
      || !Buffer.isBuffer(cose[2]) || !Buffer.isBuffer(cose[3]) || cose[3].length !== 64) {
    throw new TypeError('cose_sign1_shape_invalid');
  }
  if (cose[1].size !== 0) throw new TypeError('cose_unprotected_header_not_empty');
  const protectedHeader = decodeCbor(cose[0]);
  if (!mapExact(protectedHeader, [COSE_HDR_ALG, COSE_HDR_CONTENT_TYPE, COSE_HDR_KID])
      || protectedHeader.get(COSE_HDR_ALG) !== COSE_ALG_ED25519
      || protectedHeader.get(COSE_HDR_CONTENT_TYPE) !== CONTENT_TYPE
      || !Buffer.isBuffer(protectedHeader.get(COSE_HDR_KID))
      || protectedHeader.get(COSE_HDR_KID).length !== 8) {
    throw new TypeError('cose_protected_header_invalid');
  }
  const claims = claimObject(decodeCbor(cose[2]));
  return {
    bytes,
    protectedBytes: cose[0],
    protectedHeader,
    payloadBytes: cose[2],
    signature: cose[3],
    claims,
  };
}

function normalizedStatus(status) {
  return {
    checked_at: status.checked_at,
    expires_at: status.expires_at,
    revocation_checked: status.revocation_checked,
    revoked: status.revoked,
    consumed: status.consumed,
    unavailable: status.unavailable === true,
  };
}

function validateAdapterConfig(value) {
  if (!exactKeys(value, [
    '@version', 'authority_boundary', 'consumer_deployment_id', 'issuer_key_id',
    'replay_identities', 'settlement_boundary', 'subject_id',
  ]) || value['@version'] !== 'CEDULON-AEB-ADAPTER-CONFIG-v0.1'
      || value.authority_boundary !== 'PRE_SETTLEMENT_MACHINE_POLICY_DECISION'
      || value.settlement_boundary !== 'NO_SPEND_RECEIPT_OR_RAIL_EXTRACT_AS_AUTHORITY'
      || typeof value.consumer_deployment_id !== 'string' || value.consumer_deployment_id.length === 0
      || typeof value.issuer_key_id !== 'string' || value.issuer_key_id.length === 0
      || typeof value.subject_id !== 'string' || value.subject_id.length === 0
      || !Array.isArray(value.replay_identities)
      || canonicalizeJson(value.replay_identities) !== canonicalizeJson(['singleUseId', 'nonce'])) {
    throw new TypeError('adapter_config_invalid');
  }
  return value;
}

function parseArtifact(artifact) {
  if (!exactKeys(artifact, ['@version', 'policy', 'request', 'token']) || artifact['@version'] !== ARTIFACT_VERSION
      || !isObject(artifact.policy) || !isObject(artifact.request) || !isObject(artifact.token)
      || !exactKeys(artifact.token, ['claims', 'coseHex', 'encoding', 'publicKeyPem'])
      || artifact.token.encoding !== 'cose' || !isObject(artifact.token.claims)) {
    throw new TypeError('artifact_shape_invalid');
  }
  const request = requestDocument(artifact.request);
  const decoded = decodeDecisionToken(artifact.token.coseHex);
  if (!exactKeys(artifact.token.claims, ['requestHash', 'policyHash', 'expiryMs', 'nonce', 'singleUseId'])
      || canonicalizeJson(decoded.claims) !== canonicalizeJson(artifact.token.claims)) {
    throw new TypeError('presented_claim_map_mismatch');
  }
  return { request, decoded };
}

function strictDecisionVerification(input) {
  const config = validateAdapterConfig(input.adapter_config);
  const parsed = parseArtifact(input.artifact);
  const candidates = Array.isArray(input.trust_roots) ? input.trust_roots.filter((root) => isObject(root)
    && root.key_id === config.issuer_key_id && root.algorithm === 'Ed25519' && typeof root.public_key === 'string') : [];
  if (candidates.length !== 1) throw new TypeError('pinned_issuer_key_required');
  const pinned = strictSpki(candidates[0].public_key);
  const presented = pemSpki(input.artifact.token.publicKeyPem);
  if (!bytesEqual(pinned.bytes, presented.bytes)) throw new TypeError('presented_key_differs_from_pin');
  const expectedKid = sha256Bytes(pinned.bytes).subarray(0, 8);
  if (!bytesEqual(parsed.decoded.protectedHeader.get(COSE_HDR_KID), expectedKid)) throw new TypeError('cose_kid_mismatch');
  const sigStructure = encodeCbor(['Signature1', parsed.decoded.protectedBytes, Buffer.alloc(0), parsed.decoded.payloadBytes]);
  if (!crypto.verify(null, sigStructure, pinned.key, parsed.decoded.signature)) throw new TypeError('decision_signature_invalid');
  const requestHash = sha256Bytes(Buffer.from(canonicalizeJson(parsed.request), 'utf8')).toString('hex');
  if (requestHash !== parsed.decoded.claims.requestHash || parsed.request.nonce !== parsed.decoded.claims.nonce) {
    throw new TypeError('decision_request_binding_mismatch');
  }
  const policyHash = sha256Bytes(Buffer.from(canonicalizeJson(input.artifact.policy), 'utf8')).toString('hex');
  if (policyHash !== parsed.decoded.claims.policyHash) throw new TypeError('decision_policy_binding_mismatch');
  return { ...parsed, config };
}

function replayUnitFromClaims(claims) {
  return digestJson({
    protocol: 'cedulon-decision-token',
    version: 'draft-dogru-cedulon-04',
    single_use_id: claims.singleUseId,
    nonce: claims.nonce,
  });
}

function fallbackReplayUnit(artifact) {
  return digestJson({ protocol: 'cedulon-decision-token-invalid', evidence_digest: digestJson(artifact) });
}

function failureReason(error) {
  const message = error instanceof Error ? error.message : 'native_verification_failed';
  return /^[a-z0-9_]+$/.test(message) ? message : 'native_verification_failed';
}

function mappingProfileSupported(profile) {
  const expectedResolverDigest = digestJson(RESOLVER_DESCRIPTOR);
  return isObject(profile)
    && profile.version === ADAPTER_VERSION
    && profile.mapper_id === 'cedulon:decision-token-to-payment-attempt'
    && isObject(profile.resolver)
    && profile.resolver.id === RESOLVER_DESCRIPTOR.implementation
    && profile.resolver.version === ADAPTER_VERSION
    && profile.resolver.implementation_digest === expectedResolverDigest
    && canonicalizeJson(profile.definition) === canonicalizeJson(MAPPING_DEFINITION)
    && isObject(profile.semantic_equivalence)
    && profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
    && profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
    && canonicalizeJson(profile.semantic_equivalence.omitted_material_fields) === '[]'
    && canonicalizeJson(profile.semantic_equivalence.omitted_nonmaterial_fields) === '[]';
}

export function requestToAction(request) {
  const source = requestDocument(request);
  if (source.tool === null || source.manifestHash === null) throw new TypeError('null_request_member_outside_v0_1_subset');
  return {
    action_type: ACTION_TYPE,
    amount: source.amount,
    currency: source.currency,
    payee: source.payee,
    tool: source.tool,
    nonce: source.nonce,
    manifest_hash: source.manifestHash,
  };
}

function validAction(action) {
  return exactKeys(action, ['action_type', 'amount', 'currency', 'payee', 'tool', 'nonce', 'manifest_hash'])
    && action.action_type === ACTION_TYPE
    && typeof action.amount === 'string' && AMOUNT_RE.test(action.amount)
    && ['currency', 'payee', 'tool', 'nonce'].every((name) => typeof action[name] === 'string' && action[name].length > 0)
    && typeof action.manifest_hash === 'string' && HEX_256_RE.test(action.manifest_hash);
}

function caidForAction(action) {
  if (!validAction(action)) throw new TypeError('mapped_action_invalid');
  const canonical = canonicalizeJson(action);
  const hash = sha256Bytes(Buffer.from(canonical, 'utf8'));
  return {
    caid: `caid:1:${ACTION_TYPE}:jcs-sha256:${hash.toString('base64url')}`,
    digest: `sha256:${hash.toString('hex')}`,
  };
}

const adapter = Object.freeze({
  id: ADAPTER_ID,
  version: ADAPTER_VERSION,

  verifyNative(input) {
    const evidenceDigest = digestJson(input.artifact);
    const statusDigest = digestJson(normalizedStatus(input.status));
    let replayUnit = fallbackReplayUnit(input.artifact);
    let subjectId = 'system:cedulon-pdp-unresolved';
    try {
      const verified = strictDecisionVerification(input);
      replayUnit = replayUnitFromClaims(verified.decoded.claims);
      subjectId = verified.config.subject_id;
      const evaluatedMs = Date.parse(input.now);
      if (!Number.isFinite(evaluatedMs)) throw new TypeError('evaluation_time_invalid');
      const reasons = [];
      let acceptance = 'ACCEPTED';
      if (evaluatedMs > verified.decoded.claims.expiryMs) {
        acceptance = 'REJECTED';
        reasons.push('decision_expired');
      }
      if (input.status.revoked === true || input.status.consumed === true) {
        acceptance = 'REJECTED';
        reasons.push(input.status.revoked === true ? 'decision_revoked' : 'decision_consumed');
      } else if (input.status.unavailable === true || input.status.revocation_checked !== true) {
        // Unknown status can withhold acceptance, but it can never soften an
        // independently established expiry into an indeterminate result.
        if (acceptance !== 'REJECTED') acceptance = 'INDETERMINATE';
        reasons.push(input.status.unavailable === true ? 'status_unavailable' : 'status_not_checked');
      }
      return {
        native_verification: 'VERIFIED',
        acceptance,
        evidence_digest: evidenceDigest,
        status_digest: statusDigest,
        evidence_role: 'machine-policy-decision',
        subject: { id: subjectId, kind: 'system' },
        replay_unit: replayUnit,
        reasons: reasons.sort(),
      };
    } catch (error) {
      return {
        native_verification: 'FAILED',
        acceptance: 'REJECTED',
        evidence_digest: evidenceDigest,
        status_digest: statusDigest,
        evidence_role: 'machine-policy-decision',
        subject: { id: subjectId, kind: 'system' },
        replay_unit: replayUnit,
        reasons: [failureReason(error)],
      };
    }
  },

  mapAction(input) {
    // Mapping is content correlation, not acceptance. A verified token with an
    // unavailable status still maps to the same action while AEB independently
    // keeps the overall result INDETERMINATE.
    if (input.native.native_verification !== 'VERIFIED') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['verified_native_decision_required'] };
    }
    if (!mappingProfileSupported(input.profile)) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_not_supported'] };
    }
    try {
      const action = requestToAction(input.artifact.request);
      const computed = caidForAction(action);
      const match = canonicalizeJson(action) === canonicalizeJson(input.expected_action);
      return {
        mapping: match ? 'MATCH' : 'MISMATCH',
        caid: computed.caid,
        action_digest: computed.digest,
        reasons: match ? [] : ['material_action_mismatch'],
      };
    } catch (error) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: [failureReason(error)] };
    }
  },
});

export default adapter;
