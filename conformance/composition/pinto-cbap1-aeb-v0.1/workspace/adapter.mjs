// SPDX-License-Identifier: Apache-2.0
/**
 * Pinto CBAP-1 -> AEB historical contestability-binding adapter.
 *
 * This file is deliberately self-contained. Crossing Lab captures these exact
 * bytes, verifies their digest, and imports the captured bytes in a
 * permission-bounded worker. The adapter verifies the complete CBAP-1 positive
 * path from draft-pinto-agent-authz-contestability-00. It does not turn a
 * Contestability Binding into execution authority.
 */
import crypto from 'node:crypto';

export const ADAPTER_ID = 'pinto:cbap1-contestability-binding';
export const ADAPTER_VERSION = '0.1.0';
export const NATIVE_PROTOCOL = 'draft-pinto-agent-authz-contestability-00#CBAP-1';
export const ARTIFACT_VERSION = 'PINTO-CBAP1-BUNDLE-v0.1';
export const PROFILE_ID = 'pinto:cbap1-account-suspension';
export const MAPPER_ID = 'pinto:cbap1-direct-action-mapper';
export const RESOLVER_DESCRIPTOR = Object.freeze({
  implementation: 'pinto:cbap1-jcs-action-resolver',
  version: '0.1.0',
  action_type: 'account.suspend.1',
  material_fields: ['account_ref', 'action_type', 'policy_event_ref'],
});
export const PROFILE_DEFINITION = Object.freeze({
  '@version': 'PINTO-CBAP1-AEB-MAPPING-v0.1',
  native_protocol: NATIVE_PROTOCOL,
  native_revision: '00',
  native_binding_mode: 'direct',
  action_encoding: 'JCS-UTF8',
  action_type: 'account.suspend.1',
  material_fields: ['account_ref', 'action_type', 'policy_event_ref'],
  evidence_role: 'contestability-binding',
  claim_scope: 'historical-contestability-binding-only',
  native_result_axes: [
    'binding',
    'pre_execution_evidence',
    'discoverability',
    'forum_acknowledgement',
    'forum_operational_status',
    'selection_provenance',
    'access_binding',
    'notice_evidence',
    'retrievability',
    'filing_window_status',
    'policy_freshness',
    'declared_effect',
    'effect_acceptance',
    'effect_trigger',
    'effect_ordering',
    'effect_application',
    'reasons',
  ],
  excluded_native_features: [
    'active_effects',
    'class_manifest',
    'companion_binding',
    'external_selection',
    'multiparty_selection',
    'notices',
    'same_object_scitt',
  ],
});

const MAX_UINT64 = (1n << 64n) - 1n;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_KEYS = new Set(['account_ref', 'action_type', 'policy_event_ref']);
const ADAPTER_CONFIG_KEYS = new Set([
  '@version',
  'authorization_trust_profile_digest',
  'cbap_profile',
  'claim_scope',
  'expected_abp_digest',
  'source_txt_sha256',
  'subject_system_id',
]);
const ROOT_KEYS = new Set(['control_domain', 'kid', 'public_key', 'role']);
const ROLE_ORDER = Object.freeze(['executor', 'forum', 'issuer']);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected) {
  return isObject(value)
    && Object.keys(value).length === expected.size
    && Object.keys(value).every((key) => expected.has(key));
}

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite JSON number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
  }
  throw new TypeError('value is outside the JSON domain');
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest();
}

export function digestJson(value) {
  return `sha256:${sha256Bytes(Buffer.from(jcs(value), 'utf8')).toString('hex')}`;
}

function digestBytes(value) {
  return `sha256:${sha256Bytes(value).toString('hex')}`;
}

function labelDigest(value) {
  const bytes = Buffer.from(value);
  if (bytes.length !== 32) throw new TypeError('SHA-256 digest value must be 32 bytes');
  return `sha256:${bytes.toString('hex')}`;
}

function compareBytes(left, right) {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function uintArgument(major, value) {
  const number = typeof value === 'bigint' ? value : BigInt(value);
  if (number < 0n || number > MAX_UINT64) throw new TypeError('CBOR unsigned argument out of range');
  if (number < 24n) return Buffer.from([(major << 5) | Number(number)]);
  if (number <= 0xffn) return Buffer.from([(major << 5) | 24, Number(number)]);
  if (number <= 0xffffn) {
    const out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(Number(number), 1);
    return out;
  }
  if (number <= 0xffff_ffffn) {
    const out = Buffer.alloc(5);
    out[0] = (major << 5) | 26;
    out.writeUInt32BE(Number(number), 1);
    return out;
  }
  const out = Buffer.alloc(9);
  out[0] = (major << 5) | 27;
  out.writeBigUInt64BE(number, 1);
  return out;
}

function tagged18(value) {
  return Object.freeze({ __cbap1_tag: 18, value });
}

export function encodeDeterministicCbor(value) {
  if (typeof value === 'bigint') return uintArgument(0, value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('CBOR integer must be safe or bigint');
    if (value >= 0) return uintArgument(0, value);
    return uintArgument(1, BigInt(-1 - value));
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return Buffer.concat([uintArgument(2, bytes.length), bytes]);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([uintArgument(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([uintArgument(4, value.length), ...value.map(encodeDeterministicCbor)]);
  }
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, item]) => {
      const encodedKey = encodeDeterministicCbor(key);
      return { encodedKey, encodedValue: encodeDeterministicCbor(item) };
    }).sort((left, right) => compareBytes(left.encodedKey, right.encodedKey));
    for (let index = 1; index < entries.length; index += 1) {
      if (compareBytes(entries[index - 1].encodedKey, entries[index].encodedKey) === 0) {
        throw new TypeError('duplicate deterministic CBOR map key');
      }
    }
    return Buffer.concat([
      uintArgument(5, entries.length),
      ...entries.flatMap((entry) => [entry.encodedKey, entry.encodedValue]),
    ]);
  }
  if (value && value.__cbap1_tag === 18 && Object.keys(value).length === 2) {
    return Buffer.concat([uintArgument(6, 18), encodeDeterministicCbor(value.value)]);
  }
  if (value === false) return Buffer.from([0xf4]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === null) return Buffer.from([0xf6]);
  throw new TypeError('unsupported deterministic CBOR value');
}

function readArgument(bytes, cursor, additional) {
  if (additional < 24) return { value: BigInt(additional), next: cursor };
  const sizes = new Map([[24, 1], [25, 2], [26, 4], [27, 8]]);
  const size = sizes.get(additional);
  if (!size || cursor + size > bytes.length) throw new TypeError('truncated or reserved CBOR argument');
  let value;
  if (size === 1) value = BigInt(bytes[cursor]);
  else if (size === 2) value = BigInt(bytes.readUInt16BE(cursor));
  else if (size === 4) value = BigInt(bytes.readUInt32BE(cursor));
  else value = bytes.readBigUInt64BE(cursor);
  const minimum = size === 1 ? 24n : size === 2 ? 0x100n : size === 4 ? 0x1_0000n : 0x1_0000_0000n;
  if (value < minimum) throw new TypeError('non-shortest CBOR argument');
  return { value, next: cursor + size };
}

function representUint(value) {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
}

function parseItem(bytes, start, depth, state, allowOuterTag) {
  state.nodes += 1;
  if (state.nodes > 65_536 || depth > 32 || start >= bytes.length) throw new TypeError('CBOR bounds exceeded');
  const initial = bytes[start];
  const major = initial >> 5;
  const additional = initial & 31;
  if (additional >= 28) throw new TypeError('indefinite or reserved CBOR argument');
  const argument = readArgument(bytes, start + 1, additional);
  let cursor = argument.next;
  if (major === 0) return { value: representUint(argument.value), next: cursor };
  if (major === 1) {
    const value = -1n - argument.value;
    return { value: value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value, next: cursor };
  }
  if (major === 2 || major === 3) {
    if (argument.value > BigInt(Number.MAX_SAFE_INTEGER)) throw new TypeError('CBOR length is not representable');
    const length = Number(argument.value);
    if (length > bytes.length - cursor) throw new TypeError('CBOR length exceeds remaining input');
    const body = bytes.subarray(cursor, cursor + length);
    if (major === 2) return { value: Buffer.from(body), next: cursor + length };
    const text = new TextDecoder('utf-8', { fatal: true }).decode(body);
    if (!Buffer.from(text, 'utf8').equals(body)) throw new TypeError('non-canonical UTF-8');
    return { value: text, next: cursor + length };
  }
  if (major === 4) {
    if (argument.value > BigInt(bytes.length - cursor)) throw new TypeError('CBOR array length exceeds remaining input');
    const result = [];
    for (let index = 0n; index < argument.value; index += 1n) {
      const item = parseItem(bytes, cursor, depth + 1, state, false);
      result.push(item.value);
      cursor = item.next;
    }
    return { value: result, next: cursor };
  }
  if (major === 5) {
    if (argument.value > BigInt(bytes.length - cursor)) throw new TypeError('CBOR map length exceeds remaining input');
    const result = new Map();
    let priorKey = null;
    for (let index = 0n; index < argument.value; index += 1n) {
      const keyStart = cursor;
      const key = parseItem(bytes, cursor, depth + 1, state, false);
      cursor = key.next;
      const keyBytes = bytes.subarray(keyStart, cursor);
      if (priorKey !== null && compareBytes(priorKey, keyBytes) >= 0) throw new TypeError('unordered or duplicate CBOR map key');
      priorKey = Buffer.from(keyBytes);
      if (!Number.isSafeInteger(key.value) || key.value < 0) throw new TypeError('CBAP-1 map key must be an unsigned integer label');
      const item = parseItem(bytes, cursor, depth + 1, state, false);
      cursor = item.next;
      if (result.has(key.value)) throw new TypeError('duplicate CBOR map key');
      result.set(key.value, item.value);
    }
    return { value: result, next: cursor };
  }
  if (major === 6) {
    if (!allowOuterTag || depth !== 0 || argument.value !== 18n) throw new TypeError('unsupported CBOR tag');
    const item = parseItem(bytes, cursor, depth + 1, state, false);
    return { value: tagged18(item.value), next: item.next };
  }
  if (major === 7 && additional === 20) return { value: false, next: start + 1 };
  if (major === 7 && additional === 21) return { value: true, next: start + 1 };
  if (major === 7 && additional === 22) return { value: null, next: start + 1 };
  throw new TypeError('float or unsupported CBOR simple value');
}

export function decodeDeterministicCbor(input, options = {}) {
  const bytes = Buffer.from(input);
  const parsed = parseItem(bytes, 0, 0, { nodes: 0 }, options.allowTag18 === true);
  if (parsed.next !== bytes.length) throw new TypeError('trailing CBOR bytes');
  if (!encodeDeterministicCbor(parsed.value).equals(bytes)) throw new TypeError('CBOR is not Core Deterministic');
  return parsed.value;
}

export function hCbap1(domain, value) {
  return sha256Bytes(encodeDeterministicCbor([domain, value]));
}

export const EXPECTED_ABP_DIGEST_BYTES = hCbap1('cbap1-authorization-binding-profile-v1', 1);
export const EXPECTED_ABP_DIGEST = `sha256:${EXPECTED_ABP_DIGEST_BYTES.toString('hex')}`;
export const RESOLVER_DIGEST = digestJson(RESOLVER_DESCRIPTOR);

function exactMap(value, labels) {
  return value instanceof Map
    && value.size === labels.length
    && labels.every((label) => value.has(label));
}

function byteString(value, size) {
  return Buffer.isBuffer(value) && (size === undefined || value.length === size);
}

function text(value, maxBytes) {
  return typeof value === 'string' && value.length > 0
    && (maxBytes === undefined || Buffer.byteLength(value, 'utf8') <= maxBytes);
}

function uint(value) {
  return (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)
    || (typeof value === 'bigint' && value >= 0n && value <= MAX_UINT64);
}

function asUint(value) {
  if (!uint(value)) throw new TypeError('unsigned integer required');
  return typeof value === 'bigint' ? value : BigInt(value);
}

function equalsBytes(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
}

function isPolicyRef(value) {
  return Array.isArray(value) && value.length === 2 && text(value[0]) && byteString(value[1], 32);
}

export function validateCbap1HttpsUri(value) {
  if (typeof value !== 'string' || !value.startsWith('https://') || /[^\x21-\x7e]/.test(value)
      || value.includes('#') || /%(?![0-9A-Fa-f]{2})/.test(value)) return false;
  const authorityAndRest = value.slice(8);
  const boundary = authorityAndRest.search(/[/?]/);
  const authority = boundary === -1 ? authorityAndRest : authorityAndRest.slice(0, boundary);
  const rest = boundary === -1 ? '' : authorityAndRest.slice(boundary);
  if (!authority || authority.includes('@') || /[\[\]]/.test(rest)) return false;
  const queryStart = rest.indexOf('?');
  const path = queryStart === -1 ? rest : rest.slice(0, queryStart);
  const query = queryStart === -1 ? null : rest.slice(queryStart + 1);
  const pctEncoded = '%[0-9A-Fa-f]{2}';
  const unreserved = 'A-Za-z0-9._~\\-';
  const subDelims = "!$&'()*+,;=";
  const pchar = `(?:[${unreserved}${subDelims}:@]|${pctEncoded})`;
  if (path !== '' && (!path.startsWith('/') || !new RegExp(`^(?:/${pchar}*)*$`).test(path))) return false;
  if (query !== null && !new RegExp(`^(?:${pchar}|[/?])*$`).test(query)) return false;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close <= 1 || authority.indexOf('[', 1) !== -1 || authority.indexOf(']', close + 1) !== -1) return false;
    const literal = authority.slice(1, close);
    if (literal.includes('%')) return false;
    const suffix = authority.slice(close + 1);
    if (suffix && !/^:[0-9]+$/.test(suffix)) return false;
    if (/^[vV]/.test(literal)) {
      if (!/^[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/.test(literal)) return false;
    } else {
      try {
        const candidate = new URL(`https://[${literal}]/`);
        if (!candidate.hostname.startsWith('[')) return false;
      } catch { return false; }
    }
  } else {
    if (authority.includes('[') || authority.includes(']')) return false;
    const colon = authority.lastIndexOf(':');
    const host = colon === -1 ? authority : authority.slice(0, colon);
    const port = colon === -1 ? null : authority.slice(colon + 1);
    if (!host || !new RegExp(`^(?:[${unreserved}${subDelims}]|${pctEncoded})+$`).test(host)) return false;
    if (port !== null && (!/^[0-9]+$/.test(port) || Number(port) > 65535)) return false;
  }
  return true;
}

function validateCpoPayload(payload) {
  if (!exactMap(payload, [1, 2, 3, 4, 5, 6]) || payload.get(1) !== 1 || payload.get(2) !== 1
      || !text(payload.get(6), 64)) return false;
  const terms = payload.get(3);
  if (!exactMap(terms, Array.from({ length: 16 }, (_, index) => index + 1))
      || !byteString(terms.get(1), 16) || !byteString(terms.get(2), 32) || !byteString(terms.get(3), 32)
      || !text(terms.get(4), 64) || !Array.isArray(terms.get(5)) || terms.get(5).length !== 2
      || !uint(terms.get(5)[0]) || !uint(terms.get(5)[1]) || !byteString(terms.get(6), 32)
      || !Array.isArray(terms.get(7)) || terms.get(7).length !== 3 || !terms.get(7).every((item) => text(item))
      || !isPolicyRef(terms.get(8)) || !isPolicyRef(terms.get(9))
      || !Array.isArray(terms.get(10)) || terms.get(10).length !== 2 || !uint(terms.get(10)[0]) || !uint(terms.get(10)[1])
      || !Array.isArray(terms.get(11)) || terms.get(11).length !== 1 || !uint(terms.get(11)[0])
      || !isPolicyRef(terms.get(12)) || !Array.isArray(terms.get(13)) || terms.get(13).length === 0
      || !terms.get(13).every((entry) => Array.isArray(entry) && entry.length === 3 && uint(entry[0]) && text(entry[1]) && uint(entry[2]))
      || !uint(terms.get(14)) || !uint(terms.get(15)) || !byteString(terms.get(16), 16)) return false;
  const acceptance = payload.get(4);
  return Array.isArray(acceptance) && acceptance.length === 2 && uint(acceptance[0]) && byteString(acceptance[1], 32)
    && Array.isArray(payload.get(5));
}

function validateAcceptancePayload(payload) {
  return exactMap(payload, [1, 2, 3, 4, 5, 6, 7, 8, 9])
    && payload.get(1) === 1 && payload.get(2) === 2 && byteString(payload.get(3), 32)
    && uint(payload.get(4)) && uint(payload.get(5)) && isPolicyRef(payload.get(6)) && isPolicyRef(payload.get(7))
    && uint(payload.get(8)) && text(payload.get(9), 64);
}

function validateAuthorizationPayload(payload) {
  return exactMap(payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    && payload.get(1) === 1 && payload.get(2) === 3 && byteString(payload.get(3), 16)
    && text(payload.get(4), 64) && text(payload.get(5)) && byteString(payload.get(6), 32)
    && uint(payload.get(7)) && uint(payload.get(8)) && byteString(payload.get(9), 32) && byteString(payload.get(10), 16);
}

function validateExecutorVerificationPayload(payload) {
  return exactMap(payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    && payload.get(1) === 1 && payload.get(2) === 4 && byteString(payload.get(3), 32)
    && byteString(payload.get(4), 16) && byteString(payload.get(5), 32) && byteString(payload.get(6), 32)
    && uint(payload.get(7)) && uint(payload.get(8)) && byteString(payload.get(9), 16) && text(payload.get(10), 64);
}

function validateExecutionRecordPayload(payload) {
  return exactMap(payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    && payload.get(1) === 1 && payload.get(2) === 5 && byteString(payload.get(3), 32)
    && byteString(payload.get(4), 32) && byteString(payload.get(5), 16) && byteString(payload.get(6), 32)
    && uint(payload.get(7)) && uint(payload.get(8)) && byteString(payload.get(9), 16) && text(payload.get(10), 64);
}

function parseTrustRoots(value) {
  if (!Array.isArray(value) || value.length !== 3) return null;
  const roots = value.map((root) => exactKeys(root, ROOT_KEYS) ? root : null);
  if (roots.some((root) => root === null)) return null;
  const sorted = [...roots].sort((left, right) => (left.role < right.role ? -1 : left.role > right.role ? 1 : 0));
  if (jcs(sorted.map((root) => root.role)) !== jcs(ROLE_ORDER)) return null;
  if (new Set(sorted.map((root) => root.kid)).size !== 3
      || sorted.some((root) => !text(root.kid, 64) || !text(root.control_domain) || !text(root.public_key))) return null;
  return sorted;
}

function trustProfileDigest(roots) {
  return digestJson({
    '@version': 'PINTO-CBAP1-TRUST-PROFILE-v0.1',
    roles: roots.map(({ control_domain, kid, public_key, role }) => ({ control_domain, kid, public_key, role })),
  });
}

function resolveRoleKey(roots, role, kid) {
  const matches = roots.filter((root) => root.role === role && root.kid === kid);
  if (matches.length !== 1) return null;
  try {
    const raw = Buffer.from(matches[0].public_key, 'base64url');
    if (raw.length === 0 || raw.toString('base64url') !== matches[0].public_key) return null;
    const coseKeyPrefix = Buffer.from('a4010103322006215820', 'hex');
    if (raw.length !== coseKeyPrefix.length + 32 || !raw.subarray(0, coseKeyPrefix.length).equals(coseKeyPrefix)) return null;
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw.subarray(coseKeyPrefix.length)]);
    const key = crypto.createPublicKey({ key: spki, type: 'spki', format: 'der' });
    const canonical = key.export({ type: 'spki', format: 'der' });
    return key.asymmetricKeyType === 'ed25519' && Buffer.isBuffer(canonical) && canonical.equals(spki) ? key : null;
  } catch { return null; }
}

function parseSigned(bytes, role, validatePayload, reason, roots) {
  try {
    const tagged = decodeDeterministicCbor(bytes, { allowTag18: true });
    if (!tagged || tagged.__cbap1_tag !== 18 || !Array.isArray(tagged.value) || tagged.value.length !== 4) throw new TypeError('COSE shape');
    const [protectedBytes, unprotected, payloadBytes, signature] = tagged.value;
    if (!byteString(protectedBytes) || !(unprotected instanceof Map) || unprotected.size !== 0
        || !byteString(payloadBytes) || !byteString(signature, 64)) throw new TypeError('COSE members');
    const protectedMap = decodeDeterministicCbor(protectedBytes);
    if (!exactMap(protectedMap, [1, 4]) || protectedMap.get(1) !== -19 || !byteString(protectedMap.get(4))
        || protectedMap.get(4).length < 1 || protectedMap.get(4).length > 64) throw new TypeError('protected headers');
    const payload = decodeDeterministicCbor(payloadBytes);
    if (!(payload instanceof Map) || !validatePayload(payload)) throw new TypeError('payload schema');
    const signerLabel = payload.get(payload.get(2) === 1 ? 6 : payload.get(2) === 2 ? 9 : payload.get(2) === 3 ? 4 : 10);
    const kidBytes = protectedMap.get(4);
    if (!text(signerLabel, 64) || !Buffer.from(signerLabel, 'utf8').equals(kidBytes)) throw new TypeError('kid mismatch');
    const key = resolveRoleKey(roots, role, signerLabel);
    if (!key) throw new TypeError('role key not uniquely trusted');
    const sigStructure = encodeDeterministicCbor(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
    if (!crypto.verify(null, sigStructure, key, signature)) throw new TypeError('signature invalid');
    return { bytes: Buffer.from(bytes), payload, kid: signerLabel, protectedBytes, payloadBytes };
  } catch {
    const error = Object.assign(new Error(reason), { cbapReason: reason });
    throw error;
  }
}

function parseBundle(bytes) {
  let bundle;
  try { bundle = decodeDeterministicCbor(bytes); } catch {
    const error = Object.assign(new Error('outer_encoding_invalid'), { cbapReason: 'outer_encoding_invalid' });
    throw error;
  }
  if (!exactMap(bundle, [1, 2, 3, 4, 5, 6, 7, 8]) || bundle.get(1) !== 1
      || ![2, 3, 4, 5, 6, 7].every((label) => byteString(bundle.get(label)))
      || !Array.isArray(bundle.get(8))) {
    const error = Object.assign(new Error('bundle_schema_invalid'), { cbapReason: 'bundle_schema_invalid' });
    throw error;
  }
  return bundle;
}

function parsePolicySet(value) {
  try {
    if (!Array.isArray(value) || value.length === 0) throw new TypeError('empty policy set');
    const policies = new Map();
    let prior = null;
    for (const pair of value) {
      if (!Array.isArray(pair) || pair.length !== 2 || !byteString(pair[0], 32) || !byteString(pair[1])) throw new TypeError('bad policy pair');
      if (prior !== null && compareBytes(prior, pair[0]) >= 0) throw new TypeError('unsorted or duplicate policy');
      if (!equalsBytes(sha256Bytes(pair[1]), pair[0])) throw new TypeError('policy digest mismatch');
      prior = Buffer.from(pair[0]);
      policies.set(pair[0].toString('hex'), Buffer.from(pair[1]));
    }
    return policies;
  } catch {
    const error = Object.assign(new Error('policy_set_invalid'), { cbapReason: 'policy_set_invalid' });
    throw error;
  }
}

function parseVerificationTime(value) {
  try {
    let parsed;
    if (typeof value === 'bigint') parsed = value;
    else if (typeof value === 'number' && Number.isSafeInteger(value)) parsed = BigInt(value);
    else if (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value)) parsed = BigInt(value);
    else throw new TypeError('invalid time');
    if (parsed < 0n || parsed > MAX_UINT64) throw new TypeError('time out of range');
    return parsed;
  } catch {
    const error = Object.assign(new Error('verification_time_invalid'), { cbapReason: 'verification_time_invalid' });
    throw error;
  }
}

function fail(reason) {
  return Object.freeze({ ok: false, reason, reasons: [reason], result: null });
}

function filingStatus(now, executedAt, deadline) {
  if (now < executedAt) return 'not_open';
  return now <= deadline ? 'open' : 'closed';
}

export function verifyCbap1({ artifact, trust_roots: trustRootsInput, adapter_config: adapterConfig, verification_time: verificationTime }) {
  try {
    const now = parseVerificationTime(verificationTime);
    if (!exactKeys(artifact, new Set(['@version', 'bundle_cbor', 'bundle_sha256'])) || artifact['@version'] !== ARTIFACT_VERSION
        || typeof artifact.bundle_cbor !== 'string' || !B64URL_RE.test(artifact.bundle_cbor)
        || typeof artifact.bundle_sha256 !== 'string' || !DIGEST_RE.test(artifact.bundle_sha256)) return fail('bundle_schema_invalid');
    const bundleBytes = Buffer.from(artifact.bundle_cbor, 'base64url');
    if (bundleBytes.length === 0 || bundleBytes.toString('base64url') !== artifact.bundle_cbor
        || digestBytes(bundleBytes) !== artifact.bundle_sha256) return fail('outer_encoding_invalid');
    const bundle = parseBundle(bundleBytes);
    const policies = parsePolicySet(bundle.get(8));
    const roots = parseTrustRoots(trustRootsInput);
    if (!roots) return fail('cpo_invalid');

    const cpo = parseSigned(bundle.get(2), 'issuer', validateCpoPayload, 'cpo_invalid', roots);
    const acceptance = parseSigned(bundle.get(3), 'forum', validateAcceptancePayload, 'forum_acceptance_invalid', roots);
    const authorization = parseSigned(bundle.get(4), 'issuer', validateAuthorizationPayload, 'authorization_invalid', roots);
    const executorVerification = parseSigned(bundle.get(5), 'executor', validateExecutorVerificationPayload, 'executor_verification_invalid', roots);
    const execution = parseSigned(bundle.get(6), 'executor', validateExecutionRecordPayload, 'execution_record_invalid', roots);

    const terms = cpo.payload.get(3);
    const actionDigest = sha256Bytes(bundle.get(7));
    if (![terms.get(6), authorization.payload.get(6), executorVerification.payload.get(5), execution.payload.get(6)]
      .every((candidate) => equalsBytes(candidate, actionDigest))) return fail('action_digest_mismatch');

    if (!exactKeys(adapterConfig, ADAPTER_CONFIG_KEYS) || adapterConfig['@version'] !== 'PINTO-CBAP1-ADAPTER-CONFIG-v0.1'
        || adapterConfig.cbap_profile !== 'CBAP-1' || adapterConfig.claim_scope !== 'historical-contestability-binding-only'
        || adapterConfig.expected_abp_digest !== EXPECTED_ABP_DIGEST
        || adapterConfig.source_txt_sha256 !== '6a879935dc516df39e7cb95fdc8c45f982165869981d93763746911826b0b052'
        || typeof adapterConfig.subject_system_id !== 'string' || adapterConfig.subject_system_id.length === 0
        || typeof adapterConfig.authorization_trust_profile_digest !== 'string'
        || adapterConfig.authorization_trust_profile_digest !== trustProfileDigest(roots)
        || cpo.kid !== terms.get(4)
        || !equalsBytes(terms.get(2), EXPECTED_ABP_DIGEST_BYTES)
        || !DIGEST_RE.test(adapterConfig.authorization_trust_profile_digest)
        || terms.get(3).toString('hex') !== adapterConfig.authorization_trust_profile_digest.slice(7)
        || terms.get(10)[0] !== 1 || asUint(terms.get(10)[1]) < 1n
        || terms.get(11)[0] !== 0 || cpo.payload.get(4)[0] !== 0 || cpo.payload.get(5).length !== 0
        || !terms.get(13).some((entry) => entry[0] === 3)
        || !validateCbap1HttpsUri(terms.get(7)[0]) || !validateCbap1HttpsUri(terms.get(7)[1])
        || ![terms.get(8), terms.get(9), terms.get(12), acceptance.payload.get(6), acceptance.payload.get(7)]
          .every((reference) => validateCbap1HttpsUri(reference[0]) && policies.has(reference[1].toString('hex')))
        || !terms.get(13).every((entry) => entry[0] === 3 && validateCbap1HttpsUri(entry[1]))) return fail('profile_binding_mismatch');

    const authorizationId = terms.get(1);
    const validity = terms.get(5);
    if (!equalsBytes(authorization.payload.get(3), authorizationId)
        || authorization.payload.get(4) !== terms.get(4)
        || !equalsBytes(authorization.payload.get(6), terms.get(6))
        || asUint(authorization.payload.get(7)) !== asUint(validity[0])
        || asUint(authorization.payload.get(8)) !== asUint(validity[1])) return fail('authorization_projection_mismatch');

    const forumTerms = [terms.get(1), terms.get(2), terms.get(3), terms.get(4), terms.get(5), terms.get(6), terms.get(7), terms.get(8), terms.get(9), terms.get(10)];
    const forumTermsDigest = hCbap1('agent-contestation-forum-terms-v1', forumTerms);
    if (!equalsBytes(acceptance.payload.get(3), forumTermsDigest)
        || terms.get(7)[2] !== acceptance.kid) return fail('forum_terms_mismatch');
    const acceptanceDigest = sha256Bytes(acceptance.bytes);
    if (!equalsBytes(cpo.payload.get(4)[1], acceptanceDigest)) return fail('acceptance_binding_mismatch');
    const cpoDigest = sha256Bytes(cpo.bytes);
    if (!equalsBytes(authorization.payload.get(9), cpoDigest)) return fail('cpo_binding_mismatch');
    const authorizationDigest = sha256Bytes(authorization.bytes);
    if (!equalsBytes(executorVerification.payload.get(3), authorizationDigest)
        || !equalsBytes(execution.payload.get(3), authorizationDigest)) return fail('authorization_digest_mismatch');

    const nonce = terms.get(16);
    if (!equalsBytes(authorization.payload.get(10), nonce)
        || !equalsBytes(executorVerification.payload.get(4), authorizationId)
        || !equalsBytes(executorVerification.payload.get(5), actionDigest)
        || !equalsBytes(executorVerification.payload.get(6), cpoDigest)
        || executorVerification.payload.get(7) !== 1
        || !equalsBytes(executorVerification.payload.get(9), nonce)) return fail('executor_verification_mismatch');
    const verificationDigest = sha256Bytes(executorVerification.bytes);
    if (!equalsBytes(execution.payload.get(4), verificationDigest)
        || !equalsBytes(execution.payload.get(5), authorizationId)
        || !equalsBytes(execution.payload.get(6), actionDigest)
        || execution.payload.get(7) !== 1
        || !equalsBytes(execution.payload.get(9), nonce)
        || execution.kid !== executorVerification.kid) return fail('execution_record_mismatch');

    const notBefore = asUint(validity[0]);
    const notAfter = asUint(validity[1]);
    const verifiedAt = asUint(executorVerification.payload.get(8));
    const executedAt = asUint(execution.payload.get(8));
    if (!(notBefore <= verifiedAt && verifiedAt <= executedAt && executedAt <= notAfter)) return fail('executor_ordering_invalid');
    const duration = asUint(terms.get(10)[1]);
    if (executedAt > MAX_UINT64 - duration) return fail('filing_deadline_overflow');
    const deadline = executedAt + duration;
    if (asUint(acceptance.payload.get(8)) > notBefore
        || asUint(acceptance.payload.get(4)) > notBefore
        || asUint(acceptance.payload.get(5)) < deadline
        || asUint(terms.get(14)) > verifiedAt
        || asUint(terms.get(15)) < deadline
        || !terms.get(13).some((entry) => asUint(entry[2]) >= deadline)) return fail('filing_horizon_invalid');

    const result = Object.freeze({
      binding: 'valid',
      pre_execution_evidence: 'executor_attested',
      discoverability: 'complete',
      forum_acknowledgement: 'valid_exact',
      forum_operational_status: 'not_checked',
      selection_provenance: 'unilateral',
      access_binding: 'valid',
      notice_evidence: 'not_claimed',
      retrievability: 'not_checked',
      filing_window_status: filingStatus(now, executedAt, deadline),
      policy_freshness: 'indeterminate',
      declared_effect: 'none',
      effect_acceptance: 'not_required',
      effect_trigger: 'not_applicable',
      effect_ordering: 'not_applicable',
      effect_application: 'not_applicable',
      reasons: [],
    });
    return Object.freeze({
      ok: true,
      reason: null,
      reasons: [],
      result,
      action_bytes: bundle.get(7).toString('base64url'),
      action_digest: labelDigest(actionDigest),
      authorization_digest: labelDigest(authorizationDigest),
      cpo_digest: labelDigest(cpoDigest),
      exact_acceptance_digest: labelDigest(acceptanceDigest),
      executor_verification_digest: labelDigest(verificationDigest),
    });
  } catch (error) {
    return fail(error?.cbapReason ?? 'outer_encoding_invalid');
  }
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

function parseActionBytes(value) {
  try {
    const bytes = Buffer.from(value, 'base64url');
    const textValue = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const action = JSON.parse(textValue);
    if (!exactKeys(action, ACTION_KEYS) || action.action_type !== 'account.suspend.1'
        || !text(action.account_ref) || !text(action.policy_event_ref) || jcs(action) !== textValue) return null;
    return action;
  } catch { return null; }
}

export function computeProfileCaid(action) {
  if (!exactKeys(action, ACTION_KEYS) || action.action_type !== 'account.suspend.1'
      || !text(action.account_ref) || !text(action.policy_event_ref)) throw new TypeError('unsupported material action');
  const canonical = Buffer.from(jcs(action), 'utf8');
  const hash = sha256Bytes(canonical);
  return {
    caid: `caid:1:account.suspend.1:jcs-sha256:${hash.toString('base64url')}`,
    action_digest: `sha256:${hash.toString('hex')}`,
    action_bytes: canonical,
  };
}

export function makeCoseSign1ForFixture(payload, kid, privateJwk) {
  /** @type {Map<number, unknown>} */
  const protectedHeaders = new Map(/** @type {Array<[number, unknown]>} */ ([[1, -19], [4, Buffer.from(kid, 'utf8')]]));
  const protectedBytes = encodeDeterministicCbor(protectedHeaders);
  const payloadBytes = encodeDeterministicCbor(payload);
  const sigStructure = encodeDeterministicCbor(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
  const privateKey = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const signature = crypto.sign(null, sigStructure, privateKey);
  return encodeDeterministicCbor(tagged18([protectedBytes, new Map(), payloadBytes, signature]));
}

export default Object.freeze({
  id: ADAPTER_ID,
  version: ADAPTER_VERSION,
  verifyNative(input) {
    const evidenceDigest = digestJson(input.artifact);
    const statusDigest = digestJson(normalizedStatus(input.status));
    const verifiedAt = Math.floor(Date.parse(input.now) / 1_000);
    const native = verifyCbap1({
      artifact: input.artifact,
      trust_roots: input.trust_roots,
      adapter_config: input.adapter_config,
      verification_time: verifiedAt,
    });
    const fallbackReplay = digestJson({ native_protocol: NATIVE_PROTOCOL, artifact_digest: evidenceDigest });
    return {
      native_verification: native.ok ? 'VERIFIED' : 'FAILED',
      acceptance: native.ok ? 'ACCEPTED' : 'REJECTED',
      evidence_digest: evidenceDigest,
      status_digest: statusDigest,
      evidence_role: 'contestability-binding',
      subject: {
        id: exactKeys(input.adapter_config, ADAPTER_CONFIG_KEYS) ? input.adapter_config.subject_system_id : 'system:invalid-cbap1',
        kind: 'system',
      },
      replay_unit: native.ok
        ? digestJson({ native_protocol: NATIVE_PROTOCOL, authorization_digest: native.authorization_digest })
        : fallbackReplay,
      reasons: native.ok ? [] : [`cbap1:${native.reason}`],
    };
  },
  mapAction(input) {
    if (input.native.native_verification !== 'VERIFIED') {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_verification_required'] };
    }
    const profileValid = input.profile
      && input.profile.version === '0.1.0'
      && input.profile.mapper_id === MAPPER_ID
      && input.profile.resolver.id === RESOLVER_DESCRIPTOR.implementation
      && input.profile.resolver.version === RESOLVER_DESCRIPTOR.version
      && input.profile.resolver.implementation_digest === RESOLVER_DIGEST
      && jcs(input.profile.definition) === jcs(PROFILE_DEFINITION)
      && input.profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
      && input.profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
      && input.profile.semantic_equivalence.omitted_material_fields.length === 0
      && input.profile.semantic_equivalence.omitted_nonmaterial_fields.length === 0;
    if (!profileValid) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_not_supported'] };
    }
    const native = verifyCbap1({
      artifact: input.artifact,
      trust_roots: input.trust_roots,
      adapter_config: input.adapter_config,
      verification_time: Math.floor(Date.parse(input.now) / 1_000),
    });
    if (!native.ok) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: [`cbap1:${native.reason}`] };
    }
    const action = parseActionBytes(native.action_bytes);
    if (!action) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_action_projection_refused'] };
    }
    const projected = computeProfileCaid(action);
    if (projected.action_digest !== native.action_digest) {
      return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_action_digest_mismatch'] };
    }
    return { mapping: 'MATCH', caid: projected.caid, action_digest: projected.action_digest, reasons: [] };
  },
});
