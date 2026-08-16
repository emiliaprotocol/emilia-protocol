// SPDX-License-Identifier: Apache-2.0
/**
 * Budget cose-ml-dsa adapter for draft-mcgraw-httpapi-agent-budget-03.
 *
 * The adapter accepts tagged or untagged deterministic COSE_Sign1, verifies
 * the RFC 9964 ML-DSA-65 signature through a pinned pure backend, validates all
 * fourteen Budget claim slots used by the exact-request profile, and delegates
 * field-11 semantics to a separately pinned pure chain verifier. Verification
 * and AEB/Gate authorization remain distinct.
 */
import crypto from 'node:crypto';
// @ts-expect-error -- governed JavaScript implementation, runtime checked.
import { computeCaid } from '../vendor/caid.mjs';
import { digestAeb, } from './aeb-adapter-contract.js';
export const MCGRAW_BUDGET_DRAFT_REVISION = 'draft-mcgraw-httpapi-agent-budget-03';
export const MCGRAW_BUDGET_AEB_ADAPTER_ID = 'native:mcgraw-budget-cose-ml-dsa';
export const MCGRAW_BUDGET_AEB_ADAPTER_VERSION = '1';
export const MCGRAW_BUDGET_CONFIG_VERSION = 'AEB-MCGRAW-BUDGET-CONFIG-v1';
export const MCGRAW_BUDGET_TRUST_ROOT_VERSION = 'AEB-MCGRAW-BUDGET-ML-DSA-ROOT-v1';
export const MCGRAW_BUDGET_MAPPING_VERSION = 'AEB-MCGRAW-BUDGET-CAID-MAPPING-v1';
export const MCGRAW_BUDGET_MAPPER_ID = 'mapper:mcgraw-budget-exact-request-v1';
/** RFC 9964 COSE Algorithms registry value for ML-DSA-65. */
export const MCGRAW_BUDGET_COSE_ALGORITHM = -49;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const HEX_32_RE = /^[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/;
const DECIMAL_RE = /^(?:0|[1-9][0-9]*)(?:\.([0-9]+))?$/;
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'action_type', 'issuer', 'verifier_binding',
    'required_authority', 'budget_unit', 'minimum_remaining_budget', 'challenge_nonce',
    'content_type', 'representation_digest_semantics', 'require_request_binding',
    'clock_skew_seconds', 'max_lifetime_seconds', 'max_status_age_seconds',
    'chain_verifier', 'mldsa_verifier',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const DESCRIPTOR_KEYS = new Set(['id', 'version', 'implementation_digest']);
const ROOT_KEYS = new Set(['@version', 'issuer', 'key_id', 'algorithm', 'public_key']);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const EXPECTED_KEYS = new Set(['action_type', 'delegation_action']);
const DELEGATION_ACTION_KEYS = new Set([
    'delegated_requester', 'required_authority', 'method', 'origin', 'target', 'body_sha256',
]);
const MAPPING_KEYS = new Set([
    '@version', 'native_protocol', 'projection', 'action_type', 'suite', 'definitions',
]);
const MAX_COSE_BYTES = 65_536;
const ML_DSA_65_PUBLIC_KEY_BYTES = 1_952;
const ML_DSA_65_SIGNATURE_BYTES = 3_309;
export function tagDeterministicCbor(tag, value) {
    if (!Number.isSafeInteger(tag) || tag < 0)
        throw new TypeError('invalid CBOR tag');
    return Object.freeze({ cbor_tag: tag, value });
}
function cborHead(major, value) {
    const number = typeof value === 'bigint' ? value : BigInt(value);
    if (number < 0n || number > 0xffffffffffffffffn)
        throw new TypeError('CBOR integer out of range');
    if (number < 24n)
        return Buffer.from([(major << 5) | Number(number)]);
    if (number <= 0xffn)
        return Buffer.from([(major << 5) | 24, Number(number)]);
    if (number <= 0xffffn) {
        const out = Buffer.alloc(3);
        out[0] = (major << 5) | 25;
        out.writeUInt16BE(Number(number), 1);
        return out;
    }
    if (number <= 0xffffffffn) {
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
function encodeCbor(value, depth) {
    if (depth > 32)
        throw new TypeError('CBOR nesting too deep');
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        const bytes = Buffer.from(value);
        return Buffer.concat([cborHead(2, bytes.length), bytes]);
    }
    if (typeof value === 'string') {
        const bytes = Buffer.from(value, 'utf8');
        return Buffer.concat([cborHead(3, bytes.length), bytes]);
    }
    if (typeof value === 'number' && Number.isSafeInteger(value)) {
        return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    }
    if (Array.isArray(value)) {
        return Buffer.concat([cborHead(4, value.length), ...value.map((entry) => encodeCbor(entry, depth + 1))]);
    }
    if (value instanceof Map) {
        const entries = [...value.entries()].map(([key, entry]) => ({
            key: encodeCbor(key, depth + 1), value: encodeCbor(entry, depth + 1),
        }));
        // RFC 8949 Section 4.2.1 deterministic order: bytewise lexicographic on the
        // encoded key bytes. NOT the retired RFC 7049 length-first order; the two
        // coincide for this profile's key domain (non-negative integer labels and
        // text keys shorter than 24 bytes) but diverge once negative integer keys
        // or long text keys mix in, e.g. {100: "c", -1: "b"}.
        entries.sort((left, right) => Buffer.compare(left.key, right.key));
        for (let index = 1; index < entries.length; index += 1) {
            if (entries[index - 1].key.equals(entries[index].key))
                throw new TypeError('duplicate CBOR map key');
        }
        return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap((entry) => [entry.key, entry.value])]);
    }
    if (value && typeof value === 'object' && Object.keys(value).length === 2
        && Object.hasOwn(value, 'cbor_tag') && Object.hasOwn(value, 'value')) {
        const tagged = value;
        return Buffer.concat([cborHead(6, tagged.cbor_tag), encodeCbor(tagged.value, depth + 1)]);
    }
    throw new TypeError('value outside deterministic CBOR profile');
}
/**
 * Deterministic CBOR encoding per RFC 8949 Section 4.2.1: shortest-form
 * argument encoding and bytewise-lexicographic map key order on the encoded
 * key bytes. The decode path round-trip-checks incoming bytes against this
 * encoder, so the adapter refuses non-deterministic encodings by construction.
 * For a Result-typed RFC 8949 codec with refusal reasons instead of throws,
 * see encodeDeterministicCbor8949 in receipt-cose-encoding.ts.
 */
export function encodeDeterministicCbor(value) {
    return encodeCbor(value, 0);
}
function readCborLength(state, additional) {
    const read = (length) => {
        if (state.offset + length > state.bytes.length)
            throw new TypeError('truncated CBOR');
        const out = state.bytes.subarray(state.offset, state.offset + length);
        state.offset += length;
        return out;
    };
    if (additional < 24)
        return BigInt(additional);
    if (additional === 24) {
        const value = BigInt(read(1)[0]);
        if (value < 24n)
            throw new TypeError('non-shortest CBOR integer');
        return value;
    }
    if (additional === 25) {
        const value = BigInt(read(2).readUInt16BE());
        if (value <= 0xffn)
            throw new TypeError('non-shortest CBOR integer');
        return value;
    }
    if (additional === 26) {
        const value = BigInt(read(4).readUInt32BE());
        if (value <= 0xffffn)
            throw new TypeError('non-shortest CBOR integer');
        return value;
    }
    if (additional === 27) {
        const value = read(8).readBigUInt64BE();
        if (value <= 0xffffffffn)
            throw new TypeError('non-shortest CBOR integer');
        return value;
    }
    throw new TypeError('indefinite or reserved CBOR value');
}
function decodeCbor(state, depth) {
    if (depth > 32 || state.nodes++ > 1_024 || state.offset >= state.bytes.length) {
        throw new TypeError('CBOR limits exceeded');
    }
    const first = state.bytes[state.offset++];
    const major = first >> 5;
    const length = readCborLength(state, first & 31);
    if (length > BigInt(Number.MAX_SAFE_INTEGER))
        throw new TypeError('CBOR length too large');
    const count = Number(length);
    if (major === 0)
        return count;
    if (major === 1)
        return -1 - count;
    if (major === 2 || major === 3) {
        if (state.offset + count > state.bytes.length)
            throw new TypeError('truncated CBOR string');
        const bytes = state.bytes.subarray(state.offset, state.offset + count);
        state.offset += count;
        if (major === 2)
            return Buffer.from(bytes);
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!Buffer.from(text, 'utf8').equals(bytes))
            throw new TypeError('invalid CBOR UTF-8');
        return text;
    }
    if (major === 4) {
        return Array.from({ length: count }, () => decodeCbor(state, depth + 1));
    }
    if (major === 5) {
        const map = new Map();
        const keys = new Set();
        for (let index = 0; index < count; index += 1) {
            const start = state.offset;
            const key = decodeCbor(state, depth + 1);
            const encodedKey = state.bytes.subarray(start, state.offset).toString('hex');
            if (keys.has(encodedKey))
                throw new TypeError('duplicate CBOR map key');
            keys.add(encodedKey);
            map.set(key, decodeCbor(state, depth + 1));
        }
        return map;
    }
    if (major === 6)
        return tagDeterministicCbor(count, decodeCbor(state, depth + 1));
    throw new TypeError('unsupported CBOR major type');
}
function decodeDeterministicCbor(bytes) {
    const state = { bytes, offset: 0, nodes: 0 };
    const value = decodeCbor(state, 0);
    if (state.offset !== bytes.length || !encodeDeterministicCbor(value).equals(bytes)) {
        throw new TypeError('non-deterministic CBOR');
    }
    return value;
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, keys) {
    return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function canonicalB64url(value, length) {
    if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1)
        return false;
    try {
        const bytes = Buffer.from(value, 'base64url');
        return bytes.length > 0 && bytes.toString('base64url') === value
            && (length === undefined || bytes.length === length);
    }
    catch {
        return false;
    }
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_native_value: true });
    }
}
function descriptor(value) {
    return isRecord(value) && exactKeys(value, DESCRIPTOR_KEYS)
        && nonEmptyString(value.id) && nonEmptyString(value.version)
        && typeof value.implementation_digest === 'string' && DIGEST_RE.test(value.implementation_digest);
}
function validDecimal(value) {
    return typeof value === 'string' && DECIMAL_RE.test(value);
}
function compareDecimal(left, right) {
    const leftMatch = DECIMAL_RE.exec(left);
    const rightMatch = DECIMAL_RE.exec(right);
    const scale = Math.max(leftMatch[1]?.length ?? 0, rightMatch[1]?.length ?? 0);
    const integer = (value) => {
        const [whole, fraction = ''] = value.split('.');
        return BigInt(`${whole}${fraction.padEnd(scale, '0')}`);
    };
    const a = integer(left);
    const b = integer(right);
    return a < b ? -1 : a > b ? 1 : 0;
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== MCGRAW_BUDGET_CONFIG_VERSION
        || value.evidence_role !== 'delegated-authority'
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || typeof value.subject.id !== 'string' || !ID_RE.test(value.subject.id)
        || value.subject.kind !== 'workload' || !nonEmptyString(value.subject.native_id)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !nonEmptyString(value.issuer) || !nonEmptyString(value.verifier_binding)
        || !nonEmptyString(value.required_authority) || !nonEmptyString(value.budget_unit)
        || !validDecimal(value.minimum_remaining_budget)
        || !canonicalB64url(value.challenge_nonce)
        || value.content_type !== 'application/delegation-proof+cose'
        || value.representation_digest_semantics !== 'http-request-content-sha256'
        || typeof value.require_request_binding !== 'boolean'
        || !nonNegativeInteger(value.clock_skew_seconds) || value.clock_skew_seconds > 60
        || !nonNegativeInteger(value.max_lifetime_seconds)
        || value.max_lifetime_seconds < 1 || value.max_lifetime_seconds > 900
        || !nonNegativeInteger(value.max_status_age_seconds)
        || !descriptor(value.chain_verifier) || !descriptor(value.mldsa_verifier))
        return null;
    const challenge = Buffer.from(value.challenge_nonce, 'base64url');
    if (challenge.length < 16 || challenge.length > 64)
        return null;
    return structuredClone(value);
}
function parseRoots(value, config) {
    if (!Array.isArray(value) || value.length < 1)
        return null;
    const roots = [];
    const kids = new Set();
    for (const candidate of value) {
        if (!isRecord(candidate) || !exactKeys(candidate, ROOT_KEYS)
            || candidate['@version'] !== MCGRAW_BUDGET_TRUST_ROOT_VERSION
            || candidate.issuer !== config.issuer || candidate.algorithm !== 'ML-DSA-65'
            || !canonicalB64url(candidate.key_id)
            || !canonicalB64url(candidate.public_key, ML_DSA_65_PUBLIC_KEY_BYTES)
            || kids.has(String(candidate.key_id)))
            return null;
        kids.add(String(candidate.key_id));
        roots.push({
            ...structuredClone(candidate),
            kid: Buffer.from(String(candidate.key_id), 'base64url'),
            publicKey: Buffer.from(String(candidate.public_key), 'base64url'),
        });
    }
    return roots;
}
function matchingVerifier(implementation, pin, method) {
    return implementation.id === pin.id && implementation.version === pin.version
        && implementation.implementation_digest === pin.implementation_digest
        && typeof method === 'function';
}
function parsePins(value) {
    const config = parseConfig(value?.config);
    if (!config)
        throw new TypeError('invalid McGraw Budget constructor config');
    const roots = parseRoots(value?.trust_roots, config);
    if (!roots
        || !matchingVerifier(value.chain_verifier, config.chain_verifier, value.chain_verifier?.verify)
        || !matchingVerifier(value.mldsa_verifier, config.mldsa_verifier, value.mldsa_verifier?.verify)) {
        throw new TypeError('invalid McGraw Budget constructor pins');
    }
    return {
        config,
        roots,
        chainVerifier: value.chain_verifier,
        mldsaVerifier: value.mldsa_verifier,
        configDigest: safeDigest(config),
        rootsDigest: safeDigest(value.trust_roots),
        challenge: Buffer.from(config.challenge_nonce, 'base64url'),
    };
}
function parseInstant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
        return NaN;
    return Date.parse(value);
}
function statusDigest(status) {
    return safeDigest({
        checked_at: status?.checked_at, expires_at: status?.expires_at,
        revocation_checked: status?.revocation_checked, revoked: status?.revoked,
        consumed: status?.consumed, unavailable: status?.unavailable === true,
    });
}
function statusDisposition(status, now, maxAge) {
    if (!isRecord(status) || !Object.keys(status).every((key) => STATUS_KEYS.has(key))
        || !['checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed']
            .every((key) => Object.hasOwn(status, key))) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
    }
    const reasons = [];
    if (status.unavailable === true)
        reasons.push('status_unavailable');
    if (status.revoked === true)
        reasons.push('evidence_revoked');
    if (status.consumed === true)
        reasons.push('evidence_consumed');
    if (status.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    const nowMs = parseInstant(now);
    const checked = parseInstant(status.checked_at);
    const expires = parseInstant(status.expires_at);
    if (![nowMs, checked, expires].every(Number.isFinite))
        reasons.push('status_time_indeterminate');
    else {
        const age = Math.floor((nowMs - checked) / 1000);
        if (checked > nowMs)
            reasons.push('status_checked_in_future');
        if (checked >= expires || nowMs >= expires)
            reasons.push('status_expired');
        if (age < 0 || age > maxAge)
            reasons.push('status_too_old');
    }
    const unique = [...new Set(reasons)].sort();
    if (status.revoked === true || status.consumed === true)
        return { acceptance: 'REJECTED', reasons: unique };
    return unique.length ? { acceptance: 'INDETERMINATE', reasons: unique } : { acceptance: 'ACCEPTED', reasons: [] };
}
function exactExpectedAction(value, config) {
    if (!isRecord(value) || !exactKeys(value, EXPECTED_KEYS) || value.action_type !== config.action_type
        || !isRecord(value.delegation_action) || !exactKeys(value.delegation_action, DELEGATION_ACTION_KEYS))
        return false;
    const action = value.delegation_action;
    if (action.delegated_requester !== config.subject.native_id
        || action.required_authority !== config.required_authority
        || !nonEmptyString(action.method) || /\s/.test(action.method)
        || !nonEmptyString(action.origin) || !nonEmptyString(action.target)
        || !String(action.target).startsWith('/') || String(action.target).includes('#')
        || typeof action.body_sha256 !== 'string' || !HEX_32_RE.test(action.body_sha256))
        return false;
    try {
        const url = new URL(String(action.origin));
        return ['http:', 'https:'].includes(url.protocol)
            && url.origin === action.origin && url.pathname === '/' && url.search === '' && url.hash === '';
    }
    catch {
        return false;
    }
}
function fallbackNative(input, pins) {
    const evidenceDigest = typeof input?.artifact === 'string' && canonicalB64url(input.artifact)
        ? `sha256:${crypto.createHash('sha256').update(Buffer.from(input.artifact, 'base64url')).digest('hex')}`
        : safeDigest(input?.artifact);
    return {
        native_verification: 'FAILED', acceptance: 'INDETERMINATE', evidence_digest: evidenceDigest,
        status_digest: statusDigest(input?.status), evidence_role: pins.config.evidence_role,
        subject: { id: pins.config.subject.id, kind: 'workload' }, replay_unit: evidenceDigest, reasons: [],
    };
}
function reject(result, reason) {
    result.acceptance = 'REJECTED';
    result.reasons = [reason];
    return result;
}
function mapExact(value, expectedKeys) {
    if (!(value instanceof Map) || value.size !== expectedKeys.length)
        return false;
    return expectedKeys.every((key) => value.has(key));
}
function verifyNative(input, pins) {
    const result = fallbackNative(input, pins);
    if (safeDigest(input.adapter_config) !== pins.configDigest || safeDigest(input.trust_roots) !== pins.rootsDigest) {
        return reject(result, 'mcgraw-budget:constructor_pin_mismatch');
    }
    if (!exactExpectedAction(input.expected_action, pins.config)) {
        result.reasons = ['mcgraw-budget:missing_or_ambiguous_exact_action'];
        return result;
    }
    if (!canonicalB64url(input.artifact))
        return reject(result, 'mcgraw-budget:artifact_encoding_invalid');
    const coseBytes = Buffer.from(input.artifact, 'base64url');
    if (coseBytes.length > MAX_COSE_BYTES)
        return reject(result, 'mcgraw-budget:artifact_too_large');
    let decoded;
    try {
        decoded = decodeDeterministicCbor(coseBytes);
    }
    catch {
        return reject(result, 'mcgraw-budget:cbor_invalid');
    }
    if (isRecord(decoded) && Object.hasOwn(decoded, 'cbor_tag')) {
        const tagged = decoded;
        if (tagged.cbor_tag !== 18)
            return reject(result, 'mcgraw-budget:cose_tag_invalid');
        decoded = tagged.value;
    }
    if (!Array.isArray(decoded) || decoded.length !== 4
        || !Buffer.isBuffer(decoded[0]) || !(decoded[1] instanceof Map) || decoded[1].size !== 0
        || !Buffer.isBuffer(decoded[2]) || !Buffer.isBuffer(decoded[3])) {
        return reject(result, 'mcgraw-budget:cose_structure_invalid');
    }
    const [protectedBytes, , payloadBytes, signature] = decoded;
    if (signature.length !== ML_DSA_65_SIGNATURE_BYTES)
        return reject(result, 'mcgraw-budget:signature_size_invalid');
    let protectedMap;
    let claimsValue;
    try {
        protectedMap = decodeDeterministicCbor(protectedBytes);
        claimsValue = decodeDeterministicCbor(payloadBytes);
    }
    catch {
        return reject(result, 'mcgraw-budget:protected_or_claims_invalid');
    }
    if (!mapExact(protectedMap, [1, 3, 4])
        || protectedMap.get(1) !== MCGRAW_BUDGET_COSE_ALGORITHM
        || protectedMap.get(3) !== pins.config.content_type
        || !Buffer.isBuffer(protectedMap.get(4))) {
        return reject(result, 'mcgraw-budget:protected_header_invalid');
    }
    const kid = protectedMap.get(4);
    const root = pins.roots.find((candidate) => candidate.kid.equals(kid));
    if (!root)
        return reject(result, 'mcgraw-budget:issuer_key_not_pinned');
    const sigStructure = encodeDeterministicCbor(['Signature1', protectedBytes, Buffer.alloc(0), payloadBytes]);
    let signatureValid = false;
    try {
        signatureValid = pins.mldsaVerifier.verify(signature, sigStructure, root.publicKey) === true;
    }
    catch {
        signatureValid = false;
    }
    if (!signatureValid)
        return reject(result, 'mcgraw-budget:signature_invalid');
    const claimKeys = pins.config.require_request_binding
        ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        : [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    if (!mapExact(claimsValue, claimKeys))
        return reject(result, 'mcgraw-budget:claims_schema_invalid');
    const claims = claimsValue;
    if (claims.get(1) !== 1 || claims.get(2) !== pins.config.issuer
        || claims.get(3) !== pins.config.subject.native_id
        || !validDecimal(claims.get(4)) || !validDecimal(claims.get(5))
        || claims.get(6) !== pins.config.budget_unit
        || !Array.isArray(claims.get(7)) || !claims.get(7).every(nonEmptyString)
        || new Set(claims.get(7)).size !== claims.get(7).length
        || !claims.get(7).includes(pins.config.required_authority)
        || !Number.isSafeInteger(claims.get(8)) || !Number.isSafeInteger(claims.get(9))
        || !Buffer.isBuffer(claims.get(10)) || !claims.get(10).equals(pins.challenge)
        || !Buffer.isBuffer(claims.get(11)) || claims.get(11).length === 0
        || !Buffer.isBuffer(claims.get(12)) || claims.get(12).length !== 32
        || claims.get(13) !== pins.config.verifier_binding) {
        return reject(result, 'mcgraw-budget:claims_invalid');
    }
    const total = claims.get(4);
    const remaining = claims.get(5);
    if (compareDecimal(total, remaining) < 0
        || compareDecimal(remaining, pins.config.minimum_remaining_budget) < 0) {
        return reject(result, 'mcgraw-budget:budget_insufficient');
    }
    const issuedAt = Number(claims.get(8));
    const expiresAt = Number(claims.get(9));
    const nowMs = parseInstant(input.now);
    if (!Number.isFinite(nowMs)) {
        result.reasons = ['mcgraw-budget:verification_time_invalid'];
        return result;
    }
    if (expiresAt <= issuedAt || expiresAt - issuedAt > pins.config.max_lifetime_seconds * 1000
        || issuedAt > nowMs + pins.config.clock_skew_seconds * 1000
        || expiresAt <= nowMs - pins.config.clock_skew_seconds * 1000) {
        return reject(result, 'mcgraw-budget:time_window_invalid');
    }
    const action = input.expected_action.delegation_action;
    const bodyHash = Buffer.from(String(action.body_sha256), 'hex');
    if (!claims.get(12).equals(bodyHash))
        return reject(result, 'mcgraw-budget:representation_digest_mismatch');
    if (pins.config.require_request_binding) {
        const binding = claims.get(14);
        const expectedUriHash = crypto.createHash('sha256').update(Buffer.from(String(action.target), 'utf8')).digest();
        if (!mapExact(binding, ['method', 'uri-h', 'origin', 'body-h'])
            || binding.get('method') !== action.method || binding.get('origin') !== action.origin
            || !Buffer.isBuffer(binding.get('uri-h')) || !binding.get('uri-h').equals(expectedUriHash)
            || !Buffer.isBuffer(binding.get('body-h')) || !binding.get('body-h').equals(bodyHash)) {
            return reject(result, 'mcgraw-budget:request_binding_mismatch');
        }
    }
    let chain;
    try {
        chain = pins.chainVerifier.verify({
            chain: claims.get(11),
            issuer: String(claims.get(2)), delegated_requester: String(claims.get(3)),
            issued_at_ms: issuedAt, expires_at_ms: expiresAt, now: input.now,
        });
    }
    catch {
        result.reasons = ['mcgraw-budget:chain_verifier_error'];
        return result;
    }
    if (!chain || chain.verified !== true) {
        return reject(result, `mcgraw-budget:${nonEmptyString(chain?.reason) ? chain.reason : 'chain_not_verified'}`);
    }
    result.replay_unit = safeDigest({
        protocol: MCGRAW_BUDGET_DRAFT_REVISION,
        issuer: claims.get(2), delegated_requester: claims.get(3),
        challenge_nonce: Buffer.from(claims.get(10)).toString('base64url'),
        proof_digest: result.evidence_digest,
    });
    result.native_verification = 'VERIFIED';
    const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    return result;
}
export function createMcGrawBudgetActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('invalid McGraw Budget action type');
    return {
        '@version': MCGRAW_BUDGET_MAPPING_VERSION,
        native_protocol: MCGRAW_BUDGET_DRAFT_REVISION,
        projection: 'mcgraw-budget-exact-request-v1', action_type: actionType, suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [{ name: 'action_type', type: 'string' }, { name: 'delegation_action', type: 'object' }],
                optional_fields: [],
            }],
    };
}
function validMapping(profile, config) {
    return isRecord(profile) && profile.version === MCGRAW_BUDGET_MAPPING_VERSION
        && profile.mapper_id === MCGRAW_BUDGET_MAPPER_ID && isRecord(profile.resolver)
        && profile.resolver.id === MCGRAW_BUDGET_MAPPER_ID && profile.resolver.version === '1'
        && typeof profile.resolver.implementation_digest === 'string' && DIGEST_RE.test(profile.resolver.implementation_digest)
        && isRecord(profile.semantic_equivalence)
        && profile.semantic_equivalence.assertion === 'EQUIVALENT_UNDER_PROFILE'
        && profile.semantic_equivalence.loss_policy === 'NO_MATERIAL_FIELD_LOSS'
        && Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        && profile.semantic_equivalence.omitted_material_fields.length === 0
        && Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        && isRecord(profile.definition) && exactKeys(profile.definition, MAPPING_KEYS)
        && safeDigest(profile.definition) === safeDigest(createMcGrawBudgetActionDefinition(config.action_type));
}
function mapAction(input, pins) {
    if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
    }
    if (safeDigest(input.adapter_config) !== pins.configDigest || safeDigest(input.trust_roots) !== pins.rootsDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
    }
    if (!validMapping(input.profile, pins.config) || !exactExpectedAction(input.expected_action, pins.config)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_or_action_invalid'] };
    }
    const actionDigest = safeDigest(input.expected_action);
    let computed;
    try {
        computed = computeCaid(input.expected_action, {
            suite: 'jcs-sha256', definitions: input.profile.definition.definitions,
        });
    }
    catch {
        computed = null;
    }
    if (!isRecord(computed) || typeof computed.caid !== 'string'
        || computed.digest !== actionDigest || typeof computed.digest !== 'string') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
    }
    return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}
export function createMcGrawBudgetAebAdapter(constructorPins) {
    const pins = parsePins(constructorPins);
    return Object.freeze({
        id: MCGRAW_BUDGET_AEB_ADAPTER_ID,
        version: MCGRAW_BUDGET_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input, pins);
            }
            catch {
                const result = fallbackNative(input, pins);
                result.reasons = ['mcgraw-budget:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                return mapAction(input, pins);
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mcgraw-budget:unexpected_mapping_error'] };
            }
        },
    });
}
//# sourceMappingURL=aeb-mcgraw-delegation-adapter.js.map