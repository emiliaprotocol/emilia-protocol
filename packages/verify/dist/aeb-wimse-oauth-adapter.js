// SPDX-License-Identifier: Apache-2.0
/**
 * Revision-pinned experimental WIMSE/OAuth/SPT evidence adapter for AEB.
 *
 * This adapter verifies native compact JWS/JWT values and an RFC 9421
 * WIMSE HTTP Message Signature. It does not define a transport format.
 * The artifact object is only the AEB invocation envelope carrying the
 * exact HTTP fields and native token values observed by the relying party.
 *
 * The constructor pins every issuer, Ed25519 key, algorithm, audience,
 * trust domain, workload subject, evidence role, and maximum age. Artifact
 * headers and claims never select verification keys or broaden those pins.
 *
 * Source lock:
 *   draft-ietf-wimse-http-signature-06
 *   draft-ietf-wimse-workload-creds-02
 *   draft-ietf-wimse-identifier-02
 *   draft-ietf-wimse-wpt-02
 *   draft-ietf-oauth-transaction-tokens-11
 *   draft-coetzee-oauth-spt-txn-tokens-03
 *
 * SPT-Txn-03 leaves the exact full-chain parent and transaction-context-hash
 * claim names unspecified. Consequently, an optional SPT TXN is checked only
 * as a pinned signed intent-binding adjunct. It never supplies a human role or
 * a standalone SPT authorization result.
 */
import crypto from 'node:crypto';
// The CAID reference implementation is JavaScript and intentionally has no
// TypeScript declaration surface in this repository.
// @ts-expect-error -- checked at runtime and narrowed below.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeStrictJson, strictJsonGate } from './strict-json.js';
export const WIMSE_OAUTH_SPT_AEB_ADAPTER_ID = 'native:wimse-http-signature-oauth-txn-spt-intent';
export const WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION = '3';
export const WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION = 'AEB-WIMSE-OAUTH-SPT-CONFIG-v3';
export const WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION = 'AEB-WIMSE-OAUTH-SPT-ED25519-ROOT-v1';
export const WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION = 'AEB-WIMSE-OAUTH-SPT-CAID-MAPPING-v2';
export const WIMSE_OAUTH_SPT_CAID_MAPPER_ID = 'mapper:wimse-oauth-spt-exact-request-v2';
export const WIMSE_OAUTH_SPT_MAPPING_PROFILE_ID = 'wimse-oauth-spt-exact-request-v2';
export const WIMSE_OAUTH_SPT_MAPPING_REGISTRY_REF = 'mapping:wimse-oauth-spt-exact-request-v2';
export const WIMSE_OAUTH_SPT_OMITTED_NONMATERIAL_FIELDS = Object.freeze([
    'wit.token_bytes',
    'wit.header.alg',
    'wit.header.typ',
    'wit.header.kid',
    'wit.iss',
    'wit.sub',
    'wit.iat',
    'wit.nbf',
    'wit.exp',
    'wit.jti',
    'wit.cnf',
    'oauth.token_bytes',
    'oauth.header.alg',
    'oauth.header.typ',
    'oauth.header.kid',
    'oauth.iss',
    'oauth.aud',
    'oauth.sub',
    'oauth.txn',
    'oauth.req_wl',
    'oauth.iat',
    'oauth.nbf',
    'oauth.exp',
    'wpt.token_bytes',
    'wpt.header.alg',
    'wpt.header.typ',
    'wpt.aud',
    'wpt.jti',
    'wpt.wth',
    'wpt.tth',
    'wpt.oth',
    'wpt.iat',
    'wpt.nbf',
    'wpt.exp',
    'http.body_bytes',
    'http.signature_input.components',
    'http_signature.created',
    'http_signature.expires',
    'http_signature.nonce',
    'http_signature.tag',
    'http_signature.signature_bytes',
    'oauth_transaction_challenge.token_bytes',
    'oauth_transaction_access_token.token_bytes',
    'spt.token_bytes',
    'spt.header.alg',
    'spt.header.kid',
    'spt.iss',
    'spt.sub',
    'spt.aud',
    'spt.iat',
    'spt.nbf',
    'spt.exp',
    'spt.jti',
    'spt.txn_token_type',
    'spt.human_anchor',
    'spt.holder_key',
    'spt.spt_intent_digest',
]);
export const WIMSE_HTTP_SIGNATURE_REVISION = 'draft-ietf-wimse-http-signature-06';
export const WIMSE_WORKLOAD_CREDS_REVISION = 'draft-ietf-wimse-workload-creds-02';
export const WIMSE_WORKLOAD_IDENTIFIER_REVISION = 'draft-ietf-wimse-identifier-02';
export const WIMSE_WPT_REVISION = 'draft-ietf-wimse-wpt-02';
export const OAUTH_TRANSACTION_TOKENS_REVISION = 'draft-ietf-oauth-transaction-tokens-11';
export const SPT_TRANSACTION_TOKENS_REVISION = 'draft-coetzee-oauth-spt-txn-tokens-03';
export const OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE = 'oauth-transaction-token:trust-domain-receiving-workload-txn';
const SOURCE_REVISIONS = Object.freeze([
    WIMSE_HTTP_SIGNATURE_REVISION,
    WIMSE_WORKLOAD_CREDS_REVISION,
    WIMSE_WORKLOAD_IDENTIFIER_REVISION,
    WIMSE_WPT_REVISION,
    OAUTH_TRANSACTION_TOKENS_REVISION,
    SPT_TRANSACTION_TOKENS_REVISION,
]);
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,255}$/;
const TRUST_DOMAIN_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const METHOD_RE = /^[A-Z][A-Z0-9!#$%&'*+\-.^_`|~]*$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CONTENT_DIGEST_RE = /^sha-256=:([A-Za-z0-9+/]+={0,2}):$/;
const WORKLOAD_SUBJECT_RE = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)(\/[^?#]*)$/;
const WORKLOAD_PATH_SEGMENT_RE = /^[A-Za-z0-9._~-]+$/;
const MAX_WORKLOAD_SUBJECT_OCTETS = 2_048;
const MAX_REQUEST_METHOD_OCTETS = 32;
const MAX_REQUEST_TARGET_OCTETS = 8_192;
const MAX_REQUEST_BODY_OCTETS = 262_144;
const MAX_REQUEST_HEADER_COUNT = 32;
const MAX_REQUEST_HEADER_NAME_OCTETS = 256;
const MAX_REQUEST_HEADER_VALUE_OCTETS = 131_072;
const MAX_REQUEST_HEADER_SECTION_OCTETS = 262_144;
const MAX_SIGNATURE_COMPONENT_COUNT = 9;
const MAX_ARTIFACT_NODES = 10_000;
const MAX_ARTIFACT_STRING_OCTETS = 786_432;
const CONFIG_KEYS = new Set([
    '@version',
    'evidence_role',
    'subject',
    'trust_domain',
    'receiving_workload',
    'oauth_requesting_workload',
    'wimse_audience',
    'oauth_audience',
    'oauth_subject',
    'oauth_scope',
    'spt_audience',
    'spt_subject',
    'spt_holder_key',
    'other_token_headers',
    'action_type',
    'clock_skew_seconds',
    'max_age_seconds',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const MAX_AGE_KEYS = new Set([
    'wit',
    'wpt',
    'oauth_txn',
    'spt_txn',
    'http_signature',
    'status',
]);
const MAPPING_PROFILE_KEYS = new Set([
    'version', 'definition', 'registry_entry_ref', 'mapper_id', 'resolver',
    'semantic_equivalence', 'profile_digest',
]);
const ISSUER_ROOT_KEYS = new Set([
    '@version', 'use', 'issuer', 'key_id', 'algorithm', 'public_key',
]);
const HOLDER_ROOT_KEYS = new Set([
    '@version', 'use', 'subject', 'key_id', 'algorithm', 'public_key',
]);
const ARTIFACT_KEYS = new Set([
    'wit', 'wpt', 'txn_token', 'request', 'spt_txn', 'spt_intent',
]);
const REQUEST_KEYS = new Set(['method', 'target_uri', 'headers', 'body']);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const WIT_HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const WPT_HEADER_KEYS = new Set(['alg', 'typ']);
const OAUTH_HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const SPT_HEADER_KEYS = new Set(['alg', 'kid']);
const WIT_CNF_KEYS = new Set(['jwk']);
const WIT_JWK_KEYS = new Set(['kty', 'crv', 'alg', 'kid', 'x']);
const SPT_INTENT_KEYS = new Set(['tool', 'params', 'target']);
const REQUIRED_HTTP_COMPONENTS = Object.freeze([
    '@method',
    '@request-target',
    'content-digest',
    'txn-token',
    'workload-identity-token',
]);
const REQUIRED_REQUEST_HEADER_NAMES = Object.freeze([
    'authorization',
    'content-digest',
    'content-type',
    'signature',
    'signature-input',
    'txn-token',
    'workload-identity-token',
]);
const RESERVED_OTHER_TOKEN_HEADERS = new Set([
    'authorization',
    'content-digest',
    'content-type',
    'signature',
    'signature-input',
    'txn-token',
    'workload-identity-token',
]);
const PROFILE_OTHER_TOKEN_HEADERS = Object.freeze([
    'oauth-transaction-access-token',
    'oauth-transaction-challenge',
]);
const SIGNATURE_PARAMETER_KEYS = new Set([
    'created', 'expires', 'nonce', 'tag', 'wimse-aud',
]);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    const actual = Object.keys(value);
    return actual.length === expected.size && actual.every((key) => expected.has(key));
}
function onlyKeys(value, expected) {
    return Object.keys(value).every((key) => expected.has(key));
}
function nonEmptyString(value) {
    return typeof value === 'string'
        && value.length > 0
        && !/[\u0000-\u001f\u007f\ufffd]/.test(value);
}
function safeInteger(value) {
    return Number.isSafeInteger(value);
}
function nonNegativeInteger(value) {
    return safeInteger(value) && Number(value) >= 0;
}
function positiveInteger(value) {
    return safeInteger(value) && Number(value) > 0;
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_wimse_oauth_spt_value: true });
    }
}
function tryDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return null;
    }
}
function hasUnpairedUtf16Surrogate(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return true;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            return true;
        }
    }
    return false;
}
function boundedUtf8String(value, maxOctets) {
    if (typeof value !== 'string'
        // Every UTF-16 code unit contributes at least one UTF-8 octet. This
        // constant-time check prevents allocating or scanning a giant string.
        || value.length > maxOctets
        || hasUnpairedUtf16Surrogate(value))
        return false;
    return Buffer.byteLength(value, 'utf8') <= maxOctets;
}
function withinCanonicalBudget(value, budget, depth = 0) {
    budget.nodes += 1;
    if (budget.nodes > MAX_ARTIFACT_NODES || depth > 64)
        return false;
    if (value === null || typeof value === 'boolean')
        return true;
    if (typeof value === 'number')
        return Number.isSafeInteger(value);
    if (typeof value === 'string') {
        const remaining = MAX_ARTIFACT_STRING_OCTETS - budget.stringOctets;
        if (!boundedUtf8String(value, remaining))
            return false;
        budget.stringOctets += Buffer.byteLength(value, 'utf8');
        return true;
    }
    if (typeof value !== 'object'
        || (!isRecord(value) && !Array.isArray(value)))
        return false;
    const object = value;
    if (budget.ancestors.has(object))
        return false;
    budget.ancestors.add(object);
    try {
        if (Array.isArray(value)) {
            if (value.length > MAX_ARTIFACT_NODES - budget.nodes)
                return false;
            for (let index = 0; index < value.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !('value' in descriptor)
                    || !withinCanonicalBudget(descriptor.value, budget, depth + 1))
                    return false;
            }
            return true;
        }
        let members = 0;
        for (const key in value) {
            members += 1;
            if (members > MAX_ARTIFACT_NODES - budget.nodes || !Object.hasOwn(value, key))
                return false;
            const remaining = MAX_ARTIFACT_STRING_OCTETS - budget.stringOctets;
            if (!boundedUtf8String(key, remaining))
                return false;
            budget.stringOctets += Buffer.byteLength(key, 'utf8');
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)
                || !withinCanonicalBudget(descriptor.value, budget, depth + 1))
                return false;
        }
        return true;
    }
    finally {
        budget.ancestors.delete(object);
    }
}
function inputWithinCanonicalBudget(value) {
    return withinCanonicalBudget(value, {
        nodes: 0,
        stringOctets: 0,
        ancestors: new Set(),
    });
}
function boundedDigest(value) {
    return inputWithinCanonicalBudget(value) ? tryDigest(value) : null;
}
function enumerableDataRecordWithinKeys(value, allowed, exact) {
    if (!isRecord(value))
        return false;
    let count = 0;
    for (const key in value) {
        count += 1;
        if (count > allowed.size || !allowed.has(key) || !Object.hasOwn(value, key))
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor))
            return false;
    }
    return exact ? count === allowed.size : true;
}
function ownDataValue(value, key) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && descriptor.enumerable === true && 'value' in descriptor
        ? descriptor.value
        : undefined;
}
function artifactWithinResourceLimits(value) {
    if (!enumerableDataRecordWithinKeys(value, ARTIFACT_KEYS, false)
        || !Object.hasOwn(value, 'wit')
        || !Object.hasOwn(value, 'wpt')
        || !Object.hasOwn(value, 'txn_token')
        || !Object.hasOwn(value, 'request'))
        return false;
    for (const key of ['wit', 'wpt', 'txn_token', 'spt_txn']) {
        if (Object.hasOwn(value, key)
            && !boundedUtf8String(ownDataValue(value, key), 65_536))
            return false;
    }
    const request = ownDataValue(value, 'request');
    if (!enumerableDataRecordWithinKeys(request, REQUEST_KEYS, true))
        return false;
    const method = ownDataValue(request, 'method');
    const targetUri = ownDataValue(request, 'target_uri');
    const body = ownDataValue(request, 'body');
    const headerValue = ownDataValue(request, 'headers');
    if (!boundedUtf8String(method, MAX_REQUEST_METHOD_OCTETS)
        || !boundedUtf8String(targetUri, MAX_REQUEST_TARGET_OCTETS)
        || !boundedUtf8String(body, MAX_REQUEST_BODY_OCTETS)
        || !isRecord(headerValue))
        return false;
    let headerCount = 0;
    let headerSectionOctets = 0;
    for (const name in headerValue) {
        headerCount += 1;
        if (headerCount > MAX_REQUEST_HEADER_COUNT
            || !Object.hasOwn(headerValue, name)
            || !boundedUtf8String(name, MAX_REQUEST_HEADER_NAME_OCTETS))
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(headerValue, name);
        if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)
            || !boundedUtf8String(descriptor.value, MAX_REQUEST_HEADER_VALUE_OCTETS))
            return false;
        headerSectionOctets += Buffer.byteLength(name, 'utf8')
            + Buffer.byteLength(descriptor.value, 'utf8');
        if (headerSectionOctets > MAX_REQUEST_HEADER_SECTION_OCTETS)
            return false;
    }
    return inputWithinCanonicalBudget(value);
}
function statusWithinResourceLimits(value) {
    if (!enumerableDataRecordWithinKeys(value, STATUS_KEYS, false))
        return false;
    for (const key of ['checked_at', 'expires_at']) {
        if (Object.hasOwn(value, key)
            && !boundedUtf8String(ownDataValue(value, key), 64))
            return false;
    }
    return inputWithinCanonicalBudget(value);
}
function sameDigest(left, right) {
    try {
        return digestAeb(left) === digestAeb(right);
    }
    catch {
        return false;
    }
}
function safeEqualString(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string')
        return false;
    const leftBytes = Buffer.from(left, 'utf8');
    const rightBytes = Buffer.from(right, 'utf8');
    return leftBytes.length === rightBytes.length
        && crypto.timingSafeEqual(leftBytes, rightBytes);
}
function sha256Base64url(value) {
    return crypto.createHash('sha256').update(value).digest('base64url');
}
// Keep the WIMSE adapter's small runtime closure independent of the broad AEB
// contract entry point. These bytes are the compatibility-frozen AEB digest:
// SHA-256 over the shared strict canonical JSON representation, with no prefix.
function canonicalizeAeb(value) {
    return canonicalizeStrictJson(value);
}
function digestAeb(value) {
    return `sha256:${crypto.createHash('sha256')
        .update(Buffer.from(canonicalizeAeb(value), 'utf8'))
        .digest('hex')}`;
}
const INVALID_EVIDENCE_DIGEST = digestAeb({ invalid_wimse_oauth_spt_value: true });
const INVALID_STATUS_DIGEST = digestAeb({ invalid_wimse_oauth_spt_status: true });
function canonicalSpki(value) {
    if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1)
        return null;
    try {
        const der = Buffer.from(value, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== value)
            return null;
        const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        const canonical = key.export({ type: 'spki', format: 'der' });
        return key.type === 'public'
            && key.asymmetricKeyType === 'ed25519'
            && Buffer.isBuffer(canonical)
            && canonical.equals(der) ? key : null;
    }
    catch {
        return null;
    }
}
function parseInstant(value) {
    if (typeof value !== 'string' || !RFC3339_RE.test(value))
        return NaN;
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed))
        return NaN;
    const canonicalSecond = new Date(parsed).toISOString().replace('.000Z', 'Z');
    const inputSecond = value.replace(/\.\d{1,9}Z$/, 'Z');
    return canonicalSecond === inputSecond ? parsed : NaN;
}
function absoluteHttpsUrl(value) {
    if (!nonEmptyString(value))
        return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'https:'
            && parsed.username === ''
            && parsed.password === ''
            && parsed.hostname.length > 0
            && parsed.hash === '';
    }
    catch {
        return false;
    }
}
/**
 * Closed audience comparison rule for the WPT-02 profile. Both the pinned
 * audience and received target URI must already be in WHATWG URL serialized
 * form. The pinned audience has no query. A request query is ignored exactly
 * as WPT-02 requires; no authority or path alias is accepted.
 */
function canonicalWimseAudience(value) {
    if (!nonEmptyString(value))
        return false;
    try {
        const parsed = new URL(value);
        return parsed.protocol === 'https:'
            && parsed.username === ''
            && parsed.password === ''
            && parsed.hostname.length > 0
            && parsed.search === ''
            && parsed.hash === ''
            && parsed.href === value;
    }
    catch {
        return false;
    }
}
function wptTargetAudience(value) {
    if (!nonEmptyString(value))
        return null;
    try {
        const parsed = new URL(value);
        if (parsed.protocol !== 'https:'
            || parsed.username !== ''
            || parsed.password !== ''
            || parsed.hostname.length === 0
            || parsed.hash !== ''
            || parsed.href !== value)
            return null;
        return `${parsed.origin}${parsed.pathname}`;
    }
    catch {
        return null;
    }
}
/**
 * Stable single-spend identity for one receiving logical workload's use of a
 * native Txn-Token transaction. Transaction Tokens -11 carries one `txn`
 * through a call chain and scopes its optional single-use check to the same
 * receiving workload. Including that constructor-pinned receiver keeps a
 * shared store from treating legitimate use at another workload as replay.
 * The draft revision and optional `iss` are verification metadata, not
 * replay-key material.
 */
export function deriveOAuthTransactionTokenReplayUnit(trustDomain, receivingWorkload, transactionId) {
    if (!nonEmptyString(trustDomain)
        || !TRUST_DOMAIN_RE.test(trustDomain)
        || trustDomain !== trustDomain.toLowerCase()
        || !canonicalWorkloadSubject(receivingWorkload, trustDomain)
        || !nonEmptyString(transactionId)) {
        throw new TypeError('invalid OAuth Transaction Token replay identity');
    }
    return digestAeb({
        native_namespace: OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
        trust_domain: trustDomain,
        receiving_workload: receivingWorkload,
        txn: transactionId,
    });
}
/**
 * Conservative relying-party profile for the generic WIMSE Workload
 * Identifier URI. The scheme remains deployment-selected, including `spiffe`,
 * while the exact spelling accepted by this adapter has one comparison form.
 */
function canonicalWorkloadSubject(value, trustDomain) {
    if (!nonEmptyString(value)
        || Buffer.byteLength(value, 'utf8') > MAX_WORKLOAD_SUBJECT_OCTETS)
        return false;
    const match = WORKLOAD_SUBJECT_RE.exec(value);
    if (!match || match[2] !== trustDomain)
        return false;
    const segments = match[3].slice(1).split('/');
    return segments.length > 0
        && segments.every((segment) => segment !== '.'
            && segment !== '..'
            && WORKLOAD_PATH_SEGMENT_RE.test(segment));
}
function normalizedOtherTokenHeaders(value) {
    if (!Array.isArray(value) || value.length > 32)
        return null;
    const headers = [];
    for (const candidate of value) {
        if (typeof candidate !== 'string'
            || candidate !== candidate.toLowerCase()
            || !HEADER_NAME_RE.test(candidate)
            || RESERVED_OTHER_TOKEN_HEADERS.has(candidate)
            || headers.includes(candidate))
            return null;
        headers.push(candidate);
    }
    return headers.sort();
}
function parseConfig(value) {
    if (!isRecord(value)
        || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION
        || value.evidence_role !== 'delegated-workload'
        || !isRecord(value.subject)
        || !exactKeys(value.subject, SUBJECT_KEYS)
        || !nonEmptyString(value.subject.id)
        || !IDENTIFIER_RE.test(value.subject.id)
        || value.subject.kind !== 'workload'
        || !nonEmptyString(value.subject.native_id)
        || !nonEmptyString(value.trust_domain)
        || !TRUST_DOMAIN_RE.test(value.trust_domain)
        || value.trust_domain !== value.trust_domain.toLowerCase()
        || !canonicalWorkloadSubject(value.receiving_workload, value.trust_domain)
        || !canonicalWorkloadSubject(value.oauth_requesting_workload, value.trust_domain)
        || !canonicalWimseAudience(value.wimse_audience)
        || !nonEmptyString(value.oauth_audience)
        || value.oauth_audience !== value.trust_domain
        || !nonEmptyString(value.oauth_subject)
        || !nonEmptyString(value.oauth_scope)
        || !absoluteHttpsUrl(value.spt_audience)
        || !nonEmptyString(value.spt_subject)
        || !nonEmptyString(value.spt_holder_key)
        || typeof value.action_type !== 'string'
        || !ACTION_TYPE_RE.test(value.action_type)
        || !nonNegativeInteger(value.clock_skew_seconds)
        || Number(value.clock_skew_seconds) > 300
        || !isRecord(value.max_age_seconds)
        || !exactKeys(value.max_age_seconds, MAX_AGE_KEYS)
        || !Object.values(value.max_age_seconds).every(positiveInteger)
        || Object.values(value.max_age_seconds).some((age) => Number(age) > 86_400)) {
        return null;
    }
    const otherTokenHeaders = normalizedOtherTokenHeaders(value.other_token_headers);
    if (otherTokenHeaders === null
        || !Array.isArray(value.other_token_headers)
        || value.other_token_headers.some((header, index) => header !== otherTokenHeaders[index])
        || otherTokenHeaders.length !== PROFILE_OTHER_TOKEN_HEADERS.length
        || otherTokenHeaders.some((header, index) => header !== PROFILE_OTHER_TOKEN_HEADERS[index])) {
        return null;
    }
    if (!canonicalWorkloadSubject(value.subject.native_id, value.trust_domain))
        return null;
    const config = structuredClone(value);
    config.other_token_headers = otherTokenHeaders;
    return config;
}
function parseTrustRoots(value, config) {
    if (!Array.isArray(value) || value.length !== 4)
        return null;
    const roots = [];
    const issuers = new Map();
    let holder = null;
    for (const candidate of value) {
        if (!isRecord(candidate)
            || candidate['@version'] !== WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION
            || candidate.algorithm !== 'EdDSA'
            || !nonEmptyString(candidate.key_id))
            return null;
        const key = canonicalSpki(candidate.public_key);
        if (!key)
            return null;
        if (candidate.use === 'workload-holder') {
            if (!exactKeys(candidate, HOLDER_ROOT_KEYS)
                || holder !== null
                || candidate.subject !== config.subject.native_id)
                return null;
            const exported = key.export({ format: 'jwk' });
            if (exported.kty !== 'OKP'
                || exported.crv !== 'Ed25519'
                || typeof exported.x !== 'string')
                return null;
            const root = structuredClone(candidate);
            holder = { ...root, key, publicJwkX: exported.x };
            roots.push(root);
            continue;
        }
        if (!['wit-issuer', 'oauth-transaction-token-issuer', 'spt-transaction-token-issuer']
            .includes(String(candidate.use))
            || !exactKeys(candidate, ISSUER_ROOT_KEYS)
            || !nonEmptyString(candidate.issuer)
            || issuers.has(String(candidate.use)))
            return null;
        const root = structuredClone(candidate);
        issuers.set(root.use, { ...root, key });
        roots.push(root);
    }
    const witIssuer = issuers.get('wit-issuer');
    const oauthIssuer = issuers.get('oauth-transaction-token-issuer');
    const sptIssuer = issuers.get('spt-transaction-token-issuer');
    if (!witIssuer || !oauthIssuer || !sptIssuer || !holder)
        return null;
    return { trustRoots: roots, witIssuer, oauthIssuer, sptIssuer, holder };
}
function parseConstructorPins(value) {
    if (!inputWithinCanonicalBudget(value)
        || !isRecord(value)
        || !exactKeys(value, new Set(['config', 'trust_roots']))) {
        throw new TypeError('invalid WIMSE/OAuth/SPT constructor pins');
    }
    const config = parseConfig(value.config);
    if (!config)
        throw new TypeError('invalid WIMSE/OAuth/SPT constructor config');
    const roots = parseTrustRoots(value.trust_roots, config);
    if (!roots)
        throw new TypeError('invalid WIMSE/OAuth/SPT constructor trust roots');
    return {
        config,
        ...roots,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb(roots.trustRoots),
    };
}
function decodeB64url(segment) {
    if (!B64URL_RE.test(segment) || segment.length % 4 === 1)
        return null;
    try {
        const decoded = Buffer.from(segment, 'base64url');
        return decoded.length > 0 && decoded.toString('base64url') === segment ? decoded : null;
    }
    catch {
        return null;
    }
}
function decodeUtf8(value) {
    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(value);
    }
    catch {
        return null;
    }
}
function parseCompactJws(token) {
    if (typeof token !== 'string' || token.length > 65_536)
        return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => part.length === 0))
        return null;
    const headerBytes = decodeB64url(parts[0]);
    const claimsBytes = decodeB64url(parts[1]);
    const signature = decodeB64url(parts[2]);
    if (!headerBytes || !claimsBytes || !signature || signature.length !== 64)
        return null;
    const headerText = decodeUtf8(headerBytes);
    const claimsText = decodeUtf8(claimsBytes);
    if (headerText === null || claimsText === null
        || !strictJsonGate(headerText).ok
        || !strictJsonGate(claimsText).ok)
        return null;
    let header;
    let claims;
    try {
        header = JSON.parse(headerText);
        claims = JSON.parse(claimsText);
    }
    catch {
        return null;
    }
    if (!isRecord(header) || !isRecord(claims))
        return null;
    return {
        token,
        header,
        claims,
        signingInput: `${parts[0]}.${parts[1]}`,
        signature,
    };
}
function verifyCompactJws(token, root, allowedHeaderKeys, expectedTyp, requireKid = true) {
    const parsed = parseCompactJws(token);
    if (!parsed
        || !exactKeys(parsed.header, allowedHeaderKeys)
        || parsed.header.alg !== 'EdDSA'
        || (expectedTyp !== undefined && parsed.header.typ !== expectedTyp)
        || (requireKid && parsed.header.kid !== root.key_id)
        || !crypto.verify(null, Buffer.from(parsed.signingInput, 'ascii'), root.key, parsed.signature))
        return null;
    return parsed;
}
function timeFailure(claims, nowSeconds, maxAgeSeconds, skewSeconds, label) {
    const { iat, nbf, exp } = claims;
    if (!safeInteger(iat) || !safeInteger(nbf) || !safeInteger(exp)) {
        return `${label}_time_claims_missing_or_invalid`;
    }
    const issuedAt = Number(iat);
    const notBefore = Number(nbf);
    const expires = Number(exp);
    if (expires <= issuedAt || expires <= notBefore)
        return `${label}_invalid_time_window`;
    if (issuedAt > nowSeconds + skewSeconds)
        return `${label}_issued_in_future`;
    if (notBefore > nowSeconds + skewSeconds)
        return `${label}_not_yet_valid`;
    if (expires <= nowSeconds - skewSeconds)
        return `${label}_expired`;
    if (nowSeconds - issuedAt > maxAgeSeconds
        || expires - issuedAt > maxAgeSeconds)
        return `${label}_max_age_exceeded`;
    return null;
}
function wptTimeFailure(claims, nowSeconds, maxAgeSeconds, skewSeconds) {
    if (!safeInteger(claims.exp))
        return 'wpt_exp_missing_or_invalid';
    const expires = Number(claims.exp);
    if (expires <= nowSeconds - skewSeconds)
        return 'wpt_expired';
    if (expires > nowSeconds + maxAgeSeconds + skewSeconds)
        return 'wpt_max_age_exceeded';
    if (Object.hasOwn(claims, 'iat')) {
        if (!safeInteger(claims.iat))
            return 'wpt_iat_invalid';
        const issuedAt = Number(claims.iat);
        if (issuedAt > nowSeconds + skewSeconds)
            return 'wpt_issued_in_future';
        if (expires <= issuedAt || expires - issuedAt > maxAgeSeconds) {
            return 'wpt_invalid_time_window';
        }
    }
    if (Object.hasOwn(claims, 'nbf')) {
        if (!safeInteger(claims.nbf))
            return 'wpt_nbf_invalid';
        const notBefore = Number(claims.nbf);
        if (notBefore > nowSeconds + skewSeconds)
            return 'wpt_not_yet_valid';
        if (expires <= notBefore)
            return 'wpt_invalid_time_window';
    }
    return null;
}
function normalizedHeaderMap(value) {
    if (!isRecord(value))
        return null;
    const headers = new Map();
    let sectionOctets = 0;
    let headerCount = 0;
    for (const rawName in value) {
        headerCount += 1;
        if (headerCount > MAX_REQUEST_HEADER_COUNT || !Object.hasOwn(value, rawName))
            return null;
        const descriptor = Object.getOwnPropertyDescriptor(value, rawName);
        if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor))
            return null;
        const rawValue = descriptor.value;
        if (!HEADER_NAME_RE.test(rawName)
            || typeof rawValue !== 'string'
            || /[\r\n\u0000]/.test(rawValue)
            || hasUnpairedUtf16Surrogate(rawValue)
            || Buffer.byteLength(rawName, 'utf8') > MAX_REQUEST_HEADER_NAME_OCTETS
            || Buffer.byteLength(rawValue, 'utf8') > MAX_REQUEST_HEADER_VALUE_OCTETS)
            return null;
        const name = rawName.toLowerCase();
        if (headers.has(name))
            return null;
        const normalizedValue = rawValue.replace(/^[\t ]+|[\t ]+$/g, '');
        sectionOctets += Buffer.byteLength(name, 'utf8')
            + Buffer.byteLength(normalizedValue, 'utf8');
        if (sectionOctets > MAX_REQUEST_HEADER_SECTION_OCTETS)
            return null;
        headers.set(name, normalizedValue);
    }
    return headers;
}
function asciiTokenHash(value) {
    if (typeof value !== 'string'
        || value.length === 0
        || !/^[\x09\x20-\x7e]+$/.test(value))
        return null;
    return sha256Base64url(Buffer.from(value, 'ascii'));
}
function verifyWpt02TokenBindings(claims, headers, understoodOtherTokenHeaders) {
    const failed = (reason) => ({
        verification: 'FAILED',
        transaction_token: headers.has('txn-token') ? 'PRESENT' : 'ABSENT',
        other_token_headers: [...understoodOtherTokenHeaders].sort(),
        reason,
    });
    const txnToken = headers.get('txn-token');
    if (txnToken === undefined) {
        if (Object.hasOwn(claims, 'tth'))
            return failed('unexpected_tth_without_txn_token');
    }
    else {
        const expected = asciiTokenHash(txnToken);
        if (expected === null || !safeEqualString(claims.tth, expected)) {
            return failed('tth_missing_or_mismatch');
        }
    }
    const expectedHeaders = [...understoodOtherTokenHeaders].sort();
    if (expectedHeaders.length === 0) {
        if (Object.hasOwn(claims, 'oth'))
            return failed('unexpected_oth_without_understood_tokens');
    }
    else {
        if (!isRecord(claims.oth)
            || !exactKeys(claims.oth, new Set(expectedHeaders))) {
            return failed('oth_header_set_mismatch');
        }
        for (const header of expectedHeaders) {
            const expected = asciiTokenHash(headers.get(header));
            if (expected === null || !safeEqualString(claims.oth[header], expected)) {
                return failed(`oth_hash_mismatch:${header}`);
            }
        }
    }
    return {
        verification: 'VERIFIED',
        transaction_token: txnToken === undefined ? 'ABSENT' : 'PRESENT',
        other_token_headers: expectedHeaders,
        reason: null,
    };
}
/**
 * Reperform only the `tth` and `oth` byte-binding rules from WPT-02.
 * This function does not verify a WPT signature, authenticate a workload,
 * authorize a request, reserve an operation, or establish an external effect.
 */
export function verifyWimseWpt02TokenBindingClaims(wptClaims, requestHeaders, understoodOtherTokenHeaders) {
    const headers = normalizedHeaderMap(requestHeaders);
    const understood = normalizedOtherTokenHeaders(understoodOtherTokenHeaders);
    if (!inputWithinCanonicalBudget(wptClaims)
        || !isRecord(wptClaims)
        || !headers
        || !understood) {
        return {
            verification: 'FAILED',
            transaction_token: 'ABSENT',
            other_token_headers: [],
            reason: 'binding_input_malformed',
        };
    }
    return verifyWpt02TokenBindings(wptClaims, headers, understood);
}
function normalizeRequest(value) {
    if (!isRecord(value)
        || !exactKeys(value, REQUEST_KEYS)
        || typeof value.method !== 'string'
        || !METHOD_RE.test(value.method)
        || Buffer.byteLength(value.method, 'utf8') > MAX_REQUEST_METHOD_OCTETS
        || typeof value.target_uri !== 'string'
        || hasUnpairedUtf16Surrogate(value.target_uri)
        || Buffer.byteLength(value.target_uri, 'utf8') > MAX_REQUEST_TARGET_OCTETS
        || !isRecord(value.headers)
        || typeof value.body !== 'string'
        || value.body.includes('\ufffd')
        || hasUnpairedUtf16Surrogate(value.body)
        || Buffer.byteLength(value.body, 'utf8') > MAX_REQUEST_BODY_OCTETS)
        return null;
    const targetAudience = wptTargetAudience(value.target_uri);
    if (targetAudience === null)
        return null;
    const target = new URL(value.target_uri);
    const headers = normalizedHeaderMap(value.headers);
    if (!headers)
        return null;
    return {
        method: value.method,
        targetUri: value.target_uri,
        targetAudience,
        requestTarget: `${target.pathname}${target.search}`,
        headers,
        body: value.body,
    };
}
function parseSfString(input, offset) {
    if (input[offset] !== '"')
        return null;
    let value = '';
    let index = offset + 1;
    while (index < input.length) {
        const character = input[index];
        if (character === '"')
            return { value, next: index + 1 };
        if (character === '\\') {
            const escaped = input[index + 1];
            if (escaped !== '"' && escaped !== '\\')
                return null;
            value += escaped;
            index += 2;
            continue;
        }
        const code = character.charCodeAt(0);
        if (code < 0x20 || code > 0x7e)
            return null;
        value += character;
        index += 1;
    }
    return null;
}
function parseSignatureInput(value) {
    if (typeof value !== 'string' || !value.startsWith('wimse=(') || value.includes(','))
        return null;
    const close = value.indexOf(')');
    if (close < 'wimse=('.length)
        return null;
    const componentText = value.slice('wimse=('.length, close);
    const components = [];
    let componentOffset = 0;
    while (componentOffset < componentText.length) {
        const parsed = parseSfString(componentText, componentOffset);
        if (!parsed || !/^@?[a-z0-9][a-z0-9!#$%&'*+\-.^_`|~]*$/.test(parsed.value))
            return null;
        components.push(parsed.value);
        componentOffset = parsed.next;
        if (componentOffset === componentText.length)
            break;
        if (componentText[componentOffset] !== ' ')
            return null;
        componentOffset += 1;
    }
    if (components.length === 0
        || components.length > MAX_SIGNATURE_COMPONENT_COUNT
        || new Set(components).size !== components.length)
        return null;
    const parameters = new Map();
    let offset = close + 1;
    while (offset < value.length) {
        if (value[offset] !== ';')
            return null;
        offset += 1;
        const keyMatch = /^[a-z][a-z0-9_.*-]*/.exec(value.slice(offset));
        if (!keyMatch)
            return null;
        const key = keyMatch[0];
        offset += key.length;
        if (value[offset] !== '=' || parameters.has(key))
            return null;
        offset += 1;
        if (value[offset] === '"') {
            const parsed = parseSfString(value, offset);
            if (!parsed)
                return null;
            parameters.set(key, parsed.value);
            offset = parsed.next;
        }
        else {
            const integer = /^-?(?:0|[1-9][0-9]*)/.exec(value.slice(offset));
            if (!integer)
                return null;
            const number = Number(integer[0]);
            if (!Number.isSafeInteger(number))
                return null;
            parameters.set(key, number);
            offset += integer[0].length;
        }
    }
    if (parameters.size !== SIGNATURE_PARAMETER_KEYS.size
        || [...parameters.keys()].some((key) => !SIGNATURE_PARAMETER_KEYS.has(key))
        || !safeInteger(parameters.get('created'))
        || !safeInteger(parameters.get('expires'))
        || !nonEmptyString(parameters.get('nonce'))
        || parameters.get('tag') !== 'wimse-workload-to-workload'
        || !nonEmptyString(parameters.get('wimse-aud')))
        return null;
    return {
        components,
        created: Number(parameters.get('created')),
        expires: Number(parameters.get('expires')),
        nonce: String(parameters.get('nonce')),
        tag: String(parameters.get('tag')),
        audience: String(parameters.get('wimse-aud')),
        signatureParams: value.slice('wimse='.length),
    };
}
function parseSignatureField(value) {
    if (typeof value !== 'string' || value.includes(','))
        return null;
    const match = /^wimse=:([A-Za-z0-9+/]+={0,2}):$/.exec(value);
    if (!match)
        return null;
    try {
        const bytes = Buffer.from(match[1], 'base64');
        return bytes.length === 64 && bytes.toString('base64') === match[1] ? bytes : null;
    }
    catch {
        return null;
    }
}
function signatureComponentValue(component, request) {
    if (component === '@method')
        return request.method;
    if (component === '@request-target')
        return request.requestTarget;
    if (component.startsWith('@'))
        return null;
    return request.headers.get(component) ?? null;
}
function verifyHttpSignature(request, holder, config, nowSeconds) {
    const parsedInput = parseSignatureInput(request.headers.get('signature-input'));
    const signature = parseSignatureField(request.headers.get('signature'));
    if (!parsedInput || !signature)
        return null;
    const allowedComponents = new Set([
        ...REQUIRED_HTTP_COMPONENTS,
        'content-type',
        'authorization',
        ...config.other_token_headers,
    ]);
    if (parsedInput.components.some((component) => !allowedComponents.has(component)))
        return null;
    for (const required of REQUIRED_HTTP_COMPONENTS) {
        if (!parsedInput.components.includes(required))
            return null;
    }
    for (const conditional of ['content-type', 'authorization']) {
        if (request.headers.has(conditional) && !parsedInput.components.includes(conditional))
            return null;
    }
    if (parsedInput.created >= parsedInput.expires
        || parsedInput.created > nowSeconds + config.clock_skew_seconds
        || parsedInput.expires <= nowSeconds - config.clock_skew_seconds
        || nowSeconds - parsedInput.created > config.max_age_seconds.http_signature
        || parsedInput.expires - parsedInput.created > config.max_age_seconds.http_signature
        || parsedInput.audience !== config.wimse_audience)
        return null;
    const lines = [];
    for (const component of parsedInput.components) {
        const componentValue = signatureComponentValue(component, request);
        if (componentValue === null)
            return null;
        lines.push(`${JSON.stringify(component)}: ${componentValue}`);
    }
    lines.push(`"@signature-params": ${parsedInput.signatureParams}`);
    return crypto.verify(null, Buffer.from(lines.join('\n'), 'utf8'), holder.key, signature) ? parsedInput : null;
}
function exactRequestHeaderSet(request, understoodOtherTokenHeaders) {
    const expected = new Set([
        ...REQUIRED_REQUEST_HEADER_NAMES,
        ...understoodOtherTokenHeaders,
    ]);
    return request.headers.size === expected.size
        && [...request.headers.keys()].every((name) => expected.has(name));
}
function validContentDigest(request) {
    const value = request.headers.get('content-digest');
    const match = typeof value === 'string' ? CONTENT_DIGEST_RE.exec(value) : null;
    if (!match)
        return false;
    const expected = crypto.createHash('sha256').update(Buffer.from(request.body, 'utf8')).digest();
    let actual;
    try {
        actual = Buffer.from(match[1], 'base64');
    }
    catch {
        return false;
    }
    return actual.length === expected.length
        && actual.toString('base64') === match[1]
        && crypto.timingSafeEqual(actual, expected);
}
function claimsIssuerSubject(claims, issuer, subject) {
    return claims.iss === issuer && claims.sub === subject;
}
function trustDomainMatches(subject, trustDomain) {
    return canonicalWorkloadSubject(subject, trustDomain);
}
function witConfirmationMatches(claims, holder) {
    if (!isRecord(claims.cnf)
        || !exactKeys(claims.cnf, WIT_CNF_KEYS)
        || !isRecord(claims.cnf.jwk)
        || !exactKeys(claims.cnf.jwk, WIT_JWK_KEYS))
        return false;
    const jwk = claims.cnf.jwk;
    return jwk.kty === 'OKP'
        && jwk.crv === 'Ed25519'
        && jwk.alg === 'EdDSA'
        && jwk.kid === holder.key_id
        && jwk.x === holder.publicJwkX;
}
function validateJcsValue(value, depth = 0) {
    if (depth > 64)
        return false;
    if (value === null || typeof value === 'boolean')
        return true;
    if (typeof value === 'string')
        return !value.includes('\ufffd');
    if (typeof value === 'number') {
        return Number.isSafeInteger(value) && !Object.is(value, -0);
    }
    if (Array.isArray(value))
        return value.every((item) => validateJcsValue(item, depth + 1));
    if (!isRecord(value))
        return false;
    return Object.values(value).every((item) => validateJcsValue(item, depth + 1));
}
function validSptIntent(value) {
    return isRecord(value)
        && exactKeys(value, SPT_INTENT_KEYS)
        && nonEmptyString(value.tool)
        && isRecord(value.params)
        && nonEmptyString(value.target)
        && validateJcsValue(value);
}
function sptIntentDigest(intent) {
    try {
        const canonical = canonicalizeAeb(intent);
        return crypto.createHash('sha256')
            .update(Buffer.from('spt-txn-intent-v1', 'utf8'))
            .update(Buffer.from([0]))
            .update(Buffer.from(canonical, 'utf8'))
            .digest('base64url');
    }
    catch {
        return null;
    }
}
function wptCredential(request) {
    const authorization = request.headers.get('authorization');
    if (authorization === undefined)
        return null;
    const match = /^WPT +([^\s,]+)$/i.exec(authorization);
    return match?.[1] ?? null;
}
function failure(reason, acceptance = 'REJECTED') {
    return { acceptance, reason: `wimse-oauth-spt:${reason}` };
}
function verifyArtifact(artifact, pins, now) {
    const nowMs = parseInstant(now);
    if (!Number.isFinite(nowMs))
        return failure('invalid_verification_time', 'INDETERMINATE');
    const nowSeconds = Math.floor(nowMs / 1000);
    if (!isRecord(artifact)
        || !onlyKeys(artifact, ARTIFACT_KEYS)
        || !Object.hasOwn(artifact, 'wit')
        || !Object.hasOwn(artifact, 'wpt')
        || !Object.hasOwn(artifact, 'txn_token')
        || !Object.hasOwn(artifact, 'request'))
        return failure('artifact_malformed');
    const hasSptToken = Object.hasOwn(artifact, 'spt_txn');
    const hasSptIntent = Object.hasOwn(artifact, 'spt_intent');
    if (hasSptToken !== hasSptIntent) {
        return failure('spt_binding_incomplete', 'INDETERMINATE');
    }
    const request = normalizeRequest(artifact.request);
    if (!request)
        return failure('request_malformed');
    if (request.targetAudience !== pins.config.wimse_audience) {
        return failure('request_target_audience_mismatch');
    }
    if (request.headers.get('workload-identity-token') !== artifact.wit
        || wptCredential(request) !== artifact.wpt
        || request.headers.get('txn-token') !== artifact.txn_token) {
        return failure('native_header_value_mismatch');
    }
    if (!validContentDigest(request))
        return failure('content_digest_mismatch');
    // -06 requires validating the WIT before the request signature.
    const wit = verifyCompactJws(artifact.wit, pins.witIssuer, WIT_HEADER_KEYS, 'wit+jwt');
    if (!wit)
        return failure('wit_signature_or_header_invalid');
    const witTime = timeFailure(wit.claims, nowSeconds, pins.config.max_age_seconds.wit, pins.config.clock_skew_seconds, 'wit');
    if (witTime)
        return failure(witTime);
    if (!claimsIssuerSubject(wit.claims, pins.witIssuer.issuer, pins.config.subject.native_id)
        || !trustDomainMatches(wit.claims.sub, pins.config.trust_domain)) {
        return failure('wit_issuer_subject_or_trust_domain_mismatch');
    }
    if (!witConfirmationMatches(wit.claims, pins.holder)) {
        return failure('wit_confirmation_key_mismatch');
    }
    const oauth = verifyCompactJws(artifact.txn_token, pins.oauthIssuer, OAUTH_HEADER_KEYS, 'txntoken+jwt');
    if (!oauth)
        return failure('oauth_txn_signature_or_header_invalid');
    const oauthTime = timeFailure(oauth.claims, nowSeconds, pins.config.max_age_seconds.oauth_txn, pins.config.clock_skew_seconds, 'oauth_txn');
    if (oauthTime)
        return failure(oauthTime);
    if (!claimsIssuerSubject(oauth.claims, pins.oauthIssuer.issuer, pins.config.oauth_subject)
        || oauth.claims.aud !== pins.config.oauth_audience
        || oauth.claims.req_wl !== pins.config.oauth_requesting_workload
        || oauth.claims.scope !== pins.config.oauth_scope
        || !nonEmptyString(oauth.claims.txn)
        || !isRecord(oauth.claims.tctx)
        || !validateJcsValue(oauth.claims.tctx)) {
        return failure('oauth_txn_claims_mismatch');
    }
    if (Object.hasOwn(oauth.claims, 'rctx')) {
        return failure('oauth_txn_rctx_unsupported');
    }
    const wpt = verifyCompactJws(artifact.wpt, pins.holder, WPT_HEADER_KEYS, 'wpt+jwt', false);
    if (!wpt)
        return failure('wpt_signature_or_header_invalid');
    const wptTime = wptTimeFailure(wpt.claims, nowSeconds, pins.config.max_age_seconds.wpt, pins.config.clock_skew_seconds);
    if (wptTime)
        return failure(wptTime);
    if (wpt.claims.aud !== pins.config.wimse_audience
        || !nonEmptyString(wpt.claims.jti)
        || asciiTokenHash(artifact.wit) === null
        || !safeEqualString(wpt.claims.wth, asciiTokenHash(artifact.wit))) {
        return failure('wpt_audience_or_wth_mismatch');
    }
    if (Object.hasOwn(wpt.claims, 'ath'))
        return failure('unexpected_wpt_ath');
    const tokenBindings = verifyWpt02TokenBindings(wpt.claims, request.headers, pins.config.other_token_headers);
    if (tokenBindings.verification !== 'VERIFIED') {
        return failure(`wpt_token_binding_failed:${tokenBindings.reason}`);
    }
    const httpSignature = verifyHttpSignature(request, pins.holder, pins.config, nowSeconds);
    if (!httpSignature)
        return failure('http_signature_invalid_or_incomplete');
    // This experimental profile maps an exact provider request. Refuse headers
    // outside the closed profile rather than silently dropping a field that may
    // alter provider semantics (for example method overrides or preconditions).
    if (!exactRequestHeaderSet(request, pins.config.other_token_headers)) {
        return failure('request_header_set_mismatch');
    }
    let sptIntent = null;
    if (hasSptToken) {
        if (!validSptIntent(artifact.spt_intent)) {
            return failure('spt_intent_missing_or_malformed', 'INDETERMINATE');
        }
        sptIntent = structuredClone(artifact.spt_intent);
        const spt = verifyCompactJws(artifact.spt_txn, pins.sptIssuer, SPT_HEADER_KEYS);
        if (!spt)
            return failure('spt_txn_signature_or_header_invalid');
        const sptTime = timeFailure(spt.claims, nowSeconds, pins.config.max_age_seconds.spt_txn, pins.config.clock_skew_seconds, 'spt_txn');
        if (sptTime)
            return failure(sptTime);
        const expectedIntentDigest = sptIntentDigest(sptIntent);
        if (!claimsIssuerSubject(spt.claims, pins.sptIssuer.issuer, pins.config.spt_subject)
            || spt.claims.aud !== pins.config.spt_audience
            || spt.claims.txn_token_type !== 'TXN'
            || spt.claims.holder_key !== pins.config.spt_holder_key
            || !nonEmptyString(spt.claims.human_anchor)
            || !nonEmptyString(spt.claims.jti)
            || expectedIntentDigest === null
            || !safeEqualString(spt.claims.spt_intent_digest, expectedIntentDigest)) {
            return failure('spt_txn_claims_or_intent_binding_mismatch');
        }
        if (Object.hasOwn(spt.claims, 'status')) {
            return failure('spt_status_snapshot_required', 'INDETERMINATE');
        }
    }
    const transaction = {
        scope: oauth.claims.scope,
        context: structuredClone(oauth.claims.tctx),
    };
    const action = {
        action_type: pins.config.action_type,
        http: {
            method: request.method,
            request_target: request.requestTarget,
            content_type: request.headers.get('content-type'),
            content_digest: request.headers.get('content-digest'),
            wimse_audience: httpSignature.audience,
        },
        transaction,
    };
    if (sptIntent !== null)
        action.spt_intent = sptIntent;
    const replayUnit = deriveOAuthTransactionTokenReplayUnit(oauth.claims.aud, pins.config.receiving_workload, oauth.claims.txn);
    return { action, replayUnit };
}
function statusDigest(status) {
    return safeDigest({
        checked_at: status?.checked_at,
        expires_at: status?.expires_at,
        revocation_checked: status?.revocation_checked,
        revoked: status?.revoked,
        consumed: status?.consumed,
        unavailable: status?.unavailable === true,
    });
}
function statusDisposition(status, now, maxAgeSeconds) {
    if (!isRecord(status)
        || !onlyKeys(status, STATUS_KEYS)
        || !Object.hasOwn(status, 'checked_at')
        || !Object.hasOwn(status, 'expires_at')
        || !Object.hasOwn(status, 'revocation_checked')
        || !Object.hasOwn(status, 'revoked')
        || !Object.hasOwn(status, 'consumed')
        || typeof status.revocation_checked !== 'boolean'
        || typeof status.revoked !== 'boolean'
        || typeof status.consumed !== 'boolean'
        || (status.unavailable !== undefined && typeof status.unavailable !== 'boolean')) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
    }
    const reasons = [];
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    if (status.unavailable === true)
        reasons.push('status_unavailable');
    if (status.revoked === true)
        reasons.push('evidence_revoked');
    if (status.consumed === true)
        reasons.push('evidence_consumed');
    if (status.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        reasons.push('status_time_indeterminate');
    }
    else {
        const ageSeconds = Math.floor((nowMs - checkedMs) / 1000);
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (checkedMs >= expiresMs || nowMs >= expiresMs)
            reasons.push('status_expired');
        if (ageSeconds < 0 || ageSeconds > maxAgeSeconds)
            reasons.push('status_too_old');
    }
    const unique = [...new Set(reasons)].sort();
    if (status.revoked === true || status.consumed === true) {
        return { acceptance: 'REJECTED', reasons: unique };
    }
    return unique.length === 0
        ? { acceptance: 'ACCEPTED', reasons: [] }
        : { acceptance: 'INDETERMINATE', reasons: unique };
}
function fallbackNative(input, pins) {
    const evidenceDigest = INVALID_EVIDENCE_DIGEST;
    const subject = {
        id: pins.config.subject.id,
        kind: 'workload',
    };
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: evidenceDigest,
        status_digest: INVALID_STATUS_DIGEST,
        evidence_role: pins.config.evidence_role,
        subject,
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
function verifyNative(input, pins) {
    const result = fallbackNative(input, pins);
    if (!statusWithinResourceLimits(input?.status)) {
        result.reasons = ['wimse-oauth-spt:status_resource_or_shape_invalid'];
        return result;
    }
    result.status_digest = statusDigest(input.status);
    if (!artifactWithinResourceLimits(input?.artifact)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['wimse-oauth-spt:artifact_resource_or_shape_invalid'];
        return result;
    }
    const evidenceDigest = tryDigest(input?.artifact);
    if (evidenceDigest === null) {
        result.reasons = ['wimse-oauth-spt:artifact_outside_canonical_domain'];
        return result;
    }
    result.evidence_digest = evidenceDigest;
    if (boundedDigest(input?.adapter_config) !== pins.configDigest
        || boundedDigest(input?.trust_roots) !== pins.rootsDigest) {
        result.reasons = ['wimse-oauth-spt:constructor_pin_mismatch'];
        return result;
    }
    const detail = verifyArtifact(input?.artifact, pins, input?.now);
    if ('reason' in detail) {
        result.acceptance = detail.acceptance;
        result.reasons = [detail.reason];
        return result;
    }
    result.native_verification = 'VERIFIED';
    result.replay_unit = detail.replayUnit;
    const status = statusDisposition(input.status, input.now, pins.config.max_age_seconds.status);
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    return result;
}
export function createWimseOAuthSptActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
        native_protocols: [...SOURCE_REVISIONS],
        projection: 'signed-http-oauth-context-v1',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [
                    { name: 'action_type', type: 'string' },
                    { name: 'http', type: 'object' },
                    { name: 'transaction', type: 'object' },
                ],
                optional_fields: [
                    { name: 'spt_intent', type: 'object' },
                ],
            }],
    };
}
function wimseMappingProfileDigest(profile) {
    return digestAeb({
        profile_id: WIMSE_OAUTH_SPT_MAPPING_PROFILE_ID,
        version: profile.version,
        definition: profile.definition ?? null,
        registry_entry_ref: profile.registry_entry_ref,
        mapper_id: profile.mapper_id,
        resolver: profile.resolver,
        semantic_equivalence: profile.semantic_equivalence,
    });
}
/** Build the only mapping profile accepted by adapter v3 for this action type. */
export function createWimseOAuthSptMappingProfile(actionType) {
    const profile = {
        version: WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
        definition: createWimseOAuthSptActionDefinition(actionType),
        registry_entry_ref: WIMSE_OAUTH_SPT_MAPPING_REGISTRY_REF,
        mapper_id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
        resolver: {
            id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
            version: '2',
            implementation_digest: digestAeb({
                implementation: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
                version: '2',
            }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [...WIMSE_OAUTH_SPT_OMITTED_NONMATERIAL_FIELDS],
        },
    };
    return { ...profile, profile_digest: wimseMappingProfileDigest(profile) };
}
function validMappingProfile(profile, actionType) {
    if (!inputWithinCanonicalBudget(profile)
        || !isRecord(profile)
        || !exactKeys(profile, MAPPING_PROFILE_KEYS))
        return null;
    const expected = createWimseOAuthSptMappingProfile(actionType);
    if (!sameDigest(profile, expected) || !isRecord(profile.definition))
        return null;
    const definitions = profile.definition.definitions;
    return Array.isArray(definitions)
        ? { definition: profile.definition, definitions }
        : null;
}
function exactExpectedActionShape(value, hasSptIntent) {
    if (!isRecord(value))
        return false;
    const expectedTop = new Set(hasSptIntent
        ? ['action_type', 'http', 'transaction', 'spt_intent']
        : ['action_type', 'http', 'transaction']);
    if (!exactKeys(value, expectedTop)
        || !isRecord(value.http)
        || !exactKeys(value.http, new Set([
            'method', 'request_target', 'content_type', 'content_digest', 'wimse_audience',
        ]))
        || !Object.values(value.http).every(nonEmptyString)
        || !isRecord(value.transaction)
        || !exactKeys(value.transaction, new Set(['scope', 'context']))
        || !nonEmptyString(value.transaction.scope)
        || !isRecord(value.transaction.context)
        || !validateJcsValue(value.transaction.context))
        return false;
    return !hasSptIntent || validSptIntent(value.spt_intent);
}
function mapAction(input, pins) {
    if (input.native.native_verification !== 'VERIFIED'
        || input.native.acceptance !== 'ACCEPTED') {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['native_acceptance_required'],
        };
    }
    const evidenceDigest = artifactWithinResourceLimits(input.artifact)
        ? tryDigest(input.artifact)
        : null;
    if (evidenceDigest === null || evidenceDigest !== input.native.evidence_digest) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['native_evidence_digest_mismatch'],
        };
    }
    if (!statusWithinResourceLimits(input.status)
        || statusDigest(input.status) !== input.native.status_digest) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['native_status_digest_mismatch'],
        };
    }
    const currentStatus = statusDisposition(input.status, input.now, pins.config.max_age_seconds.status);
    if (currentStatus.acceptance !== 'ACCEPTED') {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['native_status_not_accepted', ...currentStatus.reasons],
        };
    }
    if (boundedDigest(input.adapter_config) !== pins.configDigest
        || boundedDigest(input.trust_roots) !== pins.rootsDigest) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['mapping_constructor_pin_mismatch'],
        };
    }
    const mapping = validMappingProfile(input.profile, pins.config.action_type);
    if (!mapping) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['mapping_profile_invalid'],
        };
    }
    const detail = verifyArtifact(input.artifact, pins, input.now);
    if ('reason' in detail) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: [detail.reason],
        };
    }
    const hasSptIntent = Object.hasOwn(detail.action, 'spt_intent');
    if (!inputWithinCanonicalBudget(input.expected_action)
        || !exactExpectedActionShape(input.expected_action, hasSptIntent)
        || input.expected_action.action_type !== pins.config.action_type) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['missing_or_ambiguous_exact_action'],
        };
    }
    const actionDigest = safeDigest(detail.action);
    if (!sameDigest(detail.action, input.expected_action)) {
        return {
            mapping: 'MISMATCH',
            caid: null,
            action_digest: actionDigest,
            reasons: ['exact_action_projection_mismatch'],
        };
    }
    let computed;
    try {
        computed = computeCaid(detail.action, {
            suite: 'jcs-sha256',
            definitions: mapping.definitions,
        });
    }
    catch {
        computed = null;
    }
    if (!isRecord(computed)
        || typeof computed.caid !== 'string'
        || typeof computed.digest !== 'string'
        || !DIGEST_RE.test(computed.digest)) {
        const refusals = isRecord(computed) && Array.isArray(computed.refusals)
            ? computed.refusals.map(String).sort()
            : ['caid_mapping_failed'];
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: refusals.map((reason) => `caid:${reason}`),
        };
    }
    if (computed.digest !== actionDigest) {
        return {
            mapping: 'INDETERMINATE',
            caid: null,
            action_digest: null,
            reasons: ['caid_digest_disagreement'],
        };
    }
    return {
        mapping: 'MATCH',
        caid: computed.caid,
        action_digest: actionDigest,
        reasons: [],
    };
}
/**
 * Construct an immutable adapter whose trust and policy inputs are pinned
 * twice: first here, then by exact digest equality on every AEB invocation.
 */
export function createWimseOAuthSptAebAdapter(constructorPins) {
    const pins = parseConstructorPins(constructorPins);
    return Object.freeze({
        id: WIMSE_OAUTH_SPT_AEB_ADAPTER_ID,
        version: WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input, pins);
            }
            catch {
                const result = fallbackNative(input, pins);
                result.reasons = ['wimse-oauth-spt:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                return mapAction(input, pins);
            }
            catch {
                return {
                    mapping: 'INDETERMINATE',
                    caid: null,
                    action_digest: null,
                    reasons: ['wimse-oauth-spt:unexpected_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=aeb-wimse-oauth-adapter.js.map