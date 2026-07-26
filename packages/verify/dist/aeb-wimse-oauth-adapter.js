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
 *   draft-ietf-wimse-http-signature-03
 *   draft-ietf-wimse-workload-creds-01
 *   draft-ietf-wimse-wpt-01
 *   draft-ietf-oauth-transaction-tokens-08
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
import { canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';
export const WIMSE_OAUTH_SPT_AEB_ADAPTER_ID = 'native:wimse-http-signature-oauth-txn-spt-intent';
export const WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION = '1';
export const WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION = 'AEB-WIMSE-OAUTH-SPT-CONFIG-v1';
export const WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION = 'AEB-WIMSE-OAUTH-SPT-ED25519-ROOT-v1';
export const WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION = 'AEB-WIMSE-OAUTH-SPT-CAID-MAPPING-v1';
export const WIMSE_OAUTH_SPT_CAID_MAPPER_ID = 'mapper:wimse-oauth-spt-exact-request-v1';
export const WIMSE_HTTP_SIGNATURE_REVISION = 'draft-ietf-wimse-http-signature-03';
export const WIMSE_WORKLOAD_CREDS_REVISION = 'draft-ietf-wimse-workload-creds-01';
export const WIMSE_WPT_REVISION = 'draft-ietf-wimse-wpt-01';
export const OAUTH_TRANSACTION_TOKENS_REVISION = 'draft-ietf-oauth-transaction-tokens-08';
export const SPT_TRANSACTION_TOKENS_REVISION = 'draft-coetzee-oauth-spt-txn-tokens-03';
const SOURCE_REVISIONS = Object.freeze([
    WIMSE_HTTP_SIGNATURE_REVISION,
    WIMSE_WORKLOAD_CREDS_REVISION,
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
const CONFIG_KEYS = new Set([
    '@version',
    'evidence_role',
    'subject',
    'trust_domain',
    'wimse_audience',
    'oauth_audience',
    'oauth_subject',
    'oauth_scope',
    'spt_audience',
    'spt_subject',
    'spt_holder_key',
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
        || !absoluteHttpsUrl(value.wimse_audience)
        || !nonEmptyString(value.oauth_audience)
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
    let subjectUrl;
    try {
        subjectUrl = new URL(value.subject.native_id);
    }
    catch {
        return null;
    }
    if (subjectUrl.username !== ''
        || subjectUrl.password !== ''
        || subjectUrl.host !== value.trust_domain
        || subjectUrl.pathname === '/'
        || subjectUrl.search !== ''
        || subjectUrl.hash !== '')
        return null;
    return structuredClone(value);
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
    if (!isRecord(value) || !exactKeys(value, new Set(['config', 'trust_roots']))) {
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
function normalizeRequest(value) {
    if (!isRecord(value)
        || !exactKeys(value, REQUEST_KEYS)
        || typeof value.method !== 'string'
        || !METHOD_RE.test(value.method)
        || typeof value.target_uri !== 'string'
        || !absoluteHttpsUrl(value.target_uri)
        || !isRecord(value.headers)
        || typeof value.body !== 'string'
        || value.body.includes('\ufffd'))
        return null;
    const target = new URL(value.target_uri);
    const headers = new Map();
    for (const [rawName, rawValue] of Object.entries(value.headers)) {
        if (!HEADER_NAME_RE.test(rawName)
            || typeof rawValue !== 'string'
            || /[\r\n\u0000]/.test(rawValue))
            return null;
        const name = rawName.toLowerCase();
        if (headers.has(name))
            return null;
        headers.set(name, rawValue.replace(/^[\t ]+|[\t ]+$/g, ''));
    }
    return {
        method: value.method,
        targetUri: value.target_uri,
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
    if (components.length === 0 || new Set(components).size !== components.length)
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
    if (!nonEmptyString(subject))
        return false;
    try {
        const parsed = new URL(subject);
        return parsed.username === ''
            && parsed.password === ''
            && parsed.host === trustDomain
            && parsed.pathname !== '/'
            && parsed.search === ''
            && parsed.hash === '';
    }
    catch {
        return false;
    }
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
function bearerToken(request) {
    const authorization = request.headers.get('authorization');
    if (authorization === undefined)
        return null;
    const match = /^Bearer ([^\s,]+)$/.exec(authorization);
    return match?.[1] ?? '';
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
    if (request.headers.get('workload-identity-token') !== artifact.wit
        || request.headers.get('workload-proof-token') !== artifact.wpt
        || request.headers.get('txn-token') !== artifact.txn_token) {
        return failure('native_header_value_mismatch');
    }
    if (!validContentDigest(request))
        return failure('content_digest_mismatch');
    // -03 requires validating the WIT before the request signature.
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
        || oauth.claims.req_wl !== pins.config.subject.native_id
        || oauth.claims.scope !== pins.config.oauth_scope
        || !nonEmptyString(oauth.claims.txn)
        || !isRecord(oauth.claims.tctx)
        || !validateJcsValue(oauth.claims.tctx)) {
        return failure('oauth_txn_claims_mismatch');
    }
    const wpt = verifyCompactJws(artifact.wpt, pins.holder, WPT_HEADER_KEYS, 'wpt+jwt', false);
    if (!wpt)
        return failure('wpt_signature_or_header_invalid');
    const wptTime = timeFailure(wpt.claims, nowSeconds, pins.config.max_age_seconds.wpt, pins.config.clock_skew_seconds, 'wpt');
    if (wptTime)
        return failure(wptTime);
    if (wpt.claims.aud !== pins.config.wimse_audience
        || !nonEmptyString(wpt.claims.jti)
        || !safeEqualString(wpt.claims.wth, sha256Base64url(Buffer.from(String(artifact.wit), 'ascii')))
        || !safeEqualString(wpt.claims.tth, sha256Base64url(Buffer.from(String(artifact.txn_token), 'ascii')))) {
        return failure('wpt_audience_wth_or_tth_mismatch');
    }
    const bearer = bearerToken(request);
    if (bearer === '')
        return failure('authorization_header_malformed');
    if (bearer === null) {
        if (Object.hasOwn(wpt.claims, 'ath'))
            return failure('unexpected_wpt_ath');
    }
    else if (!safeEqualString(wpt.claims.ath, sha256Base64url(Buffer.from(bearer, 'ascii')))) {
        return failure('wpt_ath_mismatch');
    }
    if (Object.hasOwn(wpt.claims, 'oth'))
        return failure('unsupported_wpt_oth', 'INDETERMINATE');
    const httpSignature = verifyHttpSignature(request, pins.holder, pins.config, nowSeconds);
    if (!httpSignature)
        return failure('http_signature_invalid_or_incomplete');
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
            content_digest: request.headers.get('content-digest'),
            wimse_audience: httpSignature.audience,
        },
        transaction,
    };
    if (sptIntent !== null)
        action.spt_intent = sptIntent;
    const replayUnit = digestAeb({
        native_protocol: OAUTH_TRANSACTION_TOKENS_REVISION,
        trust_domain: oauth.claims.aud,
        txn: oauth.claims.txn,
    });
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
    const evidenceDigest = safeDigest(input?.artifact);
    const subject = {
        id: pins.config.subject.id,
        kind: 'workload',
    };
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: evidenceDigest,
        status_digest: statusDigest(input?.status),
        evidence_role: pins.config.evidence_role,
        subject,
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
function verifyNative(input, pins) {
    const result = fallbackNative(input, pins);
    if (safeDigest(input?.adapter_config) !== pins.configDigest
        || safeDigest(input?.trust_roots) !== pins.rootsDigest) {
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
function validMappingProfile(profile, actionType) {
    if (!isRecord(profile)
        || profile.version !== WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION
        || profile.mapper_id !== WIMSE_OAUTH_SPT_CAID_MAPPER_ID
        || !isRecord(profile.resolver)
        || profile.resolver.id !== WIMSE_OAUTH_SPT_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || typeof profile.resolver.implementation_digest !== 'string'
        || !DIGEST_RE.test(profile.resolver.implementation_digest)
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !isRecord(profile.definition))
        return null;
    const expected = createWimseOAuthSptActionDefinition(actionType);
    if (!sameDigest(profile.definition, expected))
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
            'method', 'request_target', 'content_digest', 'wimse_audience',
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
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== pins.rootsDigest) {
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
    if (!exactExpectedActionShape(input.expected_action, hasSptIntent)
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