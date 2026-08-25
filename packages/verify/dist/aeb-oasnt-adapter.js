// SPDX-License-Identifier: Apache-2.0
/**
 * Revision-pinned OASNT adapter for AEB-ADAPTER-v1.
 *
 * Native-token source lock: draft-thallapelly-oasnt-02, archived text SHA-256
 * 3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603.
 * The optional OASNT-local CAID derivation is separately source-locked to
 * draft-thallapelly-oasnt-caid-01, archived text SHA-256
 * 75dfecb65e56accc5b55aa66a570e6fae52d3fe417631482eb8172d50e771963.
 *
 * OASNT proves a native, single-use human authorization token. This adapter
 * verifies that token under relying-party-pinned enrolled keys, recomputes its
 * action/display/request commitments from the action the Gate is about to
 * execute, and projects that exact action into a pinned EMILIA CAID profile.
 * It never treats the OASNT token as an AEB verdict or a local authorization.
 *
 * New at -02 (draft sec 5.4): the OPTIONAL `asl` assurance claim. The
 * effective level is the LESSER of the claimed level and the ceiling the
 * enrollment supports (sec 5.4.1); an unrecognized value carries no assurance
 * statement and must never be inferred or floored (sec 5.4.2); assurance
 * floors themselves are relying-party policy, so the requirement lives in
 * this adapter's pinned config, not in the token. The -02 verifier-side
 * lifetime bound (step 6: refuse exp-iat above a locally configured maximum)
 * was already enforced here as `max_token_lifetime_seconds`.
 */
import crypto from 'node:crypto';
// The governed CAID implementation is JavaScript and has no declaration file.
// @ts-expect-error -- runtime shape is checked before use.
import { computeCaid } from '../vendor/caid.mjs';
import { digestAeb, } from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';
export const OASNT_DRAFT_REVISION = 'draft-thallapelly-oasnt-02';
export const OASNT_DRAFT_TXT_SHA256 = 'sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603';
export const OASNT_CAID_DRAFT_REVISION = 'draft-thallapelly-oasnt-caid-01';
export const OASNT_CAID_DRAFT_TXT_SHA256 = 'sha256:75dfecb65e56accc5b55aa66a570e6fae52d3fe417631482eb8172d50e771963';
export const OASNT_AEB_ADAPTER_ID = 'native:oasnt';
export const OASNT_AEB_ADAPTER_VERSION = '2';
export const OASNT_AEB_CONFIG_VERSION = 'AEB-OASNT-CONFIG-v2';
/**
 * The "OASNT Assurance Levels" registry, initial contents (draft sec 10.2).
 * Compared by rank; larger is stronger. Values are case-sensitive and match
 * [a-z][a-z0-9-]*. An asl value outside this table is syntactically legal but
 * carries NO assurance statement (sec 5.4.2): never inferred, never floored.
 */
export const OASNT_ASSURANCE_LEVELS = Object.freeze({
    'software': 10,
    'platform-key': 20,
    'attested-display': 30,
});
const ASL_SYNTAX_RE = /^[a-z][a-z0-9-]*$/;
export const OASNT_TRUST_ROOT_VERSION = 'AEB-OASNT-ENROLLED-P256-ROOT-v1';
export const OASNT_CAID_MAPPING_VERSION = 'AEB-OASNT-CAID-MAPPING-v1';
export const OASNT_CAID_MAPPER_ID = 'mapper:oasnt-exact-action-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const HEX_32_RE = /^[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/;
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'action_type', 'require_request_binding',
    'clock_skew_seconds', 'max_token_lifetime_seconds', 'max_status_age_seconds',
    'required_assurance_level',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const ROOT_KEYS = new Set([
    '@version', 'use', 'native_subject', 'public_jwk', 'jwk_thumbprint', 'enrollment',
]);
const JWK_KEYS = new Set(['kty', 'crv', 'x', 'y']);
const ENROLLMENT_KEYS = new Set(['hardware_attested', 'evidence_digest']);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const TOKEN_HEADER_KEYS = new Set(['alg', 'typ']);
const TOKEN_CLAIM_KEYS = new Set(['sub', 'adg', 'dsp', 'rqf', 'int', 'jti', 'iat', 'exp', 'cnf', 'asl']);
const CNF_KEYS = new Set(['jkt']);
const ACTION_KEYS_WITH_REQUEST = new Set(['action_type', 'native_action', 'request']);
const ACTION_KEYS_NO_REQUEST = new Set(['action_type', 'native_action']);
const NATIVE_ACTION_KEYS = new Set(['type', 'parameters']);
const REQUEST_KEYS = new Set(['method', 'path', 'org_id', 'scope', 'body_sha256']);
const MAPPING_KEYS = new Set([
    '@version', 'native_protocol', 'projection', 'action_type', 'suite', 'definitions',
]);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, allowed, optional = new Set()) {
    const required = [...allowed].filter((key) => !optional.has(key));
    return Object.keys(value).every((key) => allowed.has(key))
        && required.every((key) => Object.hasOwn(value, key));
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function canonicalBase64url(value, length) {
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
function parseInstant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
        return NaN;
    return Date.parse(value);
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ invalid_native_value: true });
    }
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
    if (!isRecord(status) || !exactKeys(status, STATUS_KEYS, new Set(['unavailable']))) {
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
    if (typeof status.revoked !== 'boolean' || typeof status.consumed !== 'boolean'
        || typeof status.revocation_checked !== 'boolean'
        || (status.unavailable !== undefined && typeof status.unavailable !== 'boolean')) {
        reasons.push('status_malformed');
    }
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        reasons.push('status_time_indeterminate');
    }
    else {
        const age = Math.floor((nowMs - checkedMs) / 1000);
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (checkedMs >= expiresMs || nowMs >= expiresMs)
            reasons.push('status_expired');
        if (age < 0 || age > maxAgeSeconds)
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
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== OASNT_AEB_CONFIG_VERSION
        || typeof value.evidence_role !== 'string' || !IDENTIFIER_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || typeof value.subject.id !== 'string' || !IDENTIFIER_RE.test(value.subject.id)
        || value.subject.kind !== 'human'
        || !nonEmptyString(value.subject.native_id)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || typeof value.require_request_binding !== 'boolean'
        || !nonNegativeInteger(value.clock_skew_seconds)
        || !nonNegativeInteger(value.max_token_lifetime_seconds)
        || value.max_token_lifetime_seconds < 1
        || !nonNegativeInteger(value.max_status_age_seconds)
        || !(value.required_assurance_level === null
            || (typeof value.required_assurance_level === 'string'
                && Object.hasOwn(OASNT_ASSURANCE_LEVELS, value.required_assurance_level))))
        return null;
    return structuredClone(value);
}
function jwkThumbprint(jwk) {
    const canonical = JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y });
    return crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('base64url');
}
function parseRoots(value, config) {
    if (!Array.isArray(value) || value.length < 1)
        return null;
    const roots = [];
    const thumbprints = new Set();
    for (const candidate of value) {
        if (!isRecord(candidate) || !exactKeys(candidate, ROOT_KEYS)
            || candidate['@version'] !== OASNT_TRUST_ROOT_VERSION
            || candidate.use !== 'enrolled-oasnt-signing-key'
            || candidate.native_subject !== config.subject.native_id
            || !isRecord(candidate.public_jwk) || !exactKeys(candidate.public_jwk, JWK_KEYS)
            || candidate.public_jwk.kty !== 'EC' || candidate.public_jwk.crv !== 'P-256'
            || !canonicalBase64url(candidate.public_jwk.x, 32)
            || !canonicalBase64url(candidate.public_jwk.y, 32)
            || !canonicalBase64url(candidate.jwk_thumbprint, 32)
            || !isRecord(candidate.enrollment) || !exactKeys(candidate.enrollment, ENROLLMENT_KEYS)
            || candidate.enrollment.hardware_attested !== true
            || typeof candidate.enrollment.evidence_digest !== 'string'
            || !DIGEST_RE.test(candidate.enrollment.evidence_digest))
            return null;
        const root = structuredClone(candidate);
        if (jwkThumbprint(root.public_jwk) !== root.jwk_thumbprint
            || thumbprints.has(root.jwk_thumbprint))
            return null;
        let key;
        try {
            key = crypto.createPublicKey({ key: root.public_jwk, format: 'jwk' });
        }
        catch {
            return null;
        }
        if (key.asymmetricKeyType !== 'ec'
            || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
            return null;
        thumbprints.add(root.jwk_thumbprint);
        roots.push({ ...root, key });
    }
    return roots;
}
function parsePins(value) {
    const config = parseConfig(value?.config);
    if (!config)
        throw new TypeError('invalid OASNT constructor config');
    const roots = parseRoots(value?.trust_roots, config);
    if (!roots)
        throw new TypeError('invalid OASNT constructor trust roots');
    return {
        config,
        roots,
        configDigest: safeDigest(config),
        rootsDigest: safeDigest(value.trust_roots),
    };
}
function utf8Compare(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function validParameters(value) {
    if (!isRecord(value))
        return false;
    return Object.entries(value).every(([key, item]) => key.length > 0
        && !/[\u0000-\u001f\u007f]/.test(key)
        && typeof item === 'string' && !item.includes('\u0000'));
}
function actionEscape(value) {
    return value.replace(/[\\|=&]/g, (match) => `\\${match}`);
}
function displayEscape(value) {
    return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}
function sha256Base64url(value) {
    return crypto.createHash('sha256').update(value).digest('base64url');
}
export function computeOasntActionDigest(type, parameters) {
    if (!nonEmptyString(type) || !validParameters(parameters)) {
        throw new TypeError('invalid OASNT native action');
    }
    const pairs = Object.keys(parameters).sort(utf8Compare)
        .map((key) => `${actionEscape(key)}=${actionEscape(parameters[key])}`);
    return sha256Base64url(`${actionEscape(type)}|${pairs.join('&')}`);
}
/**
 * OASNT-CAID-01 Section 3.2 identifier. This identifier is confined to the
 * OASNT namespace and is never a direct join key for an EMILIA CAID.
 */
export function computeOasntCaid(type, parameters) {
    return `oasnt:caid:1:${computeOasntActionDigest(type, parameters)}`;
}
export function computeOasntDisplayDigest(type, parameters) {
    if (!nonEmptyString(type) || !validParameters(parameters)) {
        throw new TypeError('invalid OASNT native action');
    }
    const lines = Object.keys(parameters).sort(utf8Compare)
        .map((key) => `${displayEscape(key)}: ${displayEscape(parameters[key])}`);
    return sha256Base64url([displayEscape(type), ...lines].join('\n'));
}
export function computeOasntRequestFingerprint(request) {
    if (!isRecord(request) || !exactKeys(request, REQUEST_KEYS)
        || !['method', 'path', 'org_id', 'scope'].every((key) => (typeof request[key] === 'string' && !String(request[key]).includes('\u0000')))
        || typeof request.body_sha256 !== 'string' || !HEX_32_RE.test(request.body_sha256)) {
        throw new TypeError('invalid OASNT request binding');
    }
    return sha256Base64url(Buffer.concat([
        Buffer.from(request.method, 'utf8'), Buffer.from([0]),
        Buffer.from(request.path, 'utf8'), Buffer.from([0]),
        Buffer.from(request.org_id, 'utf8'), Buffer.from([0]),
        Buffer.from(request.scope, 'utf8'), Buffer.from([0]),
        Buffer.from(request.body_sha256, 'hex'),
    ]));
}
function decodeBase64urlUtf8(segment) {
    if (!canonicalBase64url(segment))
        return null;
    try {
        const bytes = Buffer.from(segment, 'base64url');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        return Buffer.from(text, 'utf8').equals(bytes) ? text : null;
    }
    catch {
        return null;
    }
}
function parseCompactToken(value) {
    if (typeof value !== 'string')
        return null;
    const parts = value.split('.');
    if (parts.length !== 3)
        return null;
    const headerText = decodeBase64urlUtf8(parts[0]);
    const claimsText = decodeBase64urlUtf8(parts[1]);
    if (headerText === null || claimsText === null
        || !strictJsonGate(headerText).ok || !strictJsonGate(claimsText).ok
        || !canonicalBase64url(parts[2], 64))
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
    if (!isRecord(header) || !exactKeys(header, TOKEN_HEADER_KEYS)
        || header.alg !== 'ES256' || header.typ !== 'oasnt+jwt'
        || !isRecord(claims)
        || !exactKeys(claims, TOKEN_CLAIM_KEYS, new Set(['rqf', 'asl'])))
        return null;
    return {
        token: value,
        claims,
        signingInput: `${parts[0]}.${parts[1]}`,
        signature: Buffer.from(parts[2], 'base64url'),
    };
}
function exactExpectedAction(value, config) {
    const keys = config.require_request_binding ? ACTION_KEYS_WITH_REQUEST : ACTION_KEYS_NO_REQUEST;
    if (!isRecord(value) || !exactKeys(value, keys)
        || value.action_type !== config.action_type
        || !isRecord(value.native_action) || !exactKeys(value.native_action, NATIVE_ACTION_KEYS)
        || !nonEmptyString(value.native_action.type)
        || !validParameters(value.native_action.parameters))
        return false;
    if (!config.require_request_binding)
        return true;
    try {
        computeOasntRequestFingerprint(value.request);
        return true;
    }
    catch {
        return false;
    }
}
function fallbackNative(input, pins) {
    const evidenceDigest = safeDigest(input?.artifact);
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: evidenceDigest,
        status_digest: statusDigest(input?.status),
        evidence_role: pins.config.evidence_role,
        subject: { id: pins.config.subject.id, kind: 'human' },
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
function verifyNative(input, pins) {
    const result = fallbackNative(input, pins);
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== pins.rootsDigest) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:constructor_pin_mismatch'];
        return result;
    }
    if (!exactExpectedAction(input.expected_action, pins.config)) {
        result.reasons = [pins.config.require_request_binding
                ? 'oasnt:concrete_request_required'
                : 'oasnt:ambiguous_expected_action'];
        return result;
    }
    const token = parseCompactToken(input.artifact);
    if (!token) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:malformed_token'];
        return result;
    }
    const claims = token.claims;
    if (!nonEmptyString(claims.sub)
        || !canonicalBase64url(claims.adg, 32)
        || !canonicalBase64url(claims.dsp, 32)
        || (claims.rqf !== undefined && !canonicalBase64url(claims.rqf, 32))
        || (claims.asl !== undefined
            && !(typeof claims.asl === 'string' && ASL_SYNTAX_RE.test(claims.asl)))
        || !['clean', 'compromised', 'unknown'].includes(String(claims.int))
        || !nonEmptyString(claims.jti)
        || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
        || !isRecord(claims.cnf) || !exactKeys(claims.cnf, CNF_KEYS)
        || !canonicalBase64url(claims.cnf.jkt, 32)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:claims_invalid'];
        return result;
    }
    result.replay_unit = safeDigest({
        protocol: OASNT_DRAFT_REVISION,
        subject: claims.sub,
        jti: claims.jti,
        key_thumbprint: claims.cnf.jkt,
    });
    const tokenThumbprint = claims.cnf.jkt;
    const root = pins.roots.find((candidate) => candidate.jwk_thumbprint === tokenThumbprint);
    if (!root || claims.sub !== pins.config.subject.native_id
        || root.native_subject !== claims.sub) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:enrolled_key_or_subject_mismatch'];
        return result;
    }
    let signatureValid = false;
    try {
        signatureValid = crypto.verify('sha256', Buffer.from(token.signingInput, 'ascii'), { key: root.key, dsaEncoding: 'ieee-p1363' }, token.signature);
    }
    catch {
        signatureValid = false;
    }
    if (!signatureValid) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:signature_invalid'];
        return result;
    }
    const nowMs = parseInstant(input.now);
    if (!Number.isFinite(nowMs)) {
        result.reasons = ['oasnt:verification_time_invalid'];
        return result;
    }
    const nowSeconds = Math.floor(nowMs / 1000);
    const iat = Number(claims.iat);
    const exp = Number(claims.exp);
    if (exp < nowSeconds || iat > nowSeconds + pins.config.clock_skew_seconds
        || exp <= iat || exp - iat > pins.config.max_token_lifetime_seconds) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:token_time_invalid'];
        return result;
    }
    const nativeAction = input.expected_action.native_action;
    const parameters = nativeAction.parameters;
    if (claims.adg !== computeOasntActionDigest(String(nativeAction.type), parameters)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:action_digest_mismatch'];
        return result;
    }
    if (claims.dsp !== computeOasntDisplayDigest(String(nativeAction.type), parameters)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:display_digest_mismatch'];
        return result;
    }
    if (pins.config.require_request_binding
        && claims.rqf !== computeOasntRequestFingerprint(input.expected_action.request)) {
        result.acceptance = 'REJECTED';
        result.reasons = [claims.rqf === undefined ? 'oasnt:request_fingerprint_missing' : 'oasnt:request_fingerprint_mismatch'];
        return result;
    }
    if (claims.int !== 'clean') {
        result.acceptance = 'REJECTED';
        result.reasons = ['oasnt:runtime_integrity_not_clean'];
        return result;
    }
    // Assurance (draft sec 5.4). Evaluated only when this relying party pinned
    // a floor: with no requirement, neither absent nor unrecognized asl is
    // evaluated (sec 5.4.2). The effective level is the LESSER of the claimed
    // level and the enrollment ceiling (sec 5.4.1), so an over-claim buys
    // nothing. This trust-root version records hardware attestation but no
    // display-path attestation, so its ceiling is at most platform-key and
    // attested-display can never be effective under it. Absent and unrecognized
    // asl decide identically (both refuse a floor) and are distinguished only
    // in the reported reason, exactly as sec 5.4.2 requires. The sec 5.4.1
    // SHOULD-level over-claim report is carried at the composition layer;
    // this result's reason vocabulary is decision-bearing only.
    const required = pins.config.required_assurance_level;
    if (required !== null) {
        const requiredRank = OASNT_ASSURANCE_LEVELS[required];
        const claimed = typeof claims.asl === 'string' ? claims.asl : undefined;
        if (claimed === undefined) {
            result.acceptance = 'REJECTED';
            result.reasons = ['oasnt:assurance_statement_absent'];
            return result;
        }
        if (!Object.hasOwn(OASNT_ASSURANCE_LEVELS, claimed)) {
            result.acceptance = 'REJECTED';
            result.reasons = ['oasnt:assurance_level_unrecognized'];
            return result;
        }
        const ceiling = root.enrollment.hardware_attested === true ? 'platform-key' : 'software';
        const effectiveRank = Math.min(OASNT_ASSURANCE_LEVELS[claimed], OASNT_ASSURANCE_LEVELS[ceiling]);
        if (effectiveRank < requiredRank) {
            result.acceptance = 'REJECTED';
            result.reasons = ['oasnt:assurance_below_requirement'];
            return result;
        }
    }
    result.native_verification = 'VERIFIED';
    const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    return result;
}
export function createOasntActionDefinition(actionType, requireRequestBinding) {
    if (!ACTION_TYPE_RE.test(actionType) || typeof requireRequestBinding !== 'boolean') {
        throw new TypeError('invalid OASNT action definition');
    }
    const required = [
        { name: 'action_type', type: 'string' },
        { name: 'native_action', type: 'object' },
    ];
    if (requireRequestBinding)
        required.push({ name: 'request', type: 'object' });
    return {
        '@version': OASNT_CAID_MAPPING_VERSION,
        native_protocol: OASNT_DRAFT_REVISION,
        projection: 'oasnt-exact-action-v1',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: required,
                optional_fields: [],
            }],
    };
}
function validMappingProfile(profile, config) {
    if (!isRecord(profile)
        || profile.version !== OASNT_CAID_MAPPING_VERSION
        || profile.mapper_id !== OASNT_CAID_MAPPER_ID
        || !isRecord(profile.resolver)
        || profile.resolver.id !== OASNT_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || typeof profile.resolver.implementation_digest !== 'string'
        || !DIGEST_RE.test(profile.resolver.implementation_digest)
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !isRecord(profile.definition)
        || !exactKeys(profile.definition, MAPPING_KEYS))
        return false;
    try {
        return safeDigest(profile.definition)
            === safeDigest(createOasntActionDefinition(config.action_type, config.require_request_binding));
    }
    catch {
        return false;
    }
}
function mapAction(input, pins) {
    if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
    }
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== pins.rootsDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
    }
    if (!validMappingProfile(input.profile, pins.config)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
    }
    if (!exactExpectedAction(input.expected_action, pins.config)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
    }
    const actionDigest = safeDigest(input.expected_action);
    let computed;
    try {
        computed = computeCaid(input.expected_action, {
            suite: 'jcs-sha256',
            definitions: input.profile.definition.definitions,
        });
    }
    catch {
        computed = null;
    }
    if (!isRecord(computed) || typeof computed.caid !== 'string'
        || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_mapping_failed'] };
    }
    if (computed.digest !== actionDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
    }
    return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
}
export function createOasntAebAdapter(constructorPins) {
    const pins = parsePins(constructorPins);
    return Object.freeze({
        id: OASNT_AEB_ADAPTER_ID,
        version: OASNT_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input, pins);
            }
            catch {
                const result = fallbackNative(input, pins);
                result.reasons = ['oasnt:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                return mapAction(input, pins);
            }
            catch {
                return {
                    mapping: 'INDETERMINATE', caid: null, action_digest: null,
                    reasons: ['oasnt:unexpected_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=aeb-oasnt-adapter.js.map