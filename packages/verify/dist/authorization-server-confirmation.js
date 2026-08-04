// SPDX-License-Identifier: Apache-2.0
/**
 * Authorization Server confirmation evidence for AEB/AEC.
 *
 * This profile consumes an independently signed AS grant. It never turns that
 * grant into a relying-party authorization verdict. The adapter verifies the
 * AS signature under relying-party-pinned trust, binds it to one exact action,
 * one exact human-evidence artifact, one human subject, and one resource-server
 * audience, then emits an ordinary AEB evidence leg. A separate AEB
 * `evidence-binding` requirement joins it to the natively verified human leg.
 *
 * The profile is deliberately an implementation surface, not a new wire-format
 * standards claim. It is shaped to compose with AS confirmation records such
 * as draft-liu-agent-operation-authorization and with the AS-owned decision
 * boundary in draft-klrc-aiagent-auth.
 */
import crypto from 'node:crypto';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- checked and narrowed at runtime.
import { computeCaid } from '../vendor/caid.mjs';
import { canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
import { strictJsonGate } from './strict-json.js';
export const AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-CONFIG-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ROOT-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID = 'native:authorization-server-confirmation';
export const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION = '1';
export const AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-CAID-MAPPING-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID = 'mapper:authorization-server-confirmation-exact-action-v1';
export const AUTHORIZATION_SERVER_CONFIRMATION_TYP = 'ep-as-confirmation+jwt';
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
// Match the AEB subject/key identifier domain so a natively accepted subject
// cannot later become an unrepresentable AEB leg.
const IDENT_RE = /^[A-Za-z0-9_.:-]{1,256}$/;
const URI_RE = /^https:\/\/[^\s]{1,500}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_BYTES = 131_072;
const MAX_JSON_BYTES = 65_536;
const HEADER_KEYS = new Set(['alg', 'typ', 'kid']);
const CLAIM_KEYS = new Set([
    'ep_version', 'iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti',
    'authorization_server_decision', 'action', 'action_digest',
    'human_evidence_digest', 'policy_digest', 'directory_digest',
    'resource_server_key_id', 'resource_server_key_digest',
]);
const ARTIFACT_KEYS = new Set(['@version', 'grant', 'human_evidence']);
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'human_evidence_role', 'issuer', 'audience',
    'resource_server_key_id', 'action_type', 'clock_skew_seconds',
    'max_token_age_seconds', 'resource_server_key_digest',
]);
const ROOT_KEYS = new Set([
    '@version', 'use', 'issuer', 'key_id', 'algorithm', 'public_key',
]);
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactKeys(value, keys) {
    const actual = Object.keys(value);
    return actual.length === keys.size && actual.every((key) => keys.has(key));
}
function nonEmptyIdentifier(value) {
    return typeof value === 'string' && IDENT_RE.test(value);
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function safeInteger(value) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return `sha256:${'0'.repeat(64)}`;
    }
}
function sameDigest(left, right) {
    const leftDigest = safeDigest(left);
    return leftDigest !== `sha256:${'0'.repeat(64)}` && leftDigest === safeDigest(right);
}
function canonicalPublicKey(value) {
    if (typeof value !== 'string' || !B64URL_RE.test(value))
        return null;
    try {
        const bytes = Buffer.from(value, 'base64url');
        if (bytes.length === 0 || bytes.toString('base64url') !== value)
            return null;
        const key = crypto.createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        const canonical = key.export({ type: 'spki', format: 'der' });
        return key.type === 'public' && key.asymmetricKeyType === 'ed25519'
            && Buffer.isBuffer(canonical) && canonical.equals(bytes) ? key : null;
    }
    catch {
        return null;
    }
}
function decodeB64url(value, maxBytes) {
    if (!B64URL_RE.test(value) || value.length % 4 === 1)
        return null;
    try {
        const decoded = Buffer.from(value, 'base64url');
        return decoded.length > 0 && decoded.length <= maxBytes
            && decoded.toString('base64url') === value ? decoded : null;
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
function parseJsonSegment(value) {
    const bytes = decodeB64url(value, MAX_JSON_BYTES);
    if (!bytes)
        return null;
    const text = decodeUtf8(bytes);
    if (text === null || !strictJsonGate(text).ok)
        return null;
    try {
        const parsed = JSON.parse(text);
        return isRecord(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
}
function parseAction(value, actionType) {
    if (!isRecord(value) || !exactKeys(value, new Set(['action_type', 'parameters']))
        || value.action_type !== actionType || !isRecord(value.parameters))
        return null;
    try {
        canonicalizeAeb(value);
        if (Object.keys(value.parameters).length === 0)
            return null;
        return structuredClone(value);
    }
    catch {
        return null;
    }
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION
        || value.evidence_role !== 'authorization-server-confirmation'
        || value.human_evidence_role !== 'human-authorization'
        || typeof value.issuer !== 'string' || !URI_RE.test(value.issuer)
        || typeof value.audience !== 'string' || !URI_RE.test(value.audience)
        || !nonEmptyIdentifier(value.resource_server_key_id)
        || !validDigest(value.resource_server_key_digest)
        || typeof value.action_type !== 'string' || !ACTION_TYPE_RE.test(value.action_type)
        || !safeInteger(value.clock_skew_seconds) || value.clock_skew_seconds > 300
        || !safeInteger(value.max_token_age_seconds) || value.max_token_age_seconds < 1
        || value.max_token_age_seconds > 86_400)
        return null;
    return structuredClone(value);
}
function parseRoot(value, config) {
    if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION
        || value.use !== 'authorization-server' || value.algorithm !== 'EdDSA'
        || value.issuer !== config.issuer || !nonEmptyIdentifier(value.key_id))
        return null;
    const key = canonicalPublicKey(value.public_key);
    if (!key)
        return null;
    const root = structuredClone(value);
    return { ...root, key };
}
function parseConstructorPins(value) {
    if (!isRecord(value) || !exactKeys(value, new Set(['config', 'trust_roots']))) {
        throw new TypeError('invalid Authorization Server confirmation constructor pins');
    }
    const config = parseConfig(value.config);
    if (!config || !Array.isArray(value.trust_roots) || value.trust_roots.length !== 1) {
        throw new TypeError('invalid Authorization Server confirmation configuration');
    }
    const root = parseRoot(value.trust_roots[0], config);
    if (!root)
        throw new TypeError('invalid Authorization Server confirmation trust root');
    const publicRoot = {
        '@version': root['@version'], use: root.use, issuer: root.issuer,
        key_id: root.key_id, algorithm: root.algorithm, public_key: root.public_key,
    };
    return {
        config,
        root,
        configDigest: digestAeb(config),
        rootsDigest: digestAeb([publicRoot]),
    };
}
function parseArtifact(value) {
    if (!isRecord(value) || !exactKeys(value, ARTIFACT_KEYS)
        || value['@version'] !== AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION
        || typeof value.grant !== 'string' || value.grant.length === 0
        || Buffer.byteLength(value.grant, 'utf8') > MAX_TOKEN_BYTES)
        return null;
    try {
        canonicalizeAeb(value.human_evidence);
    }
    catch {
        return null;
    }
    return structuredClone(value);
}
function parseClaims(value, config) {
    if (!exactKeys(value, CLAIM_KEYS)
        || value.ep_version !== AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION
        || value.iss !== config.issuer || value.aud !== config.audience
        || !nonEmptyIdentifier(value.sub) || !nonEmptyIdentifier(value.jti)
        || value.authorization_server_decision !== 'AUTHORIZED'
        || !safeInteger(value.iat) || !safeInteger(value.nbf) || !safeInteger(value.exp)
        || !validDigest(value.action_digest) || !validDigest(value.human_evidence_digest)
        || !validDigest(value.policy_digest) || !validDigest(value.directory_digest)
        || value.resource_server_key_id !== config.resource_server_key_id
        || value.resource_server_key_digest !== config.resource_server_key_digest
        || parseAction(value.action, config.action_type) === null)
        return null;
    return structuredClone(value);
}
function verifyGrant(artifactValue, pins, now) {
    const artifact = parseArtifact(artifactValue);
    if (!artifact)
        return { ok: false, reason: 'as-confirmation:artifact_malformed', acceptance: 'REJECTED' };
    const parts = artifact.grant.split('.');
    if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
        return { ok: false, reason: 'as-confirmation:jws_malformed', acceptance: 'REJECTED' };
    }
    const header = parseJsonSegment(parts[0]);
    const rawClaims = parseJsonSegment(parts[1]);
    const signature = decodeB64url(parts[2], 64);
    if (!header || !rawClaims || !signature || signature.length !== 64
        || !exactKeys(header, HEADER_KEYS) || header.alg !== 'EdDSA'
        || header.typ !== AUTHORIZATION_SERVER_CONFIRMATION_TYP
        || header.kid !== pins.root.key_id
        || !crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), pins.root.key, signature)) {
        return { ok: false, reason: 'as-confirmation:signature_or_header_invalid', acceptance: 'REJECTED' };
    }
    const claims = parseClaims(rawClaims, pins.config);
    if (!claims)
        return { ok: false, reason: 'as-confirmation:claims_invalid', acceptance: 'REJECTED' };
    const action = parseAction(claims.action, pins.config.action_type);
    if (!action || claims.action_digest !== safeDigest(action)) {
        return { ok: false, reason: 'as-confirmation:action_digest_mismatch', acceptance: 'REJECTED' };
    }
    if (claims.human_evidence_digest !== safeDigest(artifact.human_evidence)) {
        return { ok: false, reason: 'as-confirmation:human_evidence_digest_mismatch', acceptance: 'REJECTED' };
    }
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs))
        return { ok: false, reason: 'as-confirmation:now_invalid', acceptance: 'INDETERMINATE' };
    const nowSeconds = Math.floor(nowMs / 1000);
    const { iat, nbf, exp } = claims;
    if (exp <= iat || exp <= nbf)
        return { ok: false, reason: 'as-confirmation:time_window_invalid', acceptance: 'REJECTED' };
    if (iat > nowSeconds + pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'as-confirmation:issued_in_future', acceptance: 'INDETERMINATE' };
    }
    if (nbf > nowSeconds + pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'as-confirmation:not_yet_valid', acceptance: 'INDETERMINATE' };
    }
    if (exp <= nowSeconds - pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'as-confirmation:expired', acceptance: 'REJECTED' };
    }
    if (nowSeconds - iat > pins.config.max_token_age_seconds + pins.config.clock_skew_seconds) {
        return { ok: false, reason: 'as-confirmation:too_old', acceptance: 'INDETERMINATE' };
    }
    return {
        ok: true,
        value: {
            claims,
            action,
            replayUnit: digestAeb({ issuer: claims.iss, jti: claims.jti }),
        },
    };
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
function statusDisposition(status, now) {
    const reasons = [];
    const nowMs = Date.parse(now);
    const checkedMs = Date.parse(status?.checked_at);
    const expiresMs = Date.parse(status?.expires_at);
    if (status?.unavailable === true)
        reasons.push('status_unavailable');
    if (status?.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (status?.revoked === true)
        reasons.push('evidence_revoked');
    if (status?.consumed === true)
        reasons.push('evidence_consumed');
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)) {
        reasons.push('status_time_invalid');
    }
    else {
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (expiresMs <= nowMs)
            reasons.push('status_expired');
    }
    const unique = [...new Set(reasons)].sort();
    if (status?.revoked === true || status?.consumed === true || (Number.isFinite(expiresMs) && expiresMs <= nowMs)) {
        return { acceptance: 'REJECTED', reasons: unique };
    }
    return unique.length === 0
        ? { acceptance: 'ACCEPTED', reasons: [] }
        : { acceptance: 'INDETERMINATE', reasons: unique };
}
function fallbackNative(input, pins) {
    const evidenceDigest = safeDigest(input?.artifact);
    const subject = { id: 'unknown:authorization-server-subject', kind: 'human' };
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
        result.reasons = ['as-confirmation:constructor_pin_mismatch'];
        return result;
    }
    const grant = verifyGrant(input?.artifact, pins, input?.now);
    if (!grant.ok) {
        result.acceptance = grant.acceptance;
        result.reasons = [grant.reason];
        return result;
    }
    const artifact = parseArtifact(input.artifact);
    result.native_verification = 'VERIFIED';
    result.subject = { id: grant.value.claims.sub, kind: 'human' };
    result.replay_unit = grant.value.replayUnit;
    result.evidence_bindings = [{
            role: pins.config.human_evidence_role,
            evidence_digest: grant.value.claims.human_evidence_digest,
        }];
    const status = statusDisposition(input.status, input.now);
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    // Keep the parsed artifact load-bearing; this prevents a future refactor from
    // accepting a token while silently dropping the human evidence envelope.
    if (safeDigest(artifact.human_evidence) !== grant.value.claims.human_evidence_digest) {
        result.native_verification = 'FAILED';
        result.acceptance = 'REJECTED';
        result.reasons = ['as-confirmation:human_evidence_digest_mismatch'];
    }
    return result;
}
export function createAuthorizationServerConfirmationActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('valid CAID action type required');
    return {
        '@version': AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION,
        source: 'authorization-server-signed-exact-action',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [
                    { name: 'action_type', type: 'string' },
                    { name: 'parameters', type: 'object' },
                ],
                optional_fields: [],
            }],
    };
}
function validMappingProfile(profile, actionType) {
    if (!isRecord(profile) || profile.version !== AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION
        || profile.mapper_id !== AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID
        || !isRecord(profile.resolver) || profile.resolver.id !== AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID
        || profile.resolver.version !== '1' || !validDigest(profile.resolver.implementation_digest)
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || !Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || profile.semantic_equivalence.omitted_material_fields.length !== 0
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || !isRecord(profile.definition)
        || !sameDigest(profile.definition, createAuthorizationServerConfirmationActionDefinition(actionType))
        || !Array.isArray(profile.definition.definitions))
        return null;
    return profile.definition.definitions;
}
function mapAction(input, pins) {
    if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
    }
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== pins.rootsDigest) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_constructor_pin_mismatch'] };
    }
    const definitions = validMappingProfile(input.profile, pins.config.action_type);
    if (!definitions)
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
    const grant = verifyGrant(input.artifact, pins, input.now);
    if (!grant.ok)
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: [grant.reason] };
    const expected = parseAction(input.expected_action, pins.config.action_type);
    if (!expected)
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['missing_or_ambiguous_exact_action'] };
    const actionDigest = safeDigest(grant.value.action);
    if (!sameDigest(grant.value.action, expected)) {
        return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['exact_action_projection_mismatch'] };
    }
    let computed;
    try {
        computed = computeCaid(grant.value.action, { suite: 'jcs-sha256', definitions });
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
function signableClaims(value) {
    if (!isRecord(value) || !exactKeys(value, CLAIM_KEYS)
        || value.ep_version !== AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION
        || typeof value.iss !== 'string' || !URI_RE.test(value.iss)
        || typeof value.aud !== 'string' || !URI_RE.test(value.aud)
        || !nonEmptyIdentifier(value.sub) || !nonEmptyIdentifier(value.jti)
        || value.authorization_server_decision !== 'AUTHORIZED'
        || !safeInteger(value.iat) || !safeInteger(value.nbf) || !safeInteger(value.exp)
        || value.exp <= value.iat || value.exp <= value.nbf
        || !validDigest(value.action_digest) || !validDigest(value.human_evidence_digest)
        || !validDigest(value.policy_digest) || !validDigest(value.directory_digest)
        || !nonEmptyIdentifier(value.resource_server_key_id)
        || !validDigest(value.resource_server_key_digest)
        || !isRecord(value.action) || typeof value.action.action_type !== 'string'
        || !ACTION_TYPE_RE.test(value.action.action_type))
        return false;
    const action = parseAction(value.action, value.action.action_type);
    return action !== null && safeDigest(action) === value.action_digest;
}
export function signAuthorizationServerConfirmation(claims, signer) {
    if (!signableClaims(claims)
        || !nonEmptyIdentifier(signer?.key_id)
        || !(signer?.private_key instanceof crypto.KeyObject)
        || signer.private_key.type !== 'private'
        || signer.private_key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('valid closed confirmation claims and Ed25519 signer required');
    }
    // Canonical JSON is not required by JWS, but using it for this reference
    // signer makes fixtures reproducible and rejects executable non-JSON data.
    const header = canonicalizeAeb({
        alg: 'EdDSA', typ: AUTHORIZATION_SERVER_CONFIRMATION_TYP, kid: signer.key_id,
    });
    const payload = canonicalizeAeb(claims);
    const protectedHeader = Buffer.from(header, 'utf8').toString('base64url');
    const encodedPayload = Buffer.from(payload, 'utf8').toString('base64url');
    const signingInput = `${protectedHeader}.${encodedPayload}`;
    const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), signer.private_key).toString('base64url');
    return `${signingInput}.${signature}`;
}
export function createAuthorizationServerConfirmationAdapter(constructorPins) {
    const pins = parseConstructorPins(constructorPins);
    return Object.freeze({
        id: AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID,
        version: AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input, pins);
            }
            catch {
                const result = fallbackNative(input, pins);
                result.reasons = ['as-confirmation:unexpected_adapter_error'];
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
                    reasons: ['as-confirmation:unexpected_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=authorization-server-confirmation.js.map