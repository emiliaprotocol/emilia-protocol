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
import { signAgileSet, verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from './pq-signature-agility.js';
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
    'directory_observation_basis', 'directory_observed_at',
    'resource_server_key_id', 'resource_server_key_digest',
]);
const ARTIFACT_KEYS = new Set(['@version', 'grant', 'human_evidence']);
const CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'human_evidence_role', 'issuer', 'audience',
    'resource_server_key_id', 'action_type', 'clock_skew_seconds',
    'max_token_age_seconds', 'max_directory_snapshot_age_seconds',
    'resource_server_key_digest',
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
        || value.max_token_age_seconds > 86_400
        || !safeInteger(value.max_directory_snapshot_age_seconds)
        || value.max_directory_snapshot_age_seconds < 1
        || value.max_directory_snapshot_age_seconds > 604_800)
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
        || value.directory_observation_basis !== 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT'
        || !safeInteger(value.directory_observed_at)
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
function directorySnapshotDisposition(claims, config, now) {
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) {
        return { acceptance: 'INDETERMINATE', reasons: ['as-confirmation:now_invalid'] };
    }
    const nowSeconds = Math.floor(nowMs / 1000);
    if (claims.directory_observed_at > claims.iat) {
        return { acceptance: 'REJECTED', reasons: ['as-confirmation:directory_snapshot_after_issuance'] };
    }
    if (claims.directory_observed_at > nowSeconds + config.clock_skew_seconds) {
        return { acceptance: 'INDETERMINATE', reasons: ['as-confirmation:directory_snapshot_in_future'] };
    }
    if (nowSeconds - claims.directory_observed_at
        > config.max_directory_snapshot_age_seconds + config.clock_skew_seconds) {
        return { acceptance: 'INDETERMINATE', reasons: ['as-confirmation:directory_snapshot_too_old'] };
    }
    return { acceptance: 'ACCEPTED', reasons: [] };
}
function combineAcceptance(first, second) {
    const acceptance = first.acceptance === 'REJECTED' || second.acceptance === 'REJECTED'
        ? 'REJECTED'
        : first.acceptance === 'INDETERMINATE' || second.acceptance === 'INDETERMINATE'
            ? 'INDETERMINATE'
            : 'ACCEPTED';
    return { acceptance, reasons: [...new Set([...first.reasons, ...second.reasons])].sort() };
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
    const disposition = combineAcceptance(directorySnapshotDisposition(grant.value.claims, pins.config, input.now), statusDisposition(input.status, input.now));
    result.acceptance = disposition.acceptance;
    result.reasons = disposition.reasons;
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
        || value.directory_observation_basis !== 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT'
        || !safeInteger(value.directory_observed_at) || value.directory_observed_at > value.iat
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
// ===========================================================================
// EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 -- the hybrid (Ed25519 + ML-DSA-65)
// confirmation grant.
// ===========================================================================
/**
 * WHY THE JOSE `alg` HEADER IS GONE IN v2, STATED PLAINLY.
 *
 * v1's grant is a compact JWS whose protected header carries `alg: "EdDSA"`, a
 * value from the IANA JOSE Algorithms registry. There is no JOSE `alg` value
 * for ML-DSA-65 that this repository can trace to a source: the only ML-DSA
 * algorithm identifier carried anywhere in this tree is the COSE one (see
 * packages/verify/src/aeb-mcgraw-delegation-adapter.ts, RFC 9964), and
 * docs/protocol/pq-hybrid-program.md records that the JOSE registration is
 * still draft work. Putting an invented value in the JOSE `alg` slot would be
 * squatting on a foreign registry, so v2 does not do it.
 *
 * Instead the v2 protected header carries NO `alg` at all. Each signature
 * carries its own algorithm label from EP's OWN closed registry
 * (EP-SIG-AGILITY-v1: exactly { Ed25519, ML-DSA-65 }) in the AgileSignature
 * shape, and the header commits to the required SET. The envelope is therefore
 * EP-owned end to end and makes no claim on JOSE. It is deliberately NOT a
 * compact JWS and deliberately NOT presented as one: `typ` changes too.
 *
 * The five moves from EP-REVOCATION-v2, applied here:
 *
 * 1. VERSION BUMP. The artifact takes ARTIFACT-v2 and the claims take
 *    ep_version v2. The v1 parser (parseArtifact) pins `@version` to the v1
 *    marker with an exact closed key set, so it refuses a v2 artifact on the
 *    version marker before any signature work and does not throw. Asserted by
 *    test.
 * 2. SET SHAPE. `signatures` is an array of { alg, sig, key_id }, one entry per
 *    registered algorithm, verified through verifyAgileSignatureSet.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` lives INSIDE the protected
 *    header, and the protected header is inside the ASCII signing input
 *    (`<protected>.<payload>`), exactly the v1 convention. Narrow the set and
 *    the classical signature no longer verifies, because the signing input
 *    changed. The verifier additionally rebuilds the expected header from the
 *    REGISTERED set and refuses a mismatch structurally.
 * 4. V1 COMPATIBILITY. signAuthorizationServerConfirmation() and the whole
 *    synchronous AebAdapter path are UNCHANGED. ML-DSA verification is async
 *    and AebAdapter.verifyNative() is synchronous by contract, so v2 is a
 *    separate async entry point and there is no hybrid adapter in this release.
 * 5. NAMED REFUSALS. Nothing throws on caller input; an absent ML-DSA backend
 *    surfaces as `pq_backend_unavailable` and never passes on the classical leg.
 *
 * COORDINATION BOUNDARY, kept. The signer here is logically a third-party
 * Authorization Server that vendored this helper. Shipping the v2 verifier does
 * not make any AS emit v2 grants: every AS integration must deploy a second
 * (ML-DSA-65) key and the v2 signer before a relying party can REQUIRE both
 * legs. This profile is opt-in and is not deployed, default, or certified.
 */
export const AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-v2';
export const AUTHORIZATION_SERVER_CONFIRMATION_V2_ARTIFACT_VERSION = 'EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v2';
export const AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP = 'ep-as-confirmation+hybrid';
/** The registered required algorithm set, in canonical order. */
export const AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const V2_HEADER_KEYS = new Set(['ep_version', 'typ', 'kid', 'pq_kid', 'required_algorithms']);
const V2_SIGNATURE_KEYS = new Set(['alg', 'sig', 'key_id']);
const V2_GRANT_KEYS = new Set(['protected', 'payload', 'signatures']);
function asConfirmationV2SetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS[i]);
}
/**
 * The v2 protected header. `required_algorithms` is a MEMBER of it, so it is
 * inside the signing input both legs cover. Rebuilt by the verifier from the
 * REGISTERED set; the presented grant never chooses what it is checked against.
 */
export function authorizationServerConfirmationV2ProtectedHeader(keyId, pqKeyId, requiredAlgorithms = AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS) {
    if (!asConfirmationV2SetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('authorizationServerConfirmationV2ProtectedHeader: algorithm set is not the registered EP-AUTHORIZATION-SERVER-CONFIRMATION-v2 set');
    }
    return {
        ep_version: AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION,
        typ: AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP,
        kid: keyId,
        pq_kid: pqKeyId,
        required_algorithms: [...requiredAlgorithms],
    };
}
/** ASCII `<protected>.<payload>`: the exact v1 signing-input convention. */
export function authorizationServerConfirmationV2SigningInput(protectedB64u, payloadB64u) {
    return Buffer.from(`${protectedB64u}.${payloadB64u}`, 'ascii');
}
function v2SignableClaims(value) {
    if (!isRecord(value) || value.ep_version !== AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION)
        return false;
    // Reuse the v1 claim validator verbatim by swapping only the version marker,
    // so the two versions cannot drift on claim semantics.
    return signableClaims({ ...value, ep_version: AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION });
}
/**
 * Sign a v2 confirmation grant under BOTH registered algorithms. Issuer-side
 * misuse throws; an unavailable ML-DSA backend throws rather than minting a
 * one-legged v2 grant.
 */
export async function signAuthorizationServerConfirmationV2(claims, signer, options = {}) {
    if (!v2SignableClaims(claims)
        || !nonEmptyIdentifier(signer?.key_id) || !nonEmptyIdentifier(signer?.pq_key_id)
        || !(signer?.private_key instanceof crypto.KeyObject)
        || signer.private_key.type !== 'private'
        || signer.private_key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('valid closed v2 confirmation claims and Ed25519 + ML-DSA-65 signer required');
    }
    const header = canonicalizeAeb(authorizationServerConfirmationV2ProtectedHeader(signer.key_id, signer.pq_key_id));
    const payload = canonicalizeAeb(claims);
    const protectedB64u = Buffer.from(header, 'utf8').toString('base64url');
    const payloadB64u = Buffer.from(payload, 'utf8').toString('base64url');
    const signingInput = authorizationServerConfirmationV2SigningInput(protectedB64u, payloadB64u);
    const signatures = await signAgileSet(new Uint8Array(signingInput), [
        { alg: 'Ed25519', private_key: signer.private_key, key_id: signer.key_id },
        { alg: 'ML-DSA-65', private_key: signer.pq_secret_key, key_id: signer.pq_key_id },
    ], options);
    return {
        protected: protectedB64u,
        payload: payloadB64u,
        signatures: signatures.map((s) => ({ alg: s.alg, sig: s.sig, key_id: String(s.key_id ?? '') })),
    };
}
/**
 * verifyAuthorizationServerConfirmationV2 -- FAIL-CLOSED hybrid check of a v2
 * grant against a pinned AS key pair and a pinned adapter config. Never throws
 * on caller input; a v2 grant NEVER verifies on one leg alone.
 *
 * SCOPE. This checks the GRANT: header shape, committed algorithm set, both
 * signature legs under pinned keys, and closed claim validity against the
 * config's issuer/audience/action_type. It does not evaluate status, freshness
 * windows, directory-snapshot age, or AEB acceptance; those stay with the
 * synchronous v1 adapter, which is unchanged.
 */
export async function verifyAuthorizationServerConfirmationV2(grant, pin, config, options = {}) {
    const checks = {
        structure: true,
        version: true,
        algorithm_set: true,
        legs_present: true,
        as_key_pinned: true,
        claims_valid: true,
        signature_valid: true,
        signature_binds_grant: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    const done = (claims) => ({ valid: Object.values(checks).every(Boolean), checks, errors, ...(claims ? { claims } : {}) });
    if (!isRecord(grant) || !exactKeys(grant, V2_GRANT_KEYS)
        || typeof grant.protected !== 'string' || typeof grant.payload !== 'string') {
        fail('structure', 'grant must be the exact closed { protected, payload, signatures } shape');
        fail('signature_valid', 'grant shape refused before any signature was inspected');
        return done();
    }
    const header = parseJsonSegment(grant.protected);
    const rawClaims = parseJsonSegment(grant.payload);
    if (!header || !rawClaims) {
        fail('structure', 'protected header and payload must be strict-JSON base64url segments');
        fail('signature_valid', 'grant segments refused before any signature was inspected');
        return done();
    }
    if (!exactKeys(header, V2_HEADER_KEYS)) {
        fail('structure', 'protected header must use the exact closed v2 key set');
    }
    if (header.ep_version !== AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION) {
        fail('version', `unsupported version: ${String(header.ep_version)}`);
    }
    if (header.typ !== AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP) {
        fail('structure', `protected header typ must be ${AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP}`);
    }
    if (!asConfirmationV2SetMatchesRegistered(header.required_algorithms)) {
        fail('algorithm_set', `protected header required_algorithms must be exactly ${JSON.stringify([...AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    const signatures = Array.isArray(grant.signatures) ? grant.signatures : null;
    if (!signatures || signatures.length === 0) {
        fail('legs_present', 'signatures must carry one entry per required algorithm');
    }
    else {
        const presented = new Set();
        let malformed = false;
        for (const s of signatures) {
            if (!isRecord(s) || !exactKeys(s, V2_SIGNATURE_KEYS)
                || typeof s.alg !== 'string' || typeof s.sig !== 'string' || typeof s.key_id !== 'string') {
                fail('legs_present', 'each signatures entry must be { alg, sig, key_id }');
                malformed = true;
                break;
            }
            if (presented.has(s.alg)) {
                fail('legs_present', `duplicate signature for algorithm "${s.alg}"`);
                malformed = true;
                break;
            }
            presented.add(s.alg);
        }
        if (!malformed) {
            for (const alg of AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS) {
                if (!presented.has(alg))
                    fail('legs_present', `missing required ${alg} signature (leg stripped)`);
            }
            for (const alg of presented) {
                if (!AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                    fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
                }
            }
        }
    }
    // Pinned halves only; the grant's own key identifiers are matched against the
    // pin, never used as a fallback source of key material.
    const pinnedEd = isRecord(pin) && typeof pin.public_key === 'string' ? pin.public_key : '';
    const pinnedPq = isRecord(pin) && typeof pin.pq_public_key === 'string' ? pin.pq_public_key : '';
    if (!pinnedEd || !pinnedPq
        || !nonEmptyIdentifier(pin?.key_id)
        || !nonEmptyIdentifier(pin?.pq_key_id)) {
        fail('as_key_pinned', 'a pinned Ed25519 + ML-DSA-65 Authorization Server key pair is required (identified but not trusted)');
    }
    else {
        if (canonicalPublicKey(pinnedEd) === null) {
            fail('as_key_pinned', 'pinned Ed25519 AS key is not a canonical Ed25519 SPKI');
        }
        const pqBytes = decodeB64url(pinnedPq, ML_DSA_65_PUBLIC_KEY_BYTES);
        if (!pqBytes || pqBytes.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
            fail('as_key_pinned', `pinned ML-DSA-65 AS key must be ${ML_DSA_65_PUBLIC_KEY_BYTES} raw bytes, base64url`);
        }
        if (header.kid !== pin.key_id) {
            fail('as_key_pinned', 'protected header kid != pinned Ed25519 key_id');
        }
        if (header.pq_kid !== pin.pq_key_id) {
            fail('as_key_pinned', 'protected header pq_kid != pinned ML-DSA-65 key_id');
        }
    }
    // The header the verifier EXPECTS, rebuilt from the pin and the REGISTERED
    // set, must be byte-identical to the presented one. This is what makes the
    // committed set non-negotiable rather than merely declared.
    if (checks.as_key_pinned) {
        let expected = null;
        try {
            expected = Buffer.from(canonicalizeAeb(authorizationServerConfirmationV2ProtectedHeader(pin.key_id, pin.pq_key_id)), 'utf8').toString('base64url');
        }
        catch {
            expected = null;
        }
        if (expected === null || expected !== grant.protected) {
            fail('structure', 'protected header does not equal the header rebuilt from the pin and the registered algorithm set');
        }
    }
    const parsedConfig = parseConfig(config);
    if (!parsedConfig) {
        fail('claims_valid', 'a valid pinned adapter configuration is required');
    }
    else if (!v2SignableClaims(rawClaims)
        || rawClaims.iss !== parsedConfig.issuer || rawClaims.aud !== parsedConfig.audience
        || parseAction(rawClaims.action, parsedConfig.action_type) === null
        || rawClaims.resource_server_key_id !== parsedConfig.resource_server_key_id
        || rawClaims.resource_server_key_digest !== parsedConfig.resource_server_key_digest) {
        fail('claims_valid', 'claims are not the exact closed v2 claim set for this pinned configuration');
    }
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(authorizationServerConfirmationV2SigningInput(grant.protected, grant.payload)), signatures ?? [], [
            { alg: 'Ed25519', public_key: pinnedEd, key_id: pin?.key_id },
            { alg: 'ML-DSA-65', public_key: pinnedPq, key_id: pin?.pq_key_id },
        ], {
            ...options,
            policy: 'hybrid_all',
            requiredAlgorithms: [...AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        const failedLeg = Array.isArray(setResult?.results)
            ? setResult.results.find((r) => r?.verified !== true) ?? null
            : null;
        fail('signature_valid', `AS confirmation signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
        if (failedLeg?.reason === 'signature_invalid') {
            fail('signature_binds_grant', 'signature set does not bind the presented protected header and payload bytes');
        }
    }
    return done(checks.claims_valid ? rawClaims : undefined);
}
//# sourceMappingURL=authorization-server-confirmation.js.map