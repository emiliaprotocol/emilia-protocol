// SPDX-License-Identifier: Apache-2.0
/**
 * PSEA -02 native verification and optional AEB projection.
 *
 * PSEA is treated as a human-authority evidence provider, never as the final
 * execution authority.  The pure adapter verifies the native JWS/EAT proof and
 * projects its exact action into CAID.  Execution callers MUST additionally use
 * verifyAndCommitPseaProof (or an equivalent durable transaction) so the PSEA
 * counter comparison and jti finalization happen atomically before Gate admits
 * the effect.
 *
 * Source pinned by this implementation:
 * https://www.ietf.org/archive/id/draft-yossif-psea-02.html
 */
import crypto from 'node:crypto';
import { canonicalizeStrictJson } from './strict-json.js';
import { strictJsonGate } from './strict-json.js';
// The CAID reference implementation is JavaScript and intentionally has no
// TypeScript declaration surface in this repository.
// @ts-expect-error -- checked at runtime and narrowed below.
import { computeCaid } from '../vendor/caid.mjs';
export const PSEA_SOURCE_REVISION = 'draft-yossif-psea-02';
export const PSEA_EAT_PROFILE = 'urn:ietf:params:psea:eat-profile:1';
export const PSEA_PROOF_VERSION = '1';
export const PSEA_AEB_ADAPTER_ID = 'native:psea-eat-jws';
export const PSEA_AEB_ADAPTER_VERSION = '1';
export const PSEA_AEB_CONFIG_VERSION = 'AEB-PSEA-CONFIG-v1';
export const PSEA_AEB_TRUST_ROOT_VERSION = 'AEB-PSEA-ES256-ROOT-v1';
export const PSEA_AEB_CAID_MAPPING_VERSION = 'AEB-PSEA-CAID-MAPPING-v1';
export const PSEA_AEB_CAID_MAPPER_ID = 'mapper:psea-jcs-action-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const IDENT_RE = /^[A-Za-z0-9_.:@/-]{1,256}$/;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const JTI_RE = /^[A-Za-z0-9._-]{1,128}$/;
const KID_RE = /^[A-Za-z0-9._~:/+-]{1,256}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const SHA256_B64_RE = /^[A-Za-z0-9+/]{43}=$/;
const HEADER_KEYS = new Set(['alg', 'kid', 'typ']);
const ARTIFACT_KEYS = new Set(['proof', 'actionPayload', 'integrityEvidence']);
const UV_KEYS = new Set(['verified', 'method']);
const SUBMOD_KEYS = new Set(['psea-device-state']);
const REQUIRED_CLAIMS = new Set([
    'jti', 'aud', 'iss', 'iat', 'exp', 'ueid', 'eat_profile', 'psea_tier',
    'psea_op', 'psea_counter', 'psea_payload_hash', 'psea_uv',
    'psea_proof_version',
]);
const OPTIONAL_CLAIMS = new Set([
    'eat_nonce', 'submods', 'psea_chain_prev', 'psea_caller_package',
    'psea_sdk_version', 'psea_user_hash', 'psea_chain_pending',
    'psea_last_confirmed_head', 'psea_rp_context_hash',
]);
const CLAIM_KEYS = new Set([...REQUIRED_CLAIMS, ...OPTIONAL_CLAIMS]);
const CONFIG_KEYS = new Set([
    '@version', 'source_revision', 'evidence_role', 'subject', 'action_type',
    'issuer', 'audience', 'operation', 'tier', 'expected_nonce',
    'max_token_lifetime_seconds', 'max_clock_skew_seconds',
    'max_status_age_seconds', 'required_attestation_statuses', 'replay_mode',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const ROOT_KEYS = new Set([
    '@version', 'source_revision', 'issuer', 'kid', 'public_key_spki', 'ueid',
    'subject_native_id', 'enrollment_status', 'attestation_status', 'counter_scope',
]);
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exactKeys(value, allowed) {
    const keys = Object.keys(value);
    return keys.length === allowed.size && keys.every((key) => allowed.has(key));
}
function onlyKnownKeys(value, allowed) {
    return Object.keys(value).every((key) => allowed.has(key));
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0;
}
function safeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function validUnicodeScalarString(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff)
            return false;
    }
    return true;
}
/** RFC 8785-compatible JSON canonicalization for I-JSON data. */
export function canonicalizePsea(value, seen = new WeakSet()) {
    void seen;
    return canonicalizeStrictJson(value);
}
function digestBytes(bytes) {
    return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}
function safeDigest(value) {
    try {
        return digestBytes(Buffer.from(canonicalizePsea(value), 'utf8'));
    }
    catch {
        return digestBytes(Buffer.from('invalid', 'utf8'));
    }
}
function decodeB64u(value) {
    if (!nonEmptyString(value) || !B64U_RE.test(value) || value.length % 4 === 1)
        return null;
    const decoded = Buffer.from(value, 'base64url');
    return decoded.toString('base64url') === value ? decoded : null;
}
function validUeid(value) {
    const bytes = decodeB64u(value);
    return Boolean(bytes && bytes.length === 33 && bytes[0] === 0x01);
}
function validP256Spki(value) {
    const der = decodeB64u(value);
    if (!der)
        return false;
    try {
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'ec'
            && key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
    }
    catch {
        return false;
    }
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== PSEA_AEB_CONFIG_VERSION
        || value.source_revision !== PSEA_SOURCE_REVISION
        || !nonEmptyString(value.evidence_role) || !ROLE_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
        || value.subject.kind !== 'human' || !nonEmptyString(value.subject.id)
        || !IDENT_RE.test(value.subject.id) || !nonEmptyString(value.subject.native_id)
        || !ACTION_TYPE_RE.test(String(value.action_type))
        || !nonEmptyString(value.issuer) || !nonEmptyString(value.audience)
        || !nonEmptyString(value.operation) || !safeInteger(value.tier)
        || !(value.expected_nonce === null || nonEmptyString(value.expected_nonce))
        || !safeInteger(value.max_token_lifetime_seconds)
        || !safeInteger(value.max_clock_skew_seconds) || value.max_clock_skew_seconds > 60
        || !safeInteger(value.max_status_age_seconds)
        || !Array.isArray(value.required_attestation_statuses)
        || value.required_attestation_statuses.length === 0
        || !value.required_attestation_statuses.every((item) => [
            'verified-hardware-uv', 'verified-key-only', 'not-appraised', 'rejected',
        ].includes(String(item)))
        || new Set(value.required_attestation_statuses).size !== value.required_attestation_statuses.length
        || value.replay_mode !== 'gate-atomic-consumption-required')
        return null;
    return value;
}
function parseRoots(values) {
    if (!Array.isArray(values) || values.length === 0)
        return null;
    const roots = new Map();
    for (const value of values) {
        if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
            || value['@version'] !== PSEA_AEB_TRUST_ROOT_VERSION
            || value.source_revision !== PSEA_SOURCE_REVISION
            || !nonEmptyString(value.issuer) || !nonEmptyString(value.kid)
            || !KID_RE.test(value.kid) || !validP256Spki(value.public_key_spki)
            || !validUeid(value.ueid) || !nonEmptyString(value.subject_native_id)
            || !['active', 'revoked'].includes(String(value.enrollment_status))
            || !['verified-hardware-uv', 'verified-key-only', 'not-appraised', 'rejected']
                .includes(String(value.attestation_status))
            || !nonEmptyString(value.counter_scope) || roots.has(value.kid))
            return null;
        roots.set(value.kid, value);
    }
    return roots;
}
function parseJws(proof) {
    const segments = proof.split('.');
    if (segments.length !== 3)
        return null;
    const [encodedHeader, encodedPayload, encodedSignature] = segments;
    const headerBytes = decodeB64u(encodedHeader);
    const payloadBytes = decodeB64u(encodedPayload);
    const signature = decodeB64u(encodedSignature);
    if (!headerBytes || !payloadBytes || !signature || signature.length !== 64)
        return null;
    let headerText;
    let payloadText;
    try {
        headerText = new TextDecoder('utf-8', { fatal: true }).decode(headerBytes);
        payloadText = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
    }
    catch {
        return null;
    }
    if (!strictJsonGate(headerText).ok || !strictJsonGate(payloadText).ok)
        return null;
    let header;
    let payload;
    try {
        header = JSON.parse(headerText);
        payload = JSON.parse(payloadText);
    }
    catch {
        return null;
    }
    if (!isRecord(header) || !exactKeys(header, HEADER_KEYS)
        || header.alg !== 'ES256' || header.typ !== 'psea-proof+jwt'
        || !nonEmptyString(header.kid) || !KID_RE.test(header.kid)
        || !isRecord(payload))
        return null;
    try {
        if (canonicalizePsea(payload) !== payloadText)
            return null;
    }
    catch {
        return null;
    }
    return {
        header,
        payload,
        kid: header.kid,
        signingInput: Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
        signature,
    };
}
function parseClaims(value) {
    if (!onlyKnownKeys(value, CLAIM_KEYS)
        || [...REQUIRED_CLAIMS].some((key) => !Object.hasOwn(value, key))
        || !JTI_RE.test(String(value.jti))
        || !nonEmptyString(value.aud) || !nonEmptyString(value.iss)
        || !safeInteger(value.iat) || !safeInteger(value.exp) || value.exp <= value.iat
        || !validUeid(value.ueid) || value.eat_profile !== PSEA_EAT_PROFILE
        || !safeInteger(value.psea_tier) || !nonEmptyString(value.psea_op)
        || !safeInteger(value.psea_counter)
        || typeof value.psea_payload_hash !== 'string'
        || !SHA256_B64_RE.test(value.psea_payload_hash)
        || Buffer.from(value.psea_payload_hash, 'base64').length !== 32
        || !isRecord(value.psea_uv) || !exactKeys(value.psea_uv, UV_KEYS)
        || value.psea_uv.verified !== true || !nonEmptyString(value.psea_uv.method)
        || value.psea_proof_version !== PSEA_PROOF_VERSION
        || (Object.hasOwn(value, 'eat_nonce') && !nonEmptyString(value.eat_nonce)))
        return null;
    if (Object.hasOwn(value, 'submods')) {
        if (!isRecord(value.submods) || !exactKeys(value.submods, SUBMOD_KEYS)
            || !isRecord(value.submods['psea-device-state']))
            return null;
    }
    for (const key of ['psea_chain_prev', 'psea_caller_package', 'psea_sdk_version', 'psea_user_hash']) {
        if (Object.hasOwn(value, key) && !nonEmptyString(value[key]))
            return null;
    }
    return value;
}
function inspectStatus(status, now, maxAge) {
    const at = Date.parse(now);
    const checked = Date.parse(status?.checked_at);
    const expires = Date.parse(status?.expires_at);
    if (!Number.isFinite(at) || !Number.isFinite(checked) || !Number.isFinite(expires)) {
        return { acceptance: 'INDETERMINATE', reasons: ['psea:status_time_invalid'] };
    }
    if (status.unavailable || !status.revocation_checked) {
        return { acceptance: 'INDETERMINATE', reasons: ['psea:status_unavailable'] };
    }
    if (checked > at || at - checked > maxAge * 1000 || expires < at) {
        return { acceptance: 'INDETERMINATE', reasons: ['psea:status_stale'] };
    }
    if (status.revoked)
        return { acceptance: 'REJECTED', reasons: ['psea:enrollment_revoked'] };
    if (status.consumed)
        return { acceptance: 'REJECTED', reasons: ['psea:evidence_consumed'] };
    return { acceptance: 'ACCEPTED', reasons: [] };
}
function emptyInspection(artifact, reasons) {
    return {
        verified: false,
        reasons,
        proof_digest: isRecord(artifact) && typeof artifact.proof === 'string'
            ? digestBytes(Buffer.from(artifact.proof, 'utf8')) : safeDigest(artifact),
        action_digest: isRecord(artifact) && Object.hasOwn(artifact, 'actionPayload')
            ? safeDigest(artifact.actionPayload) : safeDigest(null),
        claims: null,
        root: null,
        replay_candidate: null,
    };
}
/**
 * Pure native inspection.  Optional replaySnapshot permits deterministic
 * historical checks.  It does not mutate replay state.
 */
export function inspectPseaProof(input) {
    const config = parseConfig(input.config);
    if (!config)
        return emptyInspection(input.artifact, ['psea:invalid_pinned_config']);
    const roots = parseRoots(input.trust_roots);
    if (!roots)
        return emptyInspection(input.artifact, ['psea:invalid_pinned_trust_roots']);
    if (!isRecord(input.artifact) || !onlyKnownKeys(input.artifact, ARTIFACT_KEYS)
        || !Object.hasOwn(input.artifact, 'proof')
        || !Object.hasOwn(input.artifact, 'actionPayload')
        || typeof input.artifact.proof !== 'string') {
        return emptyInspection(input.artifact, ['psea:malformed_artifact']);
    }
    let actionCanonical;
    try {
        actionCanonical = canonicalizePsea(input.artifact.actionPayload);
    }
    catch {
        return emptyInspection(input.artifact, ['psea:action_not_i_json']);
    }
    const parsed = parseJws(input.artifact.proof);
    if (!parsed)
        return emptyInspection(input.artifact, ['psea:malformed_or_noncanonical_jws']);
    const root = roots.get(parsed.kid);
    if (!root)
        return emptyInspection(input.artifact, ['psea:unknown_enrolled_key']);
    const key = crypto.createPublicKey({
        key: Buffer.from(root.public_key_spki, 'base64url'), format: 'der', type: 'spki',
    });
    const signatureValid = crypto.verify('sha256', parsed.signingInput, { key, dsaEncoding: 'ieee-p1363' }, parsed.signature);
    if (!signatureValid)
        return emptyInspection(input.artifact, ['psea:signature_invalid']);
    const claims = parseClaims(parsed.payload);
    if (!claims)
        return emptyInspection(input.artifact, ['psea:claim_set_invalid']);
    const reasons = [];
    if (claims.iss !== config.issuer || root.issuer !== config.issuer)
        reasons.push('psea:issuer_mismatch');
    if (claims.aud !== config.audience)
        reasons.push('psea:audience_mismatch');
    if (claims.psea_op !== config.operation)
        reasons.push('psea:operation_mismatch');
    if (claims.psea_tier !== config.tier)
        reasons.push('psea:tier_mismatch');
    if (claims.ueid !== root.ueid)
        reasons.push('psea:ueid_mismatch');
    if (root.subject_native_id !== config.subject.native_id)
        reasons.push('psea:subject_enrollment_mismatch');
    if (root.enrollment_status !== 'active')
        reasons.push('psea:enrollment_revoked');
    if (!config.required_attestation_statuses.includes(root.attestation_status)) {
        reasons.push('psea:inadequate_attestation');
    }
    if (config.expected_nonce !== null && claims.eat_nonce !== config.expected_nonce) {
        reasons.push('psea:nonce_mismatch');
    }
    const nowSeconds = Math.floor(Date.parse(input.now) / 1000);
    if (!Number.isSafeInteger(nowSeconds))
        reasons.push('psea:invalid_verification_time');
    else {
        if (claims.iat > nowSeconds + config.max_clock_skew_seconds)
            reasons.push('psea:issued_in_future');
        if (claims.exp < nowSeconds - config.max_clock_skew_seconds)
            reasons.push('psea:proof_expired');
        if (claims.exp - claims.iat > config.max_token_lifetime_seconds)
            reasons.push('psea:lifetime_exceeded');
    }
    const expectedPayloadHash = crypto.createHash('sha256')
        .update(actionCanonical, 'utf8').digest('base64');
    if (claims.psea_payload_hash !== expectedPayloadHash)
        reasons.push('psea:action_hash_mismatch');
    if (input.replay_snapshot) {
        const seen = input.replay_snapshot.seen_jtis instanceof Set
            ? input.replay_snapshot.seen_jtis
            : new Set(input.replay_snapshot.seen_jtis);
        if (seen.has(claims.jti))
            reasons.push('psea:jti_replay');
        if (input.replay_snapshot.highest_counter !== null
            && claims.psea_counter <= input.replay_snapshot.highest_counter) {
            reasons.push('psea:counter_rollback');
        }
    }
    const proofDigest = digestBytes(Buffer.from(input.artifact.proof, 'utf8'));
    const actionDigest = digestBytes(Buffer.from(actionCanonical, 'utf8'));
    const replayUnit = safeDigest({
        source_revision: PSEA_SOURCE_REVISION,
        issuer: claims.iss,
        ueid: claims.ueid,
        counter_scope: root.counter_scope,
        counter: claims.psea_counter,
        jti: claims.jti,
    });
    return {
        verified: reasons.length === 0,
        reasons: [...new Set(reasons)].sort(),
        proof_digest: proofDigest,
        action_digest: actionDigest,
        claims,
        root,
        replay_candidate: {
            scope: root.counter_scope,
            counter: claims.psea_counter,
            jti: claims.jti,
            replay_unit: replayUnit,
        },
    };
}
/** Verify and atomically finalize counter+jti before Gate admission. */
export async function verifyAndCommitPseaProof(input) {
    const config = parseConfig(input.config);
    const roots = parseRoots(input.trust_roots);
    if (!config || !roots || !isRecord(input.artifact) || typeof input.artifact.proof !== 'string') {
        return { ...inspectPseaProof(input), replay_committed: false };
    }
    const preliminary = parseJws(input.artifact.proof);
    const root = preliminary ? roots.get(preliminary.kid) : null;
    if (!root)
        return { ...inspectPseaProof(input), replay_committed: false };
    const snapshot = await input.replay_store.inspect(root.counter_scope);
    const inspected = inspectPseaProof({ ...input, replay_snapshot: snapshot });
    if (!inspected.verified || !inspected.replay_candidate) {
        return { ...inspected, replay_committed: false };
    }
    const committed = await input.replay_store.commit(inspected.replay_candidate);
    if (!committed.committed) {
        return {
            ...inspected,
            verified: false,
            reasons: [`psea:${committed.reason}`],
            replay_committed: false,
        };
    }
    return { ...inspected, replay_committed: true };
}
/** Reference only. Production must use a durable transaction/fence. */
export class InMemoryPseaReplayStore {
    counters = new Map();
    jtis = new Set();
    async inspect(scope) {
        return { highest_counter: this.counters.get(scope) ?? null, seen_jtis: new Set(this.jtis) };
    }
    async commit(candidate) {
        if (this.jtis.has(candidate.jti))
            return { committed: false, reason: 'jti_replay' };
        const current = this.counters.get(candidate.scope);
        if (current !== undefined && candidate.counter <= current) {
            return { committed: false, reason: 'counter_rollback' };
        }
        this.jtis.add(candidate.jti);
        this.counters.set(candidate.scope, candidate.counter);
        return { committed: true };
    }
}
function fallbackNative(input, reason) {
    const config = parseConfig(input.adapter_config);
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: isRecord(input.artifact) && typeof input.artifact.proof === 'string'
            ? digestBytes(Buffer.from(input.artifact.proof, 'utf8')) : safeDigest(input.artifact),
        status_digest: safeDigest(input.status),
        evidence_role: config?.evidence_role ?? 'human_authorization',
        subject: config ? { id: config.subject.id, kind: 'human' } : { id: 'unknown', kind: 'human' },
        replay_unit: safeDigest({ source_revision: PSEA_SOURCE_REVISION, artifact: input.artifact_ref }),
        reasons: [reason],
    };
}
function validMappingProfile(profile, actionType) {
    if (profile.version !== PSEA_AEB_CAID_MAPPING_VERSION
        || profile.mapper_id !== PSEA_AEB_CAID_MAPPER_ID
        || !isRecord(profile.definition)
        || profile.definition['@version'] !== PSEA_AEB_CAID_MAPPING_VERSION
        || profile.definition.native_protocol !== PSEA_SOURCE_REVISION
        || profile.definition.projection !== 'add-action-type-v1'
        || profile.definition.suite !== 'jcs-sha256'
        || profile.definition.action_type !== actionType
        || !Array.isArray(profile.definition.definitions)
        || profile.resolver.id !== PSEA_AEB_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
        || profile.semantic_equivalence.omitted_material_fields.length !== 0)
        return null;
    return profile.definition;
}
/** Pure PSEA-to-AEB adapter. Gate must consume replay_unit atomically. */
export function createPseaAebAdapter() {
    return Object.freeze({
        id: PSEA_AEB_ADAPTER_ID,
        version: PSEA_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                const config = parseConfig(input.adapter_config);
                if (!config)
                    return fallbackNative(input, 'psea:invalid_pinned_config');
                const inspected = inspectPseaProof({
                    artifact: input.artifact,
                    config,
                    trust_roots: input.trust_roots,
                    now: input.now,
                });
                const base = {
                    native_verification: inspected.verified ? 'VERIFIED' : 'FAILED',
                    acceptance: inspected.verified ? 'ACCEPTED' : 'REJECTED',
                    evidence_digest: inspected.proof_digest,
                    status_digest: safeDigest(input.status),
                    evidence_role: config.evidence_role,
                    subject: { id: config.subject.id, kind: 'human' },
                    replay_unit: inspected.replay_candidate?.replay_unit
                        ?? safeDigest({ source_revision: PSEA_SOURCE_REVISION, artifact: input.artifact_ref }),
                    reasons: inspected.reasons,
                };
                if (!inspected.verified)
                    return base;
                const status = inspectStatus(input.status, input.now, config.max_status_age_seconds);
                base.acceptance = status.acceptance;
                base.reasons = status.reasons;
                return base;
            }
            catch {
                return fallbackNative(input, 'psea:unexpected_adapter_error');
            }
        },
        mapAction(input) {
            try {
                if (input.native.native_verification !== 'VERIFIED'
                    || input.native.acceptance !== 'ACCEPTED') {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
                }
                const config = parseConfig(input.adapter_config);
                if (!config)
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_pinned_config_invalid'] };
                const definition = validMappingProfile(input.profile, config.action_type);
                if (!definition)
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
                if (!isRecord(input.artifact) || !isRecord(input.artifact.actionPayload)
                    || Object.hasOwn(input.artifact.actionPayload, 'action_type')) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_action_not_exactly_projectable'] };
                }
                const normalized = { action_type: config.action_type, ...input.artifact.actionPayload };
                const actionDigest = safeDigest(normalized);
                if (actionDigest !== safeDigest(input.expected_action)) {
                    return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['normalized_native_action_mismatch'] };
                }
                const computed = computeCaid(normalized, {
                    suite: 'jcs-sha256', definitions: definition.definitions,
                });
                if (!isRecord(computed) || typeof computed.caid !== 'string'
                    || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
                    const refusals = isRecord(computed) && Array.isArray(computed.refusals)
                        ? computed.refusals.map(String) : ['caid_mapping_failed'];
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: refusals.map((item) => `caid:${item}`) };
                }
                if (computed.digest !== actionDigest) {
                    return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
                }
                return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
            }
            catch {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['psea:unexpected_mapping_error'] };
            }
        },
    });
}
//# sourceMappingURL=aeb-psea-adapter.js.map