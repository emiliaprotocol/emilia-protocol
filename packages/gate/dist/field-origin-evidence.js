// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Signed per-field provenance evidence for one executor-observed action.
 *
 * The artifact authenticates a pinned issuer's assertions about where each
 * exact field came from and whether it was a snapshot of mutable state. It is
 * evaluated before admission. It does not prove the asserted origin is true,
 * detect prompt injection, authorize the action, or prove an external effect.
 */
import { createPublicKey } from 'node:crypto';
import { RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
import { canonicalizeStrictJson } from './strict-json.js';
export const FIELD_ORIGIN_EVIDENCE_VERSION = 'EP-FIELD-ORIGIN-v0.1';
export const FIELD_ORIGIN_CLAIM_BOUNDARY = 'pinned_issuer_asserted_field_provenance_bound_to_exact_action_at_admission_not_source_truth_not_prompt_injection_detection_not_authorization_not_effect_truth';
const PROFILE_KEYS = [
    'profile_id', 'relying_party_id', 'action_type', 'fields', 'transforms',
];
const FIELD_RULE_KEYS = [
    'path', 'role', 'required', 'allowed_origins', 'snapshot_policy',
    'max_snapshot_age_sec', 'allowed_transform_ids',
];
const TRANSFORM_KEYS = ['transform_id', 'version', 'digest'];
const INPUT_KEYS = [
    'evidence_id', 'profile', 'observed_action', 'observed_at', 'annotations',
];
const ANNOTATION_KEYS = ['path', 'origin_class', 'snapshot', 'transform'];
const FIELD_KEYS = [
    'path', 'value_digest', 'origin_class', 'snapshot', 'transform',
];
const SNAPSHOT_KEYS = ['kind', 'observed_at', 'source_version'];
const BODY_KEYS = [
    '@version', 'evidence_id', 'profile_id', 'profile_digest',
    'relying_party_id', 'action_type', 'action_digest', 'observed_at',
    'fields', 'claim_boundary', 'issuer',
];
const CONTEXT_KEYS = [
    'trusted_keys', 'pinned_profile', 'expected_relying_party_id',
    'observed_action', 'now',
];
const ISSUER_KEYS = ['id', 'key_id'];
const SIGNER_KEYS = ['issuer_id', 'key_id', 'private_key'];
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'];
const ORIGIN_CLASSES = new Set([
    'operator_pinned',
    'approver_supplied',
    'untrusted_bounded',
    'derived_via_versioned_transform',
    'unknown',
]);
const PROFILE_ORIGIN_CLASSES = new Set([
    'operator_pinned',
    'approver_supplied',
    'untrusted_bounded',
    'derived_via_versioned_transform',
]);
const FIELD_ROLES = new Set(['control', 'bounded_data']);
const SNAPSHOT_POLICIES = new Set(['immutable', 'mutable_snapshot', 'either']);
const MAX_FIELDS = 256;
const MAX_TRANSFORMS = 64;
const MAX_SNAPSHOT_AGE_SEC = 31_536_000;
export class FieldOriginValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'FieldOriginValidationError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new FieldOriginValidationError(code, message);
}
function strictJsonClone(value) {
    return JSON.parse(canonicalizeStrictJson(value));
}
function byteOrder(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function safeInteger(value, minimum, maximum) {
    return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum;
}
function canonicalInstant(value, field) {
    if (typeof value !== 'string')
        refuse('field_origin_instant_invalid', `${field} must be canonical RFC 3339`);
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
        refuse('field_origin_instant_invalid', `${field} must be canonical RFC 3339`);
    }
    return value;
}
function validPointer(path) {
    return typeof path === 'string'
        && path.startsWith('/')
        && Buffer.byteLength(path, 'utf8') <= 512
        && !/~(?:[^01]|$)/.test(path);
}
function decodePointer(path) {
    if (!validPointer(path))
        refuse('field_origin_path_invalid', 'field path must be a bounded JSON Pointer');
    return path.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'));
}
function encodePointerPart(part) {
    return part.replace(/~/g, '~0').replace(/\//g, '~1');
}
function actionLeafPaths(value, base = '') {
    if (Array.isArray(value) || !riskRecord(value) || Object.keys(value).length === 0) {
        return base ? [base] : [];
    }
    const paths = [];
    for (const key of Object.keys(value).sort(byteOrder)) {
        const next = `${base}/${encodePointerPart(key)}`;
        paths.push(...actionLeafPaths(value[key], next));
    }
    return paths;
}
function valueAtPointer(value, path) {
    let current = value;
    for (const part of decodePointer(path)) {
        if (Array.isArray(current)) {
            if (!/^(0|[1-9][0-9]*)$/.test(part))
                return { found: false, value: null };
            const index = Number(part);
            if (!Number.isSafeInteger(index) || index >= current.length)
                return { found: false, value: null };
            current = current[index];
            continue;
        }
        if (!riskRecord(current) || !Object.hasOwn(current, part))
            return { found: false, value: null };
        current = current[part];
    }
    return { found: true, value: current };
}
function normalizeStringSet(value, allowed, field, maximum) {
    if (!Array.isArray(value) || value.length > maximum
        || value.some((entry) => typeof entry !== 'string'
            || !riskIdentifier(entry)
            || (allowed !== null && !allowed.has(entry)))
        || new Set(value).size !== value.length) {
        refuse(`field_origin_${field}_invalid`, `${field} is invalid`);
    }
    return [...value].sort(byteOrder);
}
function normalizeTransform(value) {
    if (!riskExact(value, TRANSFORM_KEYS)
        || !riskIdentifier(value.transform_id)
        || !riskIdentifier(value.version)
        || typeof value.digest !== 'string'
        || !RISK_DIGEST.test(value.digest)) {
        refuse('field_origin_transform_invalid', 'transform is invalid');
    }
    return {
        transform_id: value.transform_id,
        version: value.version,
        digest: value.digest,
    };
}
function normalizeProfile(value) {
    if (!riskExact(value, PROFILE_KEYS)
        || !riskIdentifier(value.profile_id)
        || !riskIdentifier(value.relying_party_id)
        || !riskIdentifier(value.action_type)
        || !Array.isArray(value.fields)
        || value.fields.length < 1
        || value.fields.length > MAX_FIELDS
        || !Array.isArray(value.transforms)
        || value.transforms.length > MAX_TRANSFORMS) {
        refuse('field_origin_profile_invalid', 'field-origin profile is not a closed v0.1 object');
    }
    const transforms = value.transforms.map(normalizeTransform);
    const transformIds = new Set();
    for (const transform of transforms) {
        if (transformIds.has(transform.transform_id)) {
            refuse('field_origin_transform_duplicated', 'transform id is duplicated');
        }
        transformIds.add(transform.transform_id);
    }
    const paths = new Set();
    const fields = value.fields.map((entry) => {
        if (!riskExact(entry, FIELD_RULE_KEYS)
            || !validPointer(entry.path)
            || typeof entry.role !== 'string'
            || !FIELD_ROLES.has(entry.role)
            || typeof entry.required !== 'boolean'
            || typeof entry.snapshot_policy !== 'string'
            || !SNAPSHOT_POLICIES.has(entry.snapshot_policy)) {
            refuse('field_origin_field_rule_invalid', 'field-origin rule is invalid');
        }
        if (paths.has(entry.path))
            refuse('field_origin_path_duplicated', 'field path is duplicated');
        paths.add(entry.path);
        const allowedOrigins = normalizeStringSet(entry.allowed_origins, PROFILE_ORIGIN_CLASSES, 'allowed_origins', PROFILE_ORIGIN_CLASSES.size);
        if (allowedOrigins.length < 1) {
            refuse('field_origin_allowed_origins_invalid', 'allowed_origins must not be empty');
        }
        if (entry.role === 'control' && allowedOrigins.includes('untrusted_bounded')) {
            refuse('field_origin_control_profile_widening', 'control fields cannot allow untrusted_bounded');
        }
        const allowedTransformIds = normalizeStringSet(entry.allowed_transform_ids, null, 'allowed_transform_ids', MAX_TRANSFORMS);
        if (allowedOrigins.includes('derived_via_versioned_transform') !== (allowedTransformIds.length > 0)) {
            refuse('field_origin_transform_policy_invalid', 'derived origin and allowed transforms must be declared together');
        }
        for (const transformId of allowedTransformIds) {
            if (!transformIds.has(transformId)) {
                refuse('field_origin_transform_unresolved', 'field rule names an unknown transform');
            }
        }
        if (entry.snapshot_policy === 'immutable') {
            if (entry.max_snapshot_age_sec !== null) {
                refuse('field_origin_snapshot_policy_invalid', 'immutable fields cannot declare snapshot age');
            }
        }
        else if (!safeInteger(entry.max_snapshot_age_sec, 1, MAX_SNAPSHOT_AGE_SEC)) {
            refuse('field_origin_snapshot_policy_invalid', 'mutable or either fields require bounded snapshot age');
        }
        return {
            path: entry.path,
            role: entry.role,
            required: entry.required,
            allowed_origins: allowedOrigins,
            snapshot_policy: entry.snapshot_policy,
            max_snapshot_age_sec: entry.max_snapshot_age_sec,
            allowed_transform_ids: allowedTransformIds,
        };
    }).sort((left, right) => byteOrder(left.path, right.path));
    return {
        profile_id: value.profile_id,
        relying_party_id: value.relying_party_id,
        action_type: value.action_type,
        fields,
        transforms: transforms.sort((left, right) => byteOrder(left.transform_id, right.transform_id)),
    };
}
function normalizeTrustedKeys(value) {
    if (!riskRecord(value) || Object.keys(value).length < 1) {
        refuse('field_origin_trusted_keys_invalid', 'field-origin trust keys must be a nonempty closed map');
    }
    const normalized = {};
    for (const [keyId, pin] of Object.entries(value).sort(([left], [right]) => byteOrder(left, right))) {
        if (!riskIdentifier(keyId)
            || !riskExact(pin, TRUSTED_KEY_KEYS)
            || !riskIdentifier(pin.issuer_id)
            || typeof pin.public_key !== 'string'
            || !/^[A-Za-z0-9_-]+$/.test(pin.public_key)) {
            refuse('field_origin_trusted_keys_invalid', 'field-origin trust key pin is invalid');
        }
        try {
            const keyBytes = Buffer.from(pin.public_key, 'base64url');
            const key = createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
            if (keyBytes.toString('base64url') !== pin.public_key || key.asymmetricKeyType !== 'ed25519') {
                refuse('field_origin_trusted_keys_invalid', 'field-origin trust key must be canonical Ed25519 SPKI');
            }
        }
        catch (error) {
            if (error instanceof FieldOriginValidationError)
                throw error;
            refuse('field_origin_trusted_keys_invalid', 'field-origin trust key must be canonical Ed25519 SPKI');
        }
        normalized[keyId] = { issuer_id: pin.issuer_id, public_key: pin.public_key };
    }
    return normalized;
}
function normalizeSnapshot(value) {
    if (!riskExact(value, SNAPSHOT_KEYS)
        || (value.kind !== 'immutable' && value.kind !== 'mutable_snapshot')
        || (value.source_version !== null && !riskIdentifier(value.source_version))) {
        refuse('field_origin_snapshot_invalid', 'snapshot caveat is invalid');
    }
    if (value.kind === 'immutable') {
        if (value.observed_at !== null || value.source_version !== null) {
            refuse('field_origin_snapshot_invalid', 'immutable snapshot caveat must not carry mutable-state metadata');
        }
        return { kind: 'immutable', observed_at: null, source_version: null };
    }
    return {
        kind: 'mutable_snapshot',
        observed_at: canonicalInstant(value.observed_at, 'snapshot.observed_at'),
        source_version: value.source_version,
    };
}
function normalizeAnnotation(value) {
    if (!riskExact(value, ANNOTATION_KEYS)
        || !validPointer(value.path)
        || typeof value.origin_class !== 'string'
        || !ORIGIN_CLASSES.has(value.origin_class)) {
        refuse('field_origin_annotation_invalid', 'field annotation is invalid');
    }
    return {
        path: value.path,
        origin_class: value.origin_class,
        snapshot: normalizeSnapshot(value.snapshot),
        transform: value.transform === null ? null : normalizeTransform(value.transform),
    };
}
function normalizeField(value) {
    if (!riskExact(value, FIELD_KEYS)
        || !validPointer(value.path)
        || typeof value.value_digest !== 'string'
        || !RISK_DIGEST.test(value.value_digest)
        || typeof value.origin_class !== 'string'
        || !ORIGIN_CLASSES.has(value.origin_class)) {
        refuse('field_origin_field_invalid', 'field evidence is invalid');
    }
    return {
        path: value.path,
        value_digest: value.value_digest,
        origin_class: value.origin_class,
        snapshot: normalizeSnapshot(value.snapshot),
        transform: value.transform === null ? null : normalizeTransform(value.transform),
    };
}
function normalizeFields(value, fieldNormalizer) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FIELDS) {
        refuse('field_origin_fields_invalid', 'field evidence must be a bounded nonempty array');
    }
    const paths = new Set();
    const fields = value.map(fieldNormalizer);
    for (const field of fields) {
        if (paths.has(field.path))
            refuse('field_origin_path_duplicated', 'field path is duplicated');
        paths.add(field.path);
    }
    return fields.sort((left, right) => byteOrder(left.path, right.path));
}
function normalizeBody(value) {
    if (!riskExact(value, BODY_KEYS)
        || value['@version'] !== FIELD_ORIGIN_EVIDENCE_VERSION
        || !riskIdentifier(value.evidence_id)
        || !riskIdentifier(value.profile_id)
        || typeof value.profile_digest !== 'string'
        || !RISK_DIGEST.test(value.profile_digest)
        || !riskIdentifier(value.relying_party_id)
        || !riskIdentifier(value.action_type)
        || typeof value.action_digest !== 'string'
        || !RISK_DIGEST.test(value.action_digest)
        || value.claim_boundary !== FIELD_ORIGIN_CLAIM_BOUNDARY
        || !riskExact(value.issuer, ISSUER_KEYS)
        || !riskIdentifier(value.issuer.id)
        || !riskIdentifier(value.issuer.key_id)) {
        refuse('field_origin_evidence_invalid', 'field-origin evidence body is invalid');
    }
    const observedAt = canonicalInstant(value.observed_at, 'observed_at');
    if (value.issuer.id !== value.relying_party_id) {
        refuse('field_origin_issuer_mismatch', 'field-origin issuer must be the relying party');
    }
    return {
        '@version': FIELD_ORIGIN_EVIDENCE_VERSION,
        evidence_id: value.evidence_id,
        profile_id: value.profile_id,
        profile_digest: value.profile_digest,
        relying_party_id: value.relying_party_id,
        action_type: value.action_type,
        action_digest: value.action_digest,
        observed_at: observedAt,
        fields: normalizeFields(value.fields, normalizeField),
        claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
        issuer: riskClone(value.issuer),
    };
}
function normalizeContext(value) {
    let context;
    try {
        context = strictJsonClone(value);
    }
    catch {
        return null;
    }
    if (!riskExact(context, CONTEXT_KEYS)
        || !riskRecord(context.trusted_keys)
        || !riskRecord(context.pinned_profile)
        || !riskIdentifier(context.expected_relying_party_id)
        || !riskRecord(context.observed_action))
        return null;
    try {
        canonicalInstant(context.now, 'now');
        return {
            ...context,
            trusted_keys: normalizeTrustedKeys(context.trusted_keys),
            pinned_profile: normalizeProfile(context.pinned_profile),
        };
    }
    catch {
        return null;
    }
}
export function pinFieldOriginProfile(profile) {
    let snapshot;
    try {
        snapshot = strictJsonClone(profile);
    }
    catch {
        refuse('field_origin_profile_invalid', 'field-origin profile must be strict canonical JSON data');
    }
    return riskFreeze(normalizeProfile(snapshot));
}
export function pinFieldOriginTrustedKeys(keys) {
    let snapshot;
    try {
        snapshot = strictJsonClone(keys);
    }
    catch {
        refuse('field_origin_trusted_keys_invalid', 'field-origin trust keys must be strict canonical JSON data');
    }
    return riskFreeze(normalizeTrustedKeys(snapshot));
}
export function fieldOriginProfileDigest(profile) {
    return riskDigest(pinFieldOriginProfile(profile));
}
export function signFieldOriginEvidence(input, signer) {
    let snapshot;
    try {
        snapshot = strictJsonClone(input);
    }
    catch {
        refuse('field_origin_input_invalid', 'field-origin input must be strict canonical JSON data');
    }
    if (!riskExact(snapshot, INPUT_KEYS)
        || !riskIdentifier(snapshot.evidence_id)
        || !riskRecord(snapshot.observed_action)
        || !Array.isArray(snapshot.annotations)) {
        refuse('field_origin_input_invalid', 'field-origin input is not a closed v0.1 object');
    }
    const profile = normalizeProfile(snapshot.profile);
    if (snapshot.observed_action.action_type !== profile.action_type) {
        refuse('field_origin_action_type_mismatch', 'observed action type does not match profile');
    }
    const observedAt = canonicalInstant(snapshot.observed_at, 'observed_at');
    const annotations = normalizeFields(snapshot.annotations, normalizeAnnotation);
    const leafPaths = actionLeafPaths(snapshot.observed_action).sort(byteOrder);
    if (leafPaths.length !== annotations.length
        || leafPaths.some((path, index) => path !== annotations[index].path)) {
        refuse('field_origin_annotation_coverage_invalid', 'every observed action field requires exactly one annotation');
    }
    const fields = annotations.map((annotation) => {
        const resolved = valueAtPointer(snapshot.observed_action, annotation.path);
        if (!resolved.found)
            refuse('field_origin_annotation_coverage_invalid', 'annotation path is absent from observed action');
        return {
            path: annotation.path,
            value_digest: riskDigest(resolved.value),
            origin_class: annotation.origin_class,
            snapshot: riskClone(annotation.snapshot),
            transform: annotation.transform === null ? null : riskClone(annotation.transform),
        };
    });
    if (!riskExact(signer, SIGNER_KEYS)
        || !riskIdentifier(signer.issuer_id)
        || !riskIdentifier(signer.key_id)) {
        refuse('field_origin_signer_invalid', 'field-origin signer must be a closed Ed25519 signer');
    }
    if (signer.issuer_id !== profile.relying_party_id) {
        refuse('field_origin_issuer_mismatch', 'field-origin signer must be the relying party');
    }
    return signRiskBody(FIELD_ORIGIN_EVIDENCE_VERSION, {
        '@version': FIELD_ORIGIN_EVIDENCE_VERSION,
        evidence_id: snapshot.evidence_id,
        profile_id: profile.profile_id,
        profile_digest: riskDigest(profile),
        relying_party_id: profile.relying_party_id,
        action_type: profile.action_type,
        action_digest: riskDigest(snapshot.observed_action),
        observed_at: observedAt,
        fields,
        claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
    }, signer);
}
export function verifyFieldOriginEvidence(artifact, rawContext) {
    const fail = (reason, verified = false, artifactDigest = null) => riskFreeze({
        accepted: false,
        verified,
        reason,
        artifact_digest: artifactDigest,
        profile_digest: null,
        action_digest: null,
        field_count: 0,
        claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
    });
    const context = normalizeContext(rawContext);
    if (!context)
        return fail('field_origin_verification_context_required');
    let snapshot;
    try {
        snapshot = strictJsonClone(artifact);
    }
    catch {
        return fail('field_origin_evidence_invalid');
    }
    const signed = verifyRiskBody(snapshot, FIELD_ORIGIN_EVIDENCE_VERSION, context.trusted_keys);
    if (!signed.valid || !signed.body || !signed.artifact_digest) {
        return fail(`field_origin_${signed.reason ?? 'signature_invalid'}`);
    }
    let body;
    try {
        body = normalizeBody(signed.body);
    }
    catch (error) {
        return fail(error instanceof FieldOriginValidationError ? error.code : 'field_origin_evidence_invalid', true, signed.artifact_digest);
    }
    const profile = normalizeProfile(context.pinned_profile);
    const profileDigest = riskDigest(profile);
    if (body.relying_party_id !== context.expected_relying_party_id
        || profile.relying_party_id !== context.expected_relying_party_id) {
        return fail('field_origin_relying_party_mismatch', true, signed.artifact_digest);
    }
    if (body.profile_id !== profile.profile_id || body.profile_digest !== profileDigest) {
        return fail('field_origin_profile_mismatch', true, signed.artifact_digest);
    }
    if (body.action_type !== profile.action_type
        || context.observed_action.action_type !== profile.action_type) {
        return fail('field_origin_action_type_mismatch', true, signed.artifact_digest);
    }
    const actionDigest = riskDigest(context.observed_action);
    if (body.action_digest !== actionDigest) {
        return fail('field_origin_action_mismatch', true, signed.artifact_digest);
    }
    const now = Date.parse(context.now);
    if (Date.parse(body.observed_at) > now) {
        return fail('field_origin_evidence_from_future', true, signed.artifact_digest);
    }
    const rules = new Map(profile.fields.map((rule) => [rule.path, rule]));
    const transforms = new Map(profile.transforms.map((transform) => [transform.transform_id, transform]));
    const fields = new Map(body.fields.map((field) => [field.path, field]));
    const leafPaths = actionLeafPaths(context.observed_action).sort(byteOrder);
    for (const path of leafPaths) {
        if (!rules.has(path))
            return fail(`field_origin_field_unprofiled:${path}`, true, signed.artifact_digest);
        if (!fields.has(path))
            return fail(`field_origin_unknown:${path}`, true, signed.artifact_digest);
    }
    for (const rule of profile.fields) {
        const resolved = valueAtPointer(context.observed_action, rule.path);
        const field = fields.get(rule.path);
        if (!resolved.found) {
            if (rule.required)
                return fail(`field_origin_field_missing:${rule.path}`, true, signed.artifact_digest);
            if (field)
                return fail(`field_origin_field_unobserved:${rule.path}`, true, signed.artifact_digest);
            continue;
        }
        if (!field)
            return fail(`field_origin_unknown:${rule.path}`, true, signed.artifact_digest);
        if (field.value_digest !== riskDigest(resolved.value)) {
            return fail(`field_origin_value_mismatch:${rule.path}`, true, signed.artifact_digest);
        }
        if (field.origin_class === 'unknown') {
            return fail(`field_origin_unknown:${rule.path}`, true, signed.artifact_digest);
        }
        if (rule.role === 'control' && field.origin_class === 'untrusted_bounded') {
            return fail(`field_origin_control_untrusted:${rule.path}`, true, signed.artifact_digest);
        }
        if (!rule.allowed_origins.includes(field.origin_class)) {
            return fail(`field_origin_origin_not_allowed:${rule.path}`, true, signed.artifact_digest);
        }
        if (field.origin_class === 'derived_via_versioned_transform') {
            if (!field.transform)
                return fail(`field_origin_transform_required:${rule.path}`, true, signed.artifact_digest);
            const pinned = transforms.get(field.transform.transform_id);
            if (!pinned
                || !rule.allowed_transform_ids.includes(field.transform.transform_id)
                || riskDigest(pinned) !== riskDigest(field.transform)) {
                return fail(`field_origin_transform_unpinned:${rule.path}`, true, signed.artifact_digest);
            }
        }
        else if (field.transform !== null) {
            return fail(`field_origin_transform_unexpected:${rule.path}`, true, signed.artifact_digest);
        }
        if (rule.snapshot_policy === 'immutable' && field.snapshot.kind !== 'immutable') {
            return fail(`field_origin_snapshot_policy_mismatch:${rule.path}`, true, signed.artifact_digest);
        }
        if (rule.snapshot_policy === 'mutable_snapshot' && field.snapshot.kind !== 'mutable_snapshot') {
            return fail(`field_origin_snapshot_policy_mismatch:${rule.path}`, true, signed.artifact_digest);
        }
        if (field.snapshot.kind === 'mutable_snapshot') {
            const snapshotAt = Date.parse(field.snapshot.observed_at);
            if (snapshotAt > Date.parse(body.observed_at)) {
                return fail(`field_origin_snapshot_after_evidence:${rule.path}`, true, signed.artifact_digest);
            }
            const ageMs = now - snapshotAt;
            if (ageMs < 0)
                return fail(`field_origin_snapshot_from_future:${rule.path}`, true, signed.artifact_digest);
            if (safeInteger(rule.max_snapshot_age_sec, 1, MAX_SNAPSHOT_AGE_SEC)
                && ageMs > rule.max_snapshot_age_sec * 1000) {
                return fail(`field_origin_snapshot_stale:${rule.path}`, true, signed.artifact_digest);
            }
        }
    }
    if (fields.size !== leafPaths.length) {
        return fail('field_origin_field_set_mismatch', true, signed.artifact_digest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        artifact_digest: signed.artifact_digest,
        profile_digest: profileDigest,
        action_digest: actionDigest,
        field_count: fields.size,
        fields: riskClone(body.fields),
        claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
    });
}
/*
 * EP-ORIGIN-LABELS-v1: a closed origin-label vocabulary with explicit
 * taint-preserving propagation rules, layered on top of (and additive to)
 * the EP-FIELD-ORIGIN-v0.1 evidence artifact above. Nothing in this block
 * changes v0.1 behavior; the v0.1 origin classes remain exactly as shipped
 * and map onto this vocabulary only through the informative
 * ORIGIN_LABELS_V01_PROFILE_MAP below.
 *
 * Propagation rule (normative for this vocabulary):
 *
 * 1. Every asserted label MUST be a member of the closed set ORIGIN_LABELS.
 *    An assertion outside the set is refused unknown_origin_label:<path>.
 * 2. "derived" MUST carry derived_from naming the base label class of every
 *    source that contributed to the value. A derived assertion without
 *    derived_from is refused derivation_unspecified:<path>.
 * 3. The effective trust floor of a derived value is the LEAST-trusted
 *    label in its derivation set, under ORIGIN_LABEL_TRUST_ORDER.
 *    Summarization, reformatting, extraction, or any other transform NEVER
 *    upgrades a label: a value computed from retrieved-untrusted material
 *    keeps a retrieved-untrusted floor no matter how many model or human
 *    steps sit in between.
 * 4. INDETERMINATE never admits: a malformed assertion set, an internally
 *    inconsistent assertion set, or an unmet policy floor is a structured
 *    refusal with a named, path-precise reason, never an allow path and
 *    never a thrown error from evaluateOriginLabelAssertions.
 *
 * Scope limit (keep this verbatim-clear): labels are CLAIMS by the
 * asserting producer, verified as internally consistent and
 * policy-satisfying at admission; the boundary does not and cannot verify
 * the producer told the truth. That accountability belongs to the
 * producer's signature over the assertion set, not to the label system.
 * In particular, a producer that lies consistently (asserts user-stated
 * for a value it retrieved, and never contradicts itself elsewhere in the
 * same assertion set) is not detectable here; a producer that launders a
 * value while its own pipeline also asserts the honest label for the same
 * path, or the same value digest, is refused.
 */
export const ORIGIN_LABELS_VERSION = 'EP-ORIGIN-LABELS-v1';
export const ORIGIN_LABELS_CLAIM_BOUNDARY = 'producer_asserted_origin_labels_checked_for_closed_vocabulary_internal_consistency_and_policy_trust_floor_at_admission_not_source_truth_not_producer_honesty';
/**
 * Most-trusted first. "derived" carries no rank of its own: its effective
 * floor is computed from derived_from under rule 3 above.
 */
export const ORIGIN_LABEL_TRUST_ORDER = Object.freeze([
    'operator-config',
    'user-stated',
    'counterparty-document',
    'model-generated',
    'retrieved-untrusted',
]);
export const ORIGIN_LABELS = Object.freeze([
    ...ORIGIN_LABEL_TRUST_ORDER,
    'derived',
]);
export const ORIGIN_LABEL_DEFINITIONS = Object.freeze({
    'user-stated': 'The exact value was entered or spoken for this action by the accountable human principal, over a channel the producer attributes to that principal.',
    'operator-config': 'The exact value was read from configuration pinned by the operating organization before this action was proposed, not from any per-action input.',
    'counterparty-document': 'The exact value was taken from a document or message authored by an identified external counterparty to this transaction, such as an invoice or contract.',
    'retrieved-untrusted': 'The exact value was obtained from content the producer retrieved from a source it neither controls nor treats as an identified counterparty, such as a web page, search result, inbound message body, or output of an uncontrolled tool.',
    'model-generated': 'The exact value was produced by model inference from the model parameters alone; a value produced from any per-action source material is derived, not model-generated.',
    derived: 'The exact value was computed, summarized, extracted, reformatted, or otherwise produced from one or more source values, and the assertion carries derived_from naming the base label class of every contributing source.',
});
/**
 * Informative only: how the shipped EP-FIELD-ORIGIN-v0.1 origin classes map
 * onto this vocabulary when v0.1 is read as one implementation profile of a
 * generic origin-label input. This map does not change v0.1 verification.
 * v0.1 "unknown" has no target on purpose: it never admits there either.
 */
export const ORIGIN_LABELS_V01_PROFILE_MAP = Object.freeze({
    operator_pinned: 'operator-config',
    approver_supplied: 'user-stated',
    untrusted_bounded: 'retrieved-untrusted',
    derived_via_versioned_transform: 'derived',
});
const ORIGIN_LABEL_SET = new Set(ORIGIN_LABELS);
const ORIGIN_LABEL_RANK = new Map(ORIGIN_LABEL_TRUST_ORDER.map((label, rank) => [label, rank]));
const ORIGIN_ASSERTION_KEYS = ['path', 'label', 'derived_from', 'value_digest'];
const ORIGIN_POLICY_KEYS = ['rules'];
const ORIGIN_POLICY_RULE_KEYS = ['path', 'minimum_label'];
const ORIGIN_INPUT_KEYS = ['assertions', 'policy'];
/**
 * Computes the effective trust floor of one label under the taint-preserving
 * propagation rule. Pure and non-throwing: an invalid combination returns a
 * null floor with a named reason instead of admitting or crashing.
 */
export function originLabelTrustFloor(label, derivedFrom = null) {
    if (typeof label !== 'string' || !ORIGIN_LABEL_SET.has(label)) {
        return { floor: null, reason: 'unknown_origin_label' };
    }
    if (label !== 'derived') {
        if (derivedFrom !== null)
            return { floor: null, reason: 'derivation_unexpected' };
        return { floor: label, reason: null };
    }
    if (!Array.isArray(derivedFrom) || derivedFrom.length < 1) {
        return { floor: null, reason: 'derivation_unspecified' };
    }
    if (derivedFrom.length > ORIGIN_LABEL_TRUST_ORDER.length
        || derivedFrom.some((entry) => typeof entry !== 'string' || !ORIGIN_LABEL_RANK.has(entry))
        || new Set(derivedFrom).size !== derivedFrom.length) {
        return { floor: null, reason: 'derivation_source_invalid' };
    }
    let worst = 0;
    for (const entry of derivedFrom) {
        const rank = ORIGIN_LABEL_RANK.get(entry);
        if (rank > worst)
            worst = rank;
    }
    return { floor: ORIGIN_LABEL_TRUST_ORDER[worst], reason: null };
}
function originFail(reason) {
    return riskFreeze({
        admitted: false,
        reason,
        vocabulary: ORIGIN_LABELS_VERSION,
        floors: null,
        claim_boundary: ORIGIN_LABELS_CLAIM_BOUNDARY,
    });
}
/**
 * Evaluates one producer-asserted origin-label assertion set against a
 * relying-party policy of per-path minimum labels.
 *
 * Input (closed): { assertions, policy } where assertions is a bounded array
 * of closed { path, label, derived_from, value_digest } objects and policy is
 * a closed { rules } object of { path, minimum_label } entries. value_digest
 * is null or a sha256 digest of the exact value bytes; supplying digests opts
 * the producer into cross-path value-consistency checking.
 *
 * Fail-closed: every outcome is a frozen structured result; this function
 * never throws on hostile input, and INDETERMINATE never admits.
 */
export function evaluateOriginLabelAssertions(rawInput) {
    let input;
    try {
        input = strictJsonClone(rawInput);
    }
    catch {
        return originFail('origin_assertions_invalid');
    }
    if (!riskExact(input, ORIGIN_INPUT_KEYS))
        return originFail('origin_assertions_invalid');
    if (!Array.isArray(input.assertions)
        || input.assertions.length < 1
        || input.assertions.length > MAX_FIELDS) {
        return originFail('origin_assertions_invalid');
    }
    if (!riskExact(input.policy, ORIGIN_POLICY_KEYS)
        || !Array.isArray(input.policy.rules)
        || input.policy.rules.length > MAX_FIELDS) {
        return originFail('origin_policy_invalid');
    }
    const byPath = new Map();
    const serializedByPath = new Map();
    for (const entry of input.assertions) {
        if (!riskExact(entry, ORIGIN_ASSERTION_KEYS) || !validPointer(entry.path)) {
            return originFail('origin_assertion_invalid');
        }
        const path = entry.path;
        if (typeof entry.label !== 'string' || !ORIGIN_LABEL_SET.has(entry.label)) {
            return originFail(`unknown_origin_label:${path}`);
        }
        if (entry.value_digest !== null
            && (typeof entry.value_digest !== 'string' || !RISK_DIGEST.test(entry.value_digest))) {
            return originFail(`origin_value_digest_invalid:${path}`);
        }
        const { floor, reason } = originLabelTrustFloor(entry.label, entry.derived_from);
        if (floor === null)
            return originFail(`${reason}:${path}`);
        const normalized = {
            path,
            label: entry.label,
            derived_from: entry.label === 'derived' ? [...entry.derived_from].sort(byteOrder) : null,
            value_digest: entry.value_digest,
            floor,
        };
        const serialized = canonicalizeStrictJson({
            path: normalized.path,
            label: normalized.label,
            derived_from: normalized.derived_from,
            value_digest: normalized.value_digest,
        });
        const previous = serializedByPath.get(path);
        if (previous !== undefined) {
            return previous === serialized
                ? originFail(`duplicate_origin_assertion:${path}`)
                : originFail(`origin_conflict:${path}`);
        }
        serializedByPath.set(path, serialized);
        byPath.set(path, normalized);
    }
    // Cross-path value consistency: the same exact value bytes asserted under
    // labels with different effective trust floors is a label upgrade across a
    // copy. Detection requires byte identity; see the stated residual in
    // conformance/origin-labels/README.md for renamed or reformatted values.
    const byDigest = new Map();
    for (const assertion of [...byPath.values()].sort((a, b) => byteOrder(a.path, b.path))) {
        if (assertion.value_digest === null)
            continue;
        const group = byDigest.get(assertion.value_digest);
        if (group)
            group.push(assertion);
        else
            byDigest.set(assertion.value_digest, [assertion]);
    }
    for (const digest of [...byDigest.keys()].sort(byteOrder)) {
        const group = byDigest.get(digest);
        if (group.length < 2)
            continue;
        const ranks = group.map((a) => ORIGIN_LABEL_RANK.get(a.floor));
        if (Math.min(...ranks) !== Math.max(...ranks)) {
            const upgraded = group.reduce((best, candidate) => (ORIGIN_LABEL_RANK.get(candidate.floor)
                < ORIGIN_LABEL_RANK.get(best.floor)
                ? candidate : best));
            return originFail(`value_origin_conflict:${upgraded.path}`);
        }
    }
    const rulePaths = new Set();
    const rules = [];
    for (const rule of input.policy.rules) {
        if (!riskExact(rule, ORIGIN_POLICY_RULE_KEYS)
            || !validPointer(rule.path)
            || typeof rule.minimum_label !== 'string'
            || !ORIGIN_LABEL_RANK.has(rule.minimum_label)
            || rulePaths.has(rule.path)) {
            return originFail('origin_policy_invalid');
        }
        rulePaths.add(rule.path);
        rules.push({ path: rule.path, minimum_label: rule.minimum_label });
    }
    for (const rule of rules.sort((a, b) => byteOrder(a.path, b.path))) {
        const assertion = byPath.get(rule.path);
        if (!assertion)
            return originFail(`origin_unasserted:${rule.path}`);
        const floorRank = ORIGIN_LABEL_RANK.get(assertion.floor);
        const minimumRank = ORIGIN_LABEL_RANK.get(rule.minimum_label);
        if (floorRank > minimumRank) {
            return originFail(`origin_trust_floor_violation:${rule.path}`);
        }
    }
    const floors = {};
    for (const path of [...byPath.keys()].sort(byteOrder)) {
        floors[path] = byPath.get(path).floor;
    }
    return riskFreeze({
        admitted: true,
        reason: null,
        vocabulary: ORIGIN_LABELS_VERSION,
        floors,
        claim_boundary: ORIGIN_LABELS_CLAIM_BOUNDARY,
    });
}
//# sourceMappingURL=field-origin-evidence.js.map