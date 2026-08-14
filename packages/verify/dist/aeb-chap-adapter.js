// SPDX-License-Identifier: Apache-2.0
/**
 * Revision-pinned CHAP adapter for AEB-ADAPTER-v1.
 *
 * Source lock: BrightbeamAI/chap commit
 * 9e7af2b811d3368b4afba7c6d318764959c2fd0d.
 *
 * CHAP records human review decisions. This adapter verifies a CHAP
 * security-signed decision under relying-party-pinned participant keys and
 * maps only decisions that cryptographically bind the exact artifact Gate is
 * about to execute. A current decide.approve carrying only task_id is valid
 * CHAP evidence but is not exact-action evidence, so it remains INDETERMINATE.
 */
import crypto from 'node:crypto';
// The governed CAID implementation is JavaScript and has no declaration file.
// @ts-expect-error -- runtime shape is checked before use.
import { computeCaid } from '../vendor/caid.mjs';
import { digestAeb, } from './aeb-adapter-contract.js';
import { canonicalizeStrictJson } from './strict-json.js';
export const CHAP_SOURCE_REPOSITORY = 'https://github.com/BrightbeamAI/chap';
export const CHAP_SOURCE_COMMIT = '9e7af2b811d3368b4afba7c6d318764959c2fd0d';
export const CHAP_REVIEW_PROFILE_SHA256 = 'sha256:2a971b084ea192daafcdac275b5aa1b9e6ceb60d0cb3879db0df06ee7b430539';
export const CHAP_SECURITY_SIGNED_PROFILE_SHA256 = 'sha256:83f455763b08d0d9993fecf3c5ddf94d2cd6266d79b42a574f52ce94a313aee2';
export const CHAP_PATCH_IMPLEMENTATION_SHA256 = 'sha256:78ff3b3d898f58e5d043582705e46c06833336f411ef0caf08d11221148da7ff';
export const CHAP_AEB_ADAPTER_ID = 'native:chap';
export const CHAP_AEB_ADAPTER_VERSION = '1';
export const CHAP_AEB_CONFIG_VERSION = 'AEB-CHAP-CONFIG-v1';
export const CHAP_TRUST_ROOT_VERSION = 'AEB-CHAP-ED25519-ROOT-v1';
export const CHAP_CAID_MAPPING_VERSION = 'AEB-CHAP-CAID-MAPPING-v1';
export const CHAP_CAID_MAPPER_ID = 'mapper:chap-human-decision-exact-action-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/;
const WIRE_PROFILE = 'chap-jsonrpc-security-signed-1.0';
const DANGEROUS_POINTER_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_PATCH_OPERATIONS = 1000;
const MAX_DOCUMENT_NODES = 100_000;
const CONFIG_KEYS = new Set([
    '@version', 'wire_profile', 'evidence_role', 'subject', 'action_type',
    'approve_binding_field', 'max_decision_age_seconds', 'max_status_age_seconds',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const ROOT_KEYS = new Set([
    '@version', 'use', 'participant_id', 'kid', 'public_jwk', 'valid_from',
    'valid_until', 'revoked_at', 'identity_binding',
]);
const JWK_KEYS = new Set(['kty', 'crv', 'x']);
const IDENTITY_BINDING_KEYS = new Set(['method', 'evidence_digest']);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
]);
const ENVELOPE_KEYS = new Set(['jsonrpc', 'id', 'method', 'params', 'sig']);
const COMMON_PARAM_KEYS = new Set(['workspace', 'from', 'to', 'ts', 'task_id']);
const APPROVE_PARAM_KEYS = new Set([
    ...COMMON_PARAM_KEYS, 'comment', 'tags', 'approved_artefact_digest',
]);
const OVERRIDE_PARAM_KEYS = new Set([
    ...COMMON_PARAM_KEYS, 'based_on_artefact', 'diff', 'rationale', 'tags',
    'policy_refs', 'logical_id', 'instance_id', 'intent_preserved',
]);
const MAPPING_KEYS = new Set([
    '@version', 'native_protocol', 'source_commit', 'projection', 'action_type',
    'suite', 'definitions',
]);
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, allowed, required) {
    return Object.keys(value).every((key) => allowed.has(key))
        && required.every((key) => Object.hasOwn(value, key));
}
function nonEmptyString(value) {
    return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}
function positiveInteger(value) {
    return Number.isSafeInteger(value) && Number(value) > 0;
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
function canonicalBase64(value, length) {
    if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        return false;
    }
    try {
        const bytes = Buffer.from(value, 'base64');
        return bytes.length > 0 && bytes.toString('base64') === value
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
        return digestAeb(null);
    }
}
function statusDigest(status) {
    return safeDigest(status);
}
function validStatus(value) {
    return isRecord(value)
        && exactKeys(value, STATUS_KEYS, ['checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed'])
        && Number.isFinite(parseInstant(value.checked_at))
        && Number.isFinite(parseInstant(value.expires_at))
        && typeof value.revocation_checked === 'boolean'
        && typeof value.revoked === 'boolean'
        && typeof value.consumed === 'boolean'
        && (value.unavailable === undefined || typeof value.unavailable === 'boolean');
}
function statusDisposition(status, now, maxStatusAgeSeconds) {
    if (!validStatus(status))
        return { acceptance: 'INDETERMINATE', reasons: ['status_input_invalid'] };
    const nowMs = parseInstant(now);
    const checkedMs = parseInstant(status.checked_at);
    const expiresMs = parseInstant(status.expires_at);
    if (!Number.isFinite(nowMs) || checkedMs > nowMs
        || nowMs - checkedMs > maxStatusAgeSeconds * 1000 || expiresMs < nowMs) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_stale_or_time_invalid'] };
    }
    if (status.unavailable || !status.revocation_checked) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_unavailable_or_unchecked'] };
    }
    if (status.revoked)
        return { acceptance: 'REJECTED', reasons: ['evidence_revoked'] };
    if (status.consumed)
        return { acceptance: 'REJECTED', reasons: ['evidence_consumed'] };
    return { acceptance: 'ACCEPTED', reasons: [] };
}
function parseConfig(value) {
    if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS, [...CONFIG_KEYS])
        || value['@version'] !== CHAP_AEB_CONFIG_VERSION
        || value.wire_profile !== WIRE_PROFILE
        || !nonEmptyString(value.evidence_role) || !IDENTIFIER_RE.test(value.evidence_role)
        || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS, [...SUBJECT_KEYS])
        || value.subject.kind !== 'human'
        || !nonEmptyString(value.subject.id) || !IDENTIFIER_RE.test(value.subject.id)
        || !nonEmptyString(value.subject.native_id) || !IDENTIFIER_RE.test(value.subject.native_id)
        || !nonEmptyString(value.action_type) || !ACTION_TYPE_RE.test(value.action_type)
        || value.approve_binding_field !== 'approved_artefact_digest'
        || !positiveInteger(value.max_decision_age_seconds)
        || !positiveInteger(value.max_status_age_seconds))
        return null;
    return structuredClone(value);
}
function parseRoot(value) {
    if (!isRecord(value)
        || !exactKeys(value, ROOT_KEYS, [
            '@version', 'use', 'participant_id', 'kid', 'public_jwk', 'valid_from',
            'valid_until', 'identity_binding',
        ])
        || value['@version'] !== CHAP_TRUST_ROOT_VERSION
        || value.use !== 'chap-participant-signing-key'
        || !nonEmptyString(value.participant_id) || !IDENTIFIER_RE.test(value.participant_id)
        || !nonEmptyString(value.kid) || !IDENTIFIER_RE.test(value.kid)
        || !isRecord(value.public_jwk) || !exactKeys(value.public_jwk, JWK_KEYS, [...JWK_KEYS])
        || value.public_jwk.kty !== 'OKP' || value.public_jwk.crv !== 'Ed25519'
        || !canonicalBase64url(value.public_jwk.x, 32)
        || !Number.isFinite(parseInstant(value.valid_from))
        || !Number.isFinite(parseInstant(value.valid_until))
        || parseInstant(value.valid_until) <= parseInstant(value.valid_from)
        || (value.revoked_at !== undefined && !Number.isFinite(parseInstant(value.revoked_at)))
        || !isRecord(value.identity_binding)
        || !exactKeys(value.identity_binding, IDENTITY_BINDING_KEYS, [...IDENTITY_BINDING_KEYS])
        || !nonEmptyString(value.identity_binding.method)
        || typeof value.identity_binding.evidence_digest !== 'string'
        || !DIGEST_RE.test(value.identity_binding.evidence_digest))
        return null;
    try {
        const key = crypto.createPublicKey({
            key: {
                kty: 'OKP',
                crv: 'Ed25519',
                x: value.public_jwk.x,
            },
            format: 'jwk',
        });
        return { ...structuredClone(value), key };
    }
    catch {
        return null;
    }
}
function parsePins(value) {
    const config = parseConfig(value?.config);
    const roots = Array.isArray(value?.trust_roots) ? value.trust_roots.map(parseRoot) : [];
    if (!config || roots.length === 0 || roots.some((root) => root === null)) {
        throw new TypeError('invalid CHAP adapter constructor pins');
    }
    const parsedRoots = roots;
    const uniqueRoots = new Set(parsedRoots.map((root) => `${root.participant_id}\0${root.kid}`));
    if (uniqueRoots.size !== parsedRoots.length
        || !parsedRoots.some((root) => root.participant_id === config.subject.native_id)) {
        throw new TypeError('CHAP trust roots are ambiguous or do not contain the configured subject');
    }
    const cleanRoots = parsedRoots.map(({ key: _key, ...root }) => root);
    return Object.freeze({
        config: Object.freeze(config),
        roots: Object.freeze(parsedRoots),
        configDigest: safeDigest(config),
        rootsDigest: safeDigest(cleanRoots),
    });
}
function parseDecision(value) {
    if (!isRecord(value) || !exactKeys(value, ENVELOPE_KEYS, [...ENVELOPE_KEYS])
        || value.jsonrpc !== '2.0' || !nonEmptyString(value.id)
        || !['decide.approve', 'decide.override'].includes(String(value.method))
        || !isRecord(value.params) || !nonEmptyString(value.sig))
        return null;
    const method = value.method;
    const allowed = method === 'decide.approve' ? APPROVE_PARAM_KEYS : OVERRIDE_PARAM_KEYS;
    const required = method === 'decide.approve'
        ? [...COMMON_PARAM_KEYS]
        : [...COMMON_PARAM_KEYS, 'based_on_artefact', 'diff', 'rationale'];
    if (!exactKeys(value.params, allowed, required)
        || !nonEmptyString(value.params.workspace)
        || !nonEmptyString(value.params.from)
        || !nonEmptyString(value.params.to)
        || !nonEmptyString(value.params.task_id)
        || !Number.isFinite(parseInstant(value.params.ts)))
        return null;
    const signatureParts = value.sig.split(':', 3);
    if (signatureParts.length !== 3 || signatureParts[0] !== 'ed25519'
        || !nonEmptyString(signatureParts[1]) || !IDENTIFIER_RE.test(signatureParts[1])
        || !canonicalBase64(signatureParts[2], 64))
        return null;
    return {
        envelope: value,
        params: value.params,
        method,
        kid: signatureParts[1],
        signature: Buffer.from(signatureParts[2], 'base64'),
    };
}
function verifyDecisionSignature(decision, root) {
    const unsigned = structuredClone(decision.envelope);
    delete unsigned.sig;
    try {
        return crypto.verify(null, Buffer.from(canonicalizeStrictJson(unsigned), 'utf8'), root.key, decision.signature);
    }
    catch {
        return false;
    }
}
function splitPointer(path) {
    if (typeof path !== 'string')
        throw new TypeError('JSON Pointer must be a string');
    if (path === '')
        return [];
    if (!path.startsWith('/'))
        throw new TypeError('JSON Pointer must start with slash');
    const segments = path.slice(1).split('/').map((segment) => {
        if (/~(?:[^01]|$)/.test(segment))
            throw new TypeError('invalid JSON Pointer escape');
        return segment.replace(/~1/g, '/').replace(/~0/g, '~');
    });
    if (segments.some((segment) => DANGEROUS_POINTER_SEGMENTS.has(segment))) {
        throw new TypeError('unsafe JSON Pointer segment');
    }
    return segments;
}
function arrayIndex(segment, allowAppend) {
    if (allowAppend && segment === '-')
        return '-';
    if (!/^(?:0|[1-9][0-9]*)$/.test(segment))
        throw new TypeError('invalid array index');
    const index = Number(segment);
    if (!Number.isSafeInteger(index))
        throw new TypeError('array index is not safe');
    return index;
}
function parentAt(document, segments) {
    if (segments.length === 0)
        throw new TypeError('root has no parent');
    let parent = document;
    for (const segment of segments.slice(0, -1)) {
        if (Array.isArray(parent)) {
            const index = arrayIndex(segment, false);
            if (index === '-' || index < 0 || index >= parent.length)
                throw new TypeError('array path not found');
            parent = parent[index];
        }
        else if (isRecord(parent)) {
            if (!Object.hasOwn(parent, segment))
                throw new TypeError('object path not found');
            parent = parent[segment];
        }
        else {
            throw new TypeError('cannot traverse scalar');
        }
    }
    return {
        parent,
        key: Array.isArray(parent)
            ? arrayIndex(segments.at(-1), true)
            : segments.at(-1),
    };
}
function valueAt(document, path) {
    const segments = splitPointer(path);
    if (segments.length === 0)
        return document;
    const { parent, key } = parentAt(document, segments);
    if (Array.isArray(parent)) {
        if (key === '-' || typeof key !== 'number' || key < 0 || key >= parent.length) {
            throw new TypeError('array path not found');
        }
        return parent[key];
    }
    if (!isRecord(parent) || typeof key !== 'string' || !Object.hasOwn(parent, key)) {
        throw new TypeError('object path not found');
    }
    return parent[key];
}
function nodeCount(value) {
    if (Array.isArray(value)) {
        let total = 1;
        for (const item of value)
            total += nodeCount(item);
        return total;
    }
    if (isRecord(value)) {
        let total = 1;
        for (const item of Object.values(value))
            total += nodeCount(item);
        return total;
    }
    return 1;
}
function applyOnePatch(document, operation) {
    if (!isRecord(operation) || !nonEmptyString(operation.op) || typeof operation.path !== 'string') {
        throw new TypeError('invalid JSON Patch operation');
    }
    const segments = splitPointer(operation.path);
    if (operation.op === 'add') {
        if (!Object.hasOwn(operation, 'value'))
            throw new TypeError('add requires value');
        if (segments.length === 0)
            return structuredClone(operation.value);
        const { parent, key } = parentAt(document, segments);
        if (Array.isArray(parent)) {
            if (key === '-')
                parent.push(structuredClone(operation.value));
            else if (typeof key === 'number' && key >= 0 && key <= parent.length) {
                parent.splice(key, 0, structuredClone(operation.value));
            }
            else
                throw new TypeError('array add index out of range');
        }
        else if (isRecord(parent) && typeof key === 'string') {
            parent[key] = structuredClone(operation.value);
        }
        else
            throw new TypeError('cannot add into scalar');
        return document;
    }
    if (operation.op === 'replace') {
        if (!Object.hasOwn(operation, 'value'))
            throw new TypeError('replace requires value');
        if (segments.length === 0)
            return structuredClone(operation.value);
        const { parent, key } = parentAt(document, segments);
        if (Array.isArray(parent)) {
            if (key === '-' || typeof key !== 'number' || key < 0 || key >= parent.length) {
                throw new TypeError('array replace path not found');
            }
            parent[key] = structuredClone(operation.value);
        }
        else if (isRecord(parent) && typeof key === 'string' && Object.hasOwn(parent, key)) {
            parent[key] = structuredClone(operation.value);
        }
        else
            throw new TypeError('object replace path not found');
        return document;
    }
    if (operation.op === 'remove') {
        if (segments.length === 0)
            throw new TypeError('cannot remove root');
        const { parent, key } = parentAt(document, segments);
        if (Array.isArray(parent)) {
            if (key === '-' || typeof key !== 'number' || key < 0 || key >= parent.length) {
                throw new TypeError('array remove path not found');
            }
            parent.splice(key, 1);
        }
        else if (isRecord(parent) && typeof key === 'string' && Object.hasOwn(parent, key)) {
            delete parent[key];
        }
        else
            throw new TypeError('object remove path not found');
        return document;
    }
    if (operation.op === 'copy' || operation.op === 'move') {
        if (typeof operation.from !== 'string')
            throw new TypeError(`${operation.op} requires from`);
        if (operation.op === 'move' && operation.path.startsWith(`${operation.from}/`)) {
            throw new TypeError('cannot move a value into its child');
        }
        const copied = structuredClone(valueAt(document, operation.from));
        let working = document;
        if (operation.op === 'move') {
            working = applyOnePatch(working, { op: 'remove', path: operation.from });
        }
        return applyOnePatch(working, { op: 'add', path: operation.path, value: copied });
    }
    if (operation.op === 'test') {
        if (!Object.hasOwn(operation, 'value'))
            throw new TypeError('test requires value');
        if (safeDigest(valueAt(document, operation.path)) !== safeDigest(operation.value)) {
            throw new TypeError('test operation failed');
        }
        return document;
    }
    throw new TypeError('unsupported JSON Patch operation');
}
export function applyChapJsonPatch(document, patch) {
    if (!Array.isArray(patch) || patch.length > MAX_PATCH_OPERATIONS) {
        throw new TypeError('invalid or oversized JSON Patch');
    }
    let result = structuredClone(document);
    for (const operation of patch) {
        result = applyOnePatch(result, operation);
        if (nodeCount(result) > MAX_DOCUMENT_NODES)
            throw new TypeError('patched document exceeds node limit');
    }
    canonicalizeStrictJson(result);
    return result;
}
function exactExpectedAction(value, config) {
    return isRecord(value)
        && exactKeys(value, new Set(['action_type', 'native_action']), ['action_type', 'native_action'])
        && value.action_type === config.action_type
        && isRecord(value.native_action);
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
    const cleanRoots = pins.roots.map(({ key: _key, ...root }) => root);
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== safeDigest(cleanRoots)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:constructor_pin_mismatch'];
        return result;
    }
    if (!exactExpectedAction(input.expected_action, pins.config)) {
        result.reasons = ['chap:missing_or_ambiguous_exact_action'];
        return result;
    }
    const decision = parseDecision(input.artifact);
    if (!decision) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:malformed_or_unsupported_decision'];
        return result;
    }
    const sender = decision.params.from;
    const decisionTime = parseInstant(decision.params.ts);
    const root = pins.roots.find((candidate) => candidate.participant_id === sender && candidate.kid === decision.kid);
    if (!root || sender !== pins.config.subject.native_id) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:enrolled_key_or_subject_mismatch'];
        return result;
    }
    if (decisionTime < parseInstant(root.valid_from) || decisionTime > parseInstant(root.valid_until)
        || (root.revoked_at !== undefined && decisionTime >= parseInstant(root.revoked_at))) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:key_not_valid_at_decision'];
        return result;
    }
    if (!verifyDecisionSignature(decision, root)) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:signature_invalid'];
        return result;
    }
    result.native_verification = 'VERIFIED';
    result.replay_unit = safeDigest({
        protocol: 'CHAP',
        source_commit: CHAP_SOURCE_COMMIT,
        workspace: decision.params.workspace,
        decision_id: decision.envelope.id,
        participant_id: sender,
        kid: decision.kid,
    });
    const nowMs = parseInstant(input.now);
    if (!Number.isFinite(nowMs) || decisionTime > nowMs
        || nowMs - decisionTime > pins.config.max_decision_age_seconds * 1000) {
        result.acceptance = 'REJECTED';
        result.reasons = ['chap:decision_time_invalid'];
        return result;
    }
    const expectedNative = input.expected_action.native_action;
    if (decision.method === 'decide.approve') {
        const boundDigest = decision.params[pins.config.approve_binding_field];
        if (boundDigest === undefined) {
            result.acceptance = 'INDETERMINATE';
            result.reasons = ['chap:approve_artifact_binding_missing'];
            return result;
        }
        if (typeof boundDigest !== 'string' || !DIGEST_RE.test(boundDigest)
            || boundDigest !== safeDigest(expectedNative)) {
            result.acceptance = 'REJECTED';
            result.reasons = ['chap:approved_artifact_mismatch'];
            return result;
        }
    }
    else {
        let approvedArtifact;
        try {
            approvedArtifact = applyChapJsonPatch(decision.params.based_on_artefact, decision.params.diff);
        }
        catch {
            result.acceptance = 'REJECTED';
            result.reasons = ['chap:patch_invalid'];
            return result;
        }
        if (safeDigest(approvedArtifact) !== safeDigest(expectedNative)) {
            result.acceptance = 'REJECTED';
            result.reasons = ['chap:approved_artifact_mismatch'];
            return result;
        }
    }
    const status = statusDisposition(input.status, input.now, pins.config.max_status_age_seconds);
    result.acceptance = status.acceptance;
    result.reasons = status.reasons;
    return result;
}
export function createChapActionDefinition(actionType) {
    if (!ACTION_TYPE_RE.test(actionType))
        throw new TypeError('invalid CHAP action type');
    return {
        '@version': CHAP_CAID_MAPPING_VERSION,
        native_protocol: 'CHAP-0.2',
        source_commit: CHAP_SOURCE_COMMIT,
        projection: 'chap-human-decision-exact-action-v1',
        action_type: actionType,
        suite: 'jcs-sha256',
        definitions: [{
                action_type: actionType,
                required_fields: [
                    { name: 'action_type', type: 'string' },
                    { name: 'native_action', type: 'object' },
                ],
                optional_fields: [],
            }],
    };
}
function validMappingProfile(profile, config) {
    if (!isRecord(profile)
        || profile.version !== CHAP_CAID_MAPPING_VERSION
        || profile.mapper_id !== CHAP_CAID_MAPPER_ID
        || !isRecord(profile.resolver)
        || profile.resolver.id !== CHAP_CAID_MAPPER_ID
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
        || !exactKeys(profile.definition, MAPPING_KEYS, [...MAPPING_KEYS]))
        return false;
    return safeDigest(profile.definition) === safeDigest(createChapActionDefinition(config.action_type));
}
function mapAction(input, pins) {
    if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
    }
    const cleanRoots = pins.roots.map(({ key: _key, ...root }) => root);
    if (safeDigest(input.adapter_config) !== pins.configDigest
        || safeDigest(input.trust_roots) !== safeDigest(cleanRoots)) {
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
export function createChapAebAdapter(constructorPins) {
    const pins = parsePins(constructorPins);
    return Object.freeze({
        id: CHAP_AEB_ADAPTER_ID,
        version: CHAP_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyNative(input, pins);
            }
            catch {
                const result = fallbackNative(input, pins);
                result.reasons = ['chap:unexpected_adapter_error'];
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
                    reasons: ['chap:unexpected_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=aeb-chap-adapter.js.map