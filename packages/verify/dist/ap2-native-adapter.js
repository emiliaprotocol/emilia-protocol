// SPDX-License-Identifier: Apache-2.0
/**
 * Experimental AP2 Agent Authorization adapter for AEB.
 *
 * The AP2 mandate remains the native artifact. This adapter does not mint an
 * EMILIA receipt or claim that EMILIA originated the authorization. A
 * relying-party-pinned AP2 implementation verifies the native artifact and
 * returns its native replay identity plus an exact normalized action. AEB
 * then records the verification result and joins it to the executor's CAID.
 */
import { digestAeb, } from './aeb-adapter-contract.js';
// @ts-expect-error -- governed JavaScript CAID implementation, runtime checked.
import { computeCaid } from '../vendor/caid.mjs';
export const AP2_NATIVE_AEB_ADAPTER_ID = 'native:ap2-agent-authorization';
export const AP2_NATIVE_AEB_ADAPTER_VERSION = 'experimental-1';
export const AP2_NATIVE_AEB_CONFIG_VERSION = 'EP-AP2-NATIVE-AEB-CONFIG-v1';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CAID_RE = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/;
const CONFIG_KEYS = new Set([
    '@version', 'source_revision', 'evidence_role', 'subject',
    'max_status_age_seconds', 'verifier',
]);
const SUBJECT_KEYS = new Set(['id', 'kind']);
const DESCRIPTOR_KEYS = new Set(['id', 'version', 'implementation_digest']);
const RESULT_KEYS = new Set([
    'verified', 'accepted', 'native_artifact_digest', 'replay_unit',
    'evidence_role', 'subject', 'normalized_action', 'action_digest',
    'reasons',
]);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed',
    'unavailable',
]);
function isObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, keys, optional = new Set()) {
    const required = [...keys].filter((key) => !optional.has(key));
    return Object.keys(value).every((key) => keys.has(key))
        && required.every((key) => Object.hasOwn(value, key));
}
function nonEmpty(value) {
    return typeof value === 'string' && value.length > 0
        && value.length <= 512 && !/[\u0000-\u001f\u007f]/.test(value);
}
function identifier(value) {
    return nonEmpty(value) && IDENTIFIER_RE.test(value);
}
function validSubject(value) {
    return isObject(value) && exactKeys(value, SUBJECT_KEYS)
        && identifier(value.id)
        && ['human', 'workload', 'organization', 'system'].includes(String(value.kind));
}
function validDescriptor(value) {
    return isObject(value) && exactKeys(value, DESCRIPTOR_KEYS)
        && identifier(value.id) && nonEmpty(value.version)
        && typeof value.implementation_digest === 'string'
        && DIGEST_RE.test(value.implementation_digest);
}
function parseConfig(value) {
    if (!isObject(value) || !exactKeys(value, CONFIG_KEYS)
        || value['@version'] !== AP2_NATIVE_AEB_CONFIG_VERSION
        || !nonEmpty(value.source_revision) || !identifier(value.evidence_role)
        || !validSubject(value.subject)
        || !Number.isSafeInteger(value.max_status_age_seconds)
        || Number(value.max_status_age_seconds) < 0
        || !validDescriptor(value.verifier))
        return null;
    return {
        source_revision: value.source_revision,
        evidence_role: value.evidence_role,
        subject: { id: value.subject.id, kind: value.subject.kind },
        max_status_age_seconds: Number(value.max_status_age_seconds),
        verifier: { ...value.verifier },
    };
}
function safeDigest(value) {
    try {
        return digestAeb(value);
    }
    catch {
        return digestAeb({ malformed_native_ap2_artifact: true });
    }
}
function statusDigest(value) {
    if (!isObject(value))
        return safeDigest({ malformed_status: true });
    return safeDigest({
        checked_at: value.checked_at,
        expires_at: value.expires_at,
        revocation_checked: value.revocation_checked,
        revoked: value.revoked,
        consumed: value.consumed,
        unavailable: value.unavailable === true,
    });
}
function statusDisposition(value, now, maxAge) {
    if (!isObject(value) || !exactKeys(value, STATUS_KEYS, new Set(['unavailable']))) {
        return { acceptance: 'INDETERMINATE', reasons: ['status_malformed'] };
    }
    const reasons = [];
    if (value.revoked === true)
        reasons.push('evidence_revoked');
    if (value.consumed === true)
        reasons.push('evidence_consumed');
    if (value.unavailable === true)
        reasons.push('status_unavailable');
    if (value.revocation_checked !== true)
        reasons.push('revocation_not_checked');
    if (typeof value.revoked !== 'boolean' || typeof value.consumed !== 'boolean'
        || typeof value.revocation_checked !== 'boolean'
        || (value.unavailable !== undefined && typeof value.unavailable !== 'boolean')) {
        reasons.push('status_malformed');
    }
    const nowMs = Date.parse(now);
    const checkedMs = Date.parse(String(value.checked_at));
    const expiresMs = Date.parse(String(value.expires_at));
    if (![nowMs, checkedMs, expiresMs].every(Number.isFinite)) {
        reasons.push('status_time_indeterminate');
    }
    else {
        if (checkedMs > nowMs)
            reasons.push('status_checked_in_future');
        if (checkedMs >= expiresMs || nowMs >= expiresMs)
            reasons.push('status_expired');
        if ((nowMs - checkedMs) / 1000 > maxAge)
            reasons.push('status_too_old');
    }
    const unique = [...new Set(reasons)].sort();
    if (value.revoked === true || value.consumed === true) {
        return { acceptance: 'REJECTED', reasons: unique };
    }
    return unique.length === 0
        ? { acceptance: 'ACCEPTED', reasons: [] }
        : { acceptance: 'INDETERMINATE', reasons: unique };
}
function fallback(input, reason) {
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: safeDigest(input?.artifact),
        status_digest: statusDigest(input?.status),
        evidence_role: 'ap2-native-authorization',
        subject: { id: 'ap2:unverified', kind: 'system' },
        replay_unit: safeDigest({ protocol: 'AP2', artifact: input?.artifact }),
        reasons: [reason],
    };
}
function verifierMatches(config, verifier) {
    return config.verifier.id === verifier.id
        && config.verifier.version === verifier.version
        && config.verifier.implementation_digest === verifier.implementation_digest;
}
function inspect(verifier, input) {
    const config = parseConfig(input?.adapter_config);
    if (!config || !verifierMatches(config, verifier))
        return null;
    let result;
    try {
        result = verifier.verify({
            artifact: input.artifact,
            artifact_ref: input.artifact_ref,
            trust_roots: input.trust_roots,
            expected_action: input.expected_action,
            now: input.now,
        });
    }
    catch {
        return null;
    }
    if (!isObject(result) || !exactKeys(result, RESULT_KEYS)
        || typeof result.verified !== 'boolean' || typeof result.accepted !== 'boolean'
        || typeof result.native_artifact_digest !== 'string' || !DIGEST_RE.test(result.native_artifact_digest)
        || typeof result.replay_unit !== 'string' || !DIGEST_RE.test(result.replay_unit)
        || !identifier(result.evidence_role) || !validSubject(result.subject)
        || typeof result.action_digest !== 'string' || !DIGEST_RE.test(result.action_digest)
        || !Array.isArray(result.reasons) || !result.reasons.every(nonEmpty))
        return null;
    return { config, result: result };
}
export function createAp2NativeAebAdapter(verifier) {
    if (!validDescriptor({
        id: verifier?.id,
        version: verifier?.version,
        implementation_digest: verifier?.implementation_digest,
    }) || typeof verifier?.verify !== 'function') {
        throw new TypeError('a pinned AP2 native verifier is required');
    }
    return Object.freeze({
        id: AP2_NATIVE_AEB_ADAPTER_ID,
        version: AP2_NATIVE_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            const checked = inspect(verifier, input);
            if (!checked)
                return fallback(input, 'ap2:pinned_verifier_mismatch');
            const { config, result } = checked;
            const evidenceDigest = safeDigest(input.artifact);
            if (result.native_artifact_digest !== evidenceDigest
                || result.evidence_role !== config.evidence_role
                || result.subject.id !== config.subject.id
                || result.subject.kind !== config.subject.kind) {
                return fallback(input, 'ap2:native_result_binding_mismatch');
            }
            if (result.verified !== true) {
                return {
                    ...fallback(input, 'ap2:native_verification_failed'),
                    acceptance: 'REJECTED',
                    evidence_role: config.evidence_role,
                    subject: config.subject,
                    replay_unit: result.replay_unit,
                    reasons: [...new Set(['ap2:native_verification_failed', ...result.reasons])].sort(),
                };
            }
            if (result.accepted !== true) {
                return {
                    native_verification: 'VERIFIED',
                    acceptance: 'REJECTED',
                    evidence_digest: evidenceDigest,
                    status_digest: statusDigest(input.status),
                    evidence_role: config.evidence_role,
                    subject: config.subject,
                    replay_unit: result.replay_unit,
                    reasons: [...new Set(['ap2:native_authorization_refused', ...result.reasons])].sort(),
                };
            }
            const status = statusDisposition(input.status, input.now, config.max_status_age_seconds);
            const normalizedActionDigest = safeDigest(result.normalized_action);
            if (result.action_digest !== normalizedActionDigest) {
                return fallback(input, 'ap2:native_normalized_action_digest_mismatch');
            }
            const native = {
                native_verification: 'VERIFIED',
                acceptance: status.acceptance,
                evidence_digest: evidenceDigest,
                status_digest: statusDigest(input.status),
                evidence_role: config.evidence_role,
                subject: config.subject,
                replay_unit: result.replay_unit,
                reasons: [...new Set([...result.reasons, ...status.reasons])].sort(),
                normalized_action: result.normalized_action,
                normalized_action_digest: normalizedActionDigest,
            };
            return native;
        },
        mapAction(input) {
            const config = parseConfig(input.adapter_config);
            const native = input.native;
            if (!config || !verifierMatches(config, verifier)
                || native.native_verification !== 'VERIFIED'
                || native.acceptance !== 'ACCEPTED'
                || native.evidence_role !== config.evidence_role
                || native.subject?.id !== config.subject.id
                || native.subject?.kind !== config.subject.kind
                || !isObject(input.profile)
                || !isObject(input.profile.definition)
                || input.profile.definition.suite !== 'jcs-sha256'
                || !Array.isArray(input.profile.definition.definitions)
                || !isObject(input.profile.semantic_equivalence)
                || input.profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
                || input.profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
                || !Array.isArray(input.profile.semantic_equivalence.omitted_material_fields)
                || input.profile.semantic_equivalence.omitted_material_fields.length !== 0) {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ap2:pinned_mapping_profile_invalid'] };
            }
            const expectedDigest = safeDigest(input.expected_action);
            if (native.evidence_digest !== safeDigest(input.artifact)
                || native.normalized_action_digest !== safeDigest(native.normalized_action)
                || native.normalized_action_digest !== expectedDigest) {
                return {
                    mapping: 'MISMATCH',
                    caid: null,
                    action_digest: native.normalized_action_digest ?? null,
                    reasons: ['ap2:exact_action_mismatch'],
                };
            }
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
            if (!isObject(computed) || typeof computed.caid !== 'string'
                || !CAID_RE.test(computed.caid) || computed.digest !== expectedDigest) {
                return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['ap2:caid_mapping_failed'] };
            }
            return {
                mapping: 'MATCH',
                caid: computed.caid,
                action_digest: expectedDigest,
                reasons: [],
            };
        },
    });
}
//# sourceMappingURL=ap2-native-adapter.js.map