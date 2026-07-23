// SPDX-License-Identifier: Apache-2.0
/**
 * Native AgentROA and ORPRG adapters for AEB-ADAPTER-v1.
 *
 * These adapters accept trust, policy, status, mapping, and expected-action
 * inputs only from the relying-party-pinned AEB configuration. Native
 * artifacts cannot select their verifier keys, role, subject, mapping profile,
 * or action. The adapters deliberately stop at evidence acceptance and action
 * mapping; only the AEB evaluator can decide SATISFIED, and only Gate can make
 * a local authorization/consumption decision.
 *
 * ORPRG uses its native non-mutating inspector. Inspection verifies every
 * native predicate and returns the native replay identity without claiming a
 * final ALLOW; AEB/Gate must still atomically reserve and consume that replay
 * unit before a consequential effect.
 */
import crypto from 'node:crypto';
// The CAID reference implementation is JavaScript and intentionally has no
// TypeScript declaration surface in this repository.
// @ts-expect-error -- checked at runtime and narrowed below.
import { computeCaid } from '../vendor/caid.mjs';
import { digestAeb, } from './aeb-adapter-contract.js';
import { AGENTROA_DRAFT, verifyAgentROA } from './agentroa.js';
import { ORPRG_JSON_JCS_PROFILE, inspectOrprgJsonJcsPermit, } from './orprg.js';
export const AEB_NATIVE_CAID_MAPPING_VERSION = 'AEB-NATIVE-CAID-MAPPING-v1';
export const AEB_NATIVE_CAID_MAPPER_ID = 'mapper:aeb-native-add-action-type-v1';
export const AGENTROA_AEB_ADAPTER_ID = 'native:agentroa';
export const AGENTROA_AEB_ADAPTER_VERSION = '1';
export const AGENTROA_AEB_CONFIG_VERSION = 'AEB-AGENTROA-CONFIG-v1';
export const AGENTROA_AEB_TRUST_ROOT_VERSION = 'AEB-AGENTROA-ED25519-ROOT-v1';
export const ORPRG_AEB_ADAPTER_ID = 'native:orprg-json-jcs';
export const ORPRG_AEB_ADAPTER_VERSION = '1';
export const ORPRG_AEB_CONFIG_VERSION = 'AEB-ORPRG-CONFIG-v1';
export const ORPRG_AEB_TRUST_ROOT_VERSION = 'AEB-ORPRG-ED25519-ROOT-v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const AEB_IDENTIFIER = /^[A-Za-z0-9_.:-]+$/;
const ACTION_TYPE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+\.[1-9][0-9]*$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const AGENT_CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'action_type', 'max_status_age_seconds', 'policy',
]);
const AGENT_POLICY_KEYS = new Set([
    'expected_policy_id', 'expected_policy_version', 'expected_policy_digest',
    'allow_degraded', 'allowed_topologies', 'capability_manifest',
]);
const AGENT_ROOT_KEYS = new Set(['@version', 'role', 'signer_id', 'public_key']);
const ORPRG_CONFIG_KEYS = new Set([
    '@version', 'evidence_role', 'subject', 'action_type', 'expected_policy_digest',
    'expected_epoch', 'max_receipt_age_seconds', 'max_status_age_seconds',
    'require_budget', 'native_replay_phase',
]);
const ORPRG_ROOT_KEYS = new Set(['@version', 'issuer_id', 'key_id', 'public_key']);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const MAPPING_DEFINITION_KEYS = new Set([
    '@version', 'native_protocol', 'projection', 'action_type', 'suite', 'definitions',
]);
const STATUS_KEYS = new Set([
    'checked_at', 'expires_at', 'revocation_checked', 'revoked', 'consumed', 'unavailable',
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
function validIdentifier(value) {
    return nonEmptyString(value) && AEB_IDENTIFIER.test(value);
}
function nonNegativeInteger(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function uniqueStrings(value, allowEmpty = false) {
    return Array.isArray(value)
        && (allowEmpty || value.length > 0)
        && value.every(nonEmptyString)
        && new Set(value).size === value.length;
}
function validPinnedSubject(value, kinds) {
    return isRecord(value)
        && exactKeys(value, SUBJECT_KEYS)
        && validIdentifier(value.id)
        && kinds.has(String(value.kind))
        && nonEmptyString(value.native_id);
}
function validEd25519Spki(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1)
        return false;
    try {
        const der = Buffer.from(value, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== value)
            return false;
        const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
        return key.asymmetricKeyType === 'ed25519'
            && key.export({ type: 'spki', format: 'der' }).equals(der);
    }
    catch {
        return false;
    }
}
function parseInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = RFC3339.exec(value);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , , offsetHour, offsetMinute] = match;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
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
function inputStatusDigest(status) {
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
    if (!Number.isFinite(nowMs) || !Number.isFinite(checkedMs) || !Number.isFinite(expiresMs)
        || !nonNegativeInteger(maxAgeSeconds)) {
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
function fallbackNative(input, role = 'invalid-evidence', subject = { id: 'invalid-evidence', kind: 'system' }) {
    const evidenceDigest = safeDigest(input?.artifact);
    return {
        native_verification: 'FAILED',
        acceptance: 'INDETERMINATE',
        evidence_digest: evidenceDigest,
        status_digest: inputStatusDigest(input?.status),
        evidence_role: role,
        subject,
        replay_unit: evidenceDigest,
        reasons: [],
    };
}
function parseAgentConfig(value) {
    if (!isRecord(value) || !exactKeys(value, AGENT_CONFIG_KEYS)
        || value['@version'] !== AGENTROA_AEB_CONFIG_VERSION
        || !validIdentifier(value.evidence_role)
        || !validPinnedSubject(value.subject, new Set(['workload']))
        || value.subject.kind !== 'workload'
        || typeof value.action_type !== 'string' || !ACTION_TYPE.test(value.action_type)
        || !nonNegativeInteger(value.max_status_age_seconds)
        || !isRecord(value.policy) || !exactKeys(value.policy, AGENT_POLICY_KEYS))
        return null;
    const policy = value.policy;
    if (!nonEmptyString(policy.expected_policy_id)
        || !nonEmptyString(policy.expected_policy_version)
        || typeof policy.expected_policy_digest !== 'string' || !DIGEST.test(policy.expected_policy_digest)
        || typeof policy.allow_degraded !== 'boolean'
        || !uniqueStrings(policy.allowed_topologies)
        || !isRecord(policy.capability_manifest))
        return null;
    const capabilityManifest = Object.create(null);
    for (const [wildcard, capabilities] of Object.entries(policy.capability_manifest)) {
        if (!nonEmptyString(wildcard) || !uniqueStrings(capabilities))
            return null;
        capabilityManifest[wildcard] = [...capabilities];
    }
    return {
        evidence_role: value.evidence_role,
        subject: {
            id: value.subject.id,
            kind: 'workload',
            native_id: value.subject.native_id,
        },
        action_type: value.action_type,
        max_status_age_seconds: value.max_status_age_seconds,
        policy: {
            expected_policy_id: policy.expected_policy_id,
            expected_policy_version: policy.expected_policy_version,
            expected_policy_digest: policy.expected_policy_digest,
            allow_degraded: policy.allow_degraded,
            allowed_topologies: [...policy.allowed_topologies],
            capability_manifest: capabilityManifest,
        },
    };
}
function agentPins(trustRoots) {
    if (!Array.isArray(trustRoots) || trustRoots.length === 0)
        return null;
    const pins = {
        roa: Object.create(null),
        ara: Object.create(null),
        aer: Object.create(null),
    };
    for (const root of trustRoots) {
        if (!isRecord(root) || !exactKeys(root, AGENT_ROOT_KEYS)
            || root['@version'] !== AGENTROA_AEB_TRUST_ROOT_VERSION
            || !['roa', 'ara', 'aer'].includes(String(root.role))
            || !nonEmptyString(root.signer_id) || !validEd25519Spki(root.public_key))
            return null;
        const role = root.role;
        if (Object.hasOwn(pins[role], root.signer_id))
            return null;
        pins[role][root.signer_id] = root.public_key;
    }
    if (Object.keys(pins.roa).length === 0 || Object.keys(pins.aer).length === 0)
        return null;
    return pins;
}
function stripPinnedActionType(value, actionType) {
    if (!isRecord(value) || value.action_type !== actionType)
        return null;
    const native = {};
    for (const [key, item] of Object.entries(value)) {
        if (key !== 'action_type')
            native[key] = item;
    }
    return native;
}
function agentReplayUnit(artifact, fallback) {
    if (!isRecord(artifact) || !Array.isArray(artifact.chain) || !isRecord(artifact.chain[0])
        || !isRecord(artifact.aer) || !isRecord(artifact.aer.border_gateway)
        || !isRecord(artifact.aer.session)
        || !nonEmptyString(artifact.chain[0].envelope_id)
        || !nonEmptyString(artifact.aer.aer_id)
        || !nonEmptyString(artifact.aer.border_gateway.gateway_id)
        || !nonEmptyString(artifact.aer.session.session_id))
        return fallback;
    return safeDigest({
        native_protocol: AGENTROA_DRAFT,
        root_envelope_id: artifact.chain[0].envelope_id,
        aer_id: artifact.aer.aer_id,
        gateway_id: artifact.aer.border_gateway.gateway_id,
        session_id: artifact.aer.session.session_id,
    });
}
function agentFailureAcceptance(reason) {
    return ['invalid_verification_time', 'malformed_expected_action', 'missing_policy_profile', 'malformed_policy_profile']
        .includes(String(reason)) ? 'INDETERMINATE' : 'REJECTED';
}
function verifyAgentNative(input) {
    const config = parseAgentConfig(input?.adapter_config);
    const base = fallbackNative(input, config?.evidence_role, config ? { id: config.subject.id, kind: config.subject.kind } : undefined);
    base.replay_unit = agentReplayUnit(input?.artifact, base.evidence_digest);
    if (!config) {
        base.reasons = ['agentroa:invalid_pinned_config'];
        return base;
    }
    const pins = agentPins(input.trust_roots);
    if (!pins) {
        base.acceptance = 'REJECTED';
        base.reasons = ['agentroa:invalid_pinned_trust_roots'];
        return base;
    }
    const expectedNativeAction = stripPinnedActionType(input.expected_action, config.action_type);
    if (!expectedNativeAction) {
        base.reasons = ['agentroa:ambiguous_expected_action'];
        return base;
    }
    const result = verifyAgentROA(input.artifact, {
        keysByType: { agentroa: pins },
        policiesByType: { agentroa: config.policy },
        verificationTime: input.now,
        action: expectedNativeAction,
    });
    const nativeReason = nonEmptyString(result?.reason) ? `agentroa:${result.reason}` : null;
    if (result?.verified !== true) {
        base.acceptance = agentFailureAcceptance(result?.reason);
        base.reasons = nativeReason ? [nativeReason] : ['agentroa:native_verification_failed'];
        return base;
    }
    base.native_verification = 'VERIFIED';
    if (!isRecord(input.artifact) || !isRecord(input.artifact.aer)
        || !isRecord(input.artifact.aer.session)
        || input.artifact.aer.session.agent_id !== config.subject.native_id) {
        base.acceptance = 'REJECTED';
        base.reasons = ['agentroa:native_subject_mismatch'];
        return base;
    }
    if (result.valid !== true) {
        base.acceptance = 'REJECTED';
        base.reasons = nativeReason ? [nativeReason] : ['agentroa:native_permit_refused'];
        return base;
    }
    const status = statusDisposition(input.status, input.now, config.max_status_age_seconds);
    base.acceptance = status.acceptance;
    base.reasons = status.reasons;
    return base;
}
function parseOrprgConfig(value) {
    if (!isRecord(value) || !exactKeys(value, ORPRG_CONFIG_KEYS)
        || value['@version'] !== ORPRG_AEB_CONFIG_VERSION
        || !validIdentifier(value.evidence_role)
        || !validPinnedSubject(value.subject, new Set(['organization', 'system']))
        || (value.subject.kind !== 'organization' && value.subject.kind !== 'system')
        || typeof value.action_type !== 'string' || !ACTION_TYPE.test(value.action_type)
        || typeof value.expected_policy_digest !== 'string' || !DIGEST.test(value.expected_policy_digest)
        || !((nonEmptyString(value.expected_epoch)) || nonNegativeInteger(value.expected_epoch))
        || !nonNegativeInteger(value.max_receipt_age_seconds)
        || !nonNegativeInteger(value.max_status_age_seconds)
        || typeof value.require_budget !== 'boolean'
        || value.native_replay_phase !== 'inspection-only')
        return null;
    return {
        evidence_role: value.evidence_role,
        subject: {
            id: value.subject.id,
            kind: value.subject.kind,
            native_id: value.subject.native_id,
        },
        action_type: value.action_type,
        expected_policy_digest: value.expected_policy_digest,
        expected_epoch: value.expected_epoch,
        max_receipt_age_seconds: value.max_receipt_age_seconds,
        max_status_age_seconds: value.max_status_age_seconds,
        require_budget: value.require_budget,
    };
}
function orprgIssuerKeys(trustRoots) {
    if (!Array.isArray(trustRoots) || trustRoots.length === 0)
        return null;
    const issuers = Object.create(null);
    for (const root of trustRoots) {
        if (!isRecord(root) || !exactKeys(root, ORPRG_ROOT_KEYS)
            || root['@version'] !== ORPRG_AEB_TRUST_ROOT_VERSION
            || !nonEmptyString(root.issuer_id) || !nonEmptyString(root.key_id)
            || !validEd25519Spki(root.public_key))
            return null;
        if (!Object.hasOwn(issuers, root.issuer_id))
            issuers[root.issuer_id] = Object.create(null);
        if (Object.hasOwn(issuers[root.issuer_id], root.key_id))
            return null;
        issuers[root.issuer_id][root.key_id] = root.public_key;
    }
    return issuers;
}
function orprgFailureAcceptance(code) {
    return ['AMBIGUOUS_CONTEXT', 'REVOCATION_UNKNOWN_OR_STALE', 'ANTI_REPLAY_FAILURE']
        .includes(String(code)) ? 'INDETERMINATE' : 'REJECTED';
}
function nativeInspectionPassed(result) {
    const checks = result?.detail?.checks;
    if (!isRecord(checks))
        return false;
    const required = [
        'structure', 'canonical_action', 'canonicalization_profile', 'action_binding',
        'policy_binding', 'epoch_binding', 'scope_binding', 'budget_binding', 'validity',
        'receipt_recency', 'status', 'status_recency', 'issuer_pinned', 'signature',
    ];
    return required.every((check) => checks[check] === true)
        && checks.anti_replay === false
        && result.valid === false
        && result.inspection_valid === true
        && typeof result.action_digest === 'string' && DIGEST.test(result.action_digest)
        && typeof result.replay_key === 'string'
        && /^orprg-replay:sha256:[0-9a-f]{64}$/.test(result.replay_key)
        && isRecord(result.replay_context)
        && result.detail.decision === 'INSPECTED_NOT_CONSUMED'
        && result.detail.denial_reason_code === 'ANTI_REPLAY_RESERVATION_REQUIRED';
}
/**
 * Normalize the native two-phase inspector to the adapter's internal shape.
 * No replay hook is supplied or invoked during this phase.
 */
function inspectOrprgForAeb(input, options) {
    const nativeResult = inspectOrprgJsonJcsPermit(input, options);
    const complete = nativeInspectionPassed(nativeResult);
    return {
        native_result: nativeResult,
        pre_replay_verified: complete,
        non_mutating_verification_complete: complete,
        replay_key: complete ? nativeResult.replay_key : null,
        replay_context: complete ? nativeResult.replay_context : null,
    };
}
function verifyOrprgNative(input) {
    const config = parseOrprgConfig(input?.adapter_config);
    const base = fallbackNative(input, config?.evidence_role, config ? { id: config.subject.id, kind: config.subject.kind } : undefined);
    if (!config) {
        base.reasons = ['orprg:invalid_pinned_config'];
        return base;
    }
    const issuerKeys = orprgIssuerKeys(input.trust_roots);
    if (!issuerKeys) {
        base.acceptance = 'REJECTED';
        base.reasons = ['orprg:invalid_pinned_trust_roots'];
        return base;
    }
    const expectedNativeAction = stripPinnedActionType(input.expected_action, config.action_type);
    if (!expectedNativeAction) {
        base.reasons = ['orprg:ambiguous_expected_action'];
        return base;
    }
    const inspection = inspectOrprgForAeb(input.artifact, {
        expectedAction: expectedNativeAction,
        verificationTime: input.now,
        expectedPolicyDigest: config.expected_policy_digest,
        expectedEpoch: config.expected_epoch,
        maxReceiptAgeSeconds: config.max_receipt_age_seconds,
        maxStatusAgeSeconds: config.max_status_age_seconds,
        requireBudget: config.require_budget,
        issuerKeys,
    });
    const result = inspection.native_result;
    if (inspection.replay_key !== null) {
        base.replay_unit = inspection.replay_key.slice('orprg-replay:'.length);
    }
    const code = result?.detail?.denial_reason_code;
    const reason = nonEmptyString(code) ? `orprg:${code}` : 'orprg:native_verification_failed';
    if (!isRecord(input.artifact) || !isRecord(input.artifact.authenticity)
        || input.artifact.authenticity.issuer_id !== config.subject.native_id) {
        base.acceptance = 'REJECTED';
        base.reasons = ['orprg:native_subject_mismatch', reason];
        return base;
    }
    const externalStatus = statusDisposition(input.status, input.now, config.max_status_age_seconds);
    if (externalStatus.acceptance !== 'ACCEPTED') {
        base.acceptance = externalStatus.acceptance;
        base.reasons = [...new Set([reason, ...externalStatus.reasons])].sort();
        return base;
    }
    if (inspection.pre_replay_verified) {
        if (inspection.non_mutating_verification_complete) {
            base.native_verification = 'VERIFIED';
            base.acceptance = 'ACCEPTED';
            base.reasons = [];
            return base;
        }
    }
    base.acceptance = orprgFailureAcceptance(code);
    base.reasons = [reason];
    return base;
}
function parseMappingProfile(profile, nativeProtocol, configActionType) {
    const reasons = [];
    if (!isRecord(profile)
        || profile.version !== AEB_NATIVE_CAID_MAPPING_VERSION
        || profile.mapper_id !== AEB_NATIVE_CAID_MAPPER_ID
        || !isRecord(profile.resolver)
        || profile.resolver.id !== AEB_NATIVE_CAID_MAPPER_ID
        || profile.resolver.version !== '1'
        || !isRecord(profile.semantic_equivalence)
        || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
        || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS') {
        return { mapping: null, reasons: ['mapping_profile_invalid'] };
    }
    if (!Array.isArray(profile.semantic_equivalence.omitted_material_fields)
        || !Array.isArray(profile.semantic_equivalence.omitted_nonmaterial_fields)
        || profile.semantic_equivalence.omitted_material_fields.length > 0
        || profile.semantic_equivalence.omitted_nonmaterial_fields.length > 0) {
        reasons.push('mapping_profile_information_loss');
    }
    if (!isRecord(profile.definition) || !exactKeys(profile.definition, MAPPING_DEFINITION_KEYS)
        || profile.definition['@version'] !== AEB_NATIVE_CAID_MAPPING_VERSION
        || profile.definition.projection !== 'add-action-type-v1'
        || profile.definition.suite !== 'jcs-sha256'
        || !Array.isArray(profile.definition.definitions)) {
        reasons.push('mapping_profile_invalid');
        return { mapping: null, reasons: [...new Set(reasons)].sort() };
    }
    const definition = profile.definition;
    if (definition.native_protocol !== nativeProtocol)
        reasons.push('mapping_profile_protocol_mismatch');
    if (definition.action_type !== configActionType
        || typeof definition.action_type !== 'string'
        || !ACTION_TYPE.test(definition.action_type))
        reasons.push('mapping_profile_action_type_mismatch');
    const matchingDefinitions = definition.definitions.filter((candidate) => (isRecord(candidate) && candidate.action_type === definition.action_type));
    if (matchingDefinitions.length !== 1)
        reasons.push('mapping_profile_definition_ambiguous');
    if (reasons.length > 0)
        return { mapping: null, reasons: [...new Set(reasons)].sort() };
    return {
        mapping: {
            native_protocol: definition.native_protocol,
            action_type: definition.action_type,
            suite: 'jcs-sha256',
            definitions: definition.definitions,
        },
        reasons: [],
    };
}
function mapExactNativeAction(input, nativeProtocol, configActionType, signedNativeAction) {
    if (input.native.native_verification !== 'VERIFIED' || input.native.acceptance !== 'ACCEPTED') {
        return {
            mapping: 'INDETERMINATE', caid: null, action_digest: null,
            reasons: ['native_acceptance_required'],
        };
    }
    if (configActionType === null) {
        return {
            mapping: 'INDETERMINATE', caid: null, action_digest: null,
            reasons: ['mapping_pinned_config_invalid'],
        };
    }
    const parsed = parseMappingProfile(input.profile, nativeProtocol, configActionType);
    if (!parsed.mapping) {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: parsed.reasons };
    }
    if (!isRecord(signedNativeAction) || Object.hasOwn(signedNativeAction, 'action_type')) {
        return {
            mapping: 'INDETERMINATE', caid: null, action_digest: null,
            reasons: ['native_action_not_exactly_projectable'],
        };
    }
    const normalizedAction = { action_type: parsed.mapping.action_type, ...signedNativeAction };
    const expectedDigest = safeDigest(input.expected_action);
    const normalizedDigest = safeDigest(normalizedAction);
    if (expectedDigest !== normalizedDigest) {
        return {
            mapping: 'MISMATCH', caid: null, action_digest: normalizedDigest,
            reasons: ['normalized_native_action_mismatch'],
        };
    }
    let computed;
    try {
        computed = computeCaid(normalizedAction, {
            suite: parsed.mapping.suite,
            definitions: parsed.mapping.definitions,
        });
    }
    catch {
        computed = null;
    }
    if (!isRecord(computed) || typeof computed.caid !== 'string'
        || typeof computed.digest !== 'string' || !DIGEST.test(computed.digest)) {
        const refusals = isRecord(computed) && Array.isArray(computed.refusals)
            ? computed.refusals.map(String).sort() : ['caid_mapping_failed'];
        return {
            mapping: 'INDETERMINATE', caid: null, action_digest: null,
            reasons: refusals.map((reason) => `caid:${reason}`),
        };
    }
    if (computed.digest !== normalizedDigest) {
        return {
            mapping: 'INDETERMINATE', caid: null, action_digest: null,
            reasons: ['caid_digest_disagreement'],
        };
    }
    return {
        mapping: 'MATCH',
        caid: computed.caid,
        action_digest: normalizedDigest,
        reasons: [],
    };
}
/** Build the fixed AgentROA native adapter. All mutable policy comes from AEB pins. */
export function createAgentRoaAebAdapter() {
    return Object.freeze({
        id: AGENTROA_AEB_ADAPTER_ID,
        version: AGENTROA_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyAgentNative(input);
            }
            catch {
                const result = fallbackNative(input);
                result.reasons = ['agentroa:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                const config = parseAgentConfig(input.adapter_config);
                const signedAction = isRecord(input.artifact) && isRecord(input.artifact.aer)
                    ? input.artifact.aer.action : null;
                return mapExactNativeAction(input, AGENTROA_DRAFT, config?.action_type ?? null, signedAction);
            }
            catch {
                return {
                    mapping: 'INDETERMINATE', caid: null, action_digest: null,
                    reasons: ['agentroa:unexpected_mapping_error'],
                };
            }
        },
    });
}
/**
 * Build the fixed ORPRG native adapter.
 *
 * Native inspection can establish VERIFIED/ACCEPTED evidence, but never final
 * ORPRG ALLOW. Gate must atomically reserve and consume the adapter's native
 * replay_unit before execution.
 */
export function createOrprgAebAdapter() {
    return Object.freeze({
        id: ORPRG_AEB_ADAPTER_ID,
        version: ORPRG_AEB_ADAPTER_VERSION,
        verifyNative(input) {
            try {
                return verifyOrprgNative(input);
            }
            catch {
                const result = fallbackNative(input);
                result.reasons = ['orprg:unexpected_adapter_error'];
                return result;
            }
        },
        mapAction(input) {
            try {
                const config = parseOrprgConfig(input.adapter_config);
                const expectedNativeAction = config
                    ? stripPinnedActionType(input.expected_action, config.action_type) : null;
                return mapExactNativeAction(input, ORPRG_JSON_JCS_PROFILE, config?.action_type ?? null, expectedNativeAction);
            }
            catch {
                return {
                    mapping: 'INDETERMINATE', caid: null, action_digest: null,
                    reasons: ['orprg:unexpected_mapping_error'],
                };
            }
        },
    });
}
//# sourceMappingURL=aeb-native-adapters.js.map