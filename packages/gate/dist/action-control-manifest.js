// SPDX-License-Identifier: Apache-2.0
//
// EP Action Control Manifest: the missing control-plane waist between agent
// runtimes, receipt formats, transparency logs, and system-of-record adapters.
//
// A receipt proves an authorization event. This manifest tells an executor
// when a receipt is required, what assurance tier is required, which material
// fields must be observed from the system of record, and what evidence must be
// emitted after the effect boundary.
import { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS } from './action-packs.js';
export const ACTION_CONTROL_MANIFEST_VERSION = 'EP-ACTION-CONTROL-MANIFEST-v0.2';
export const ACTION_CONTROL_SCHEMA_URL = 'https://www.emiliaprotocol.ai/docs/schemas/agent-action-control-manifest-v0.2.schema.json';
export const ACTION_CONTROL_CONFORMANCE_LEVEL = 'EG-1';
export const ACTION_CONTROL_AUTHORIZATION = Object.freeze({
    authorization_endpoint: 'https://www.emiliaprotocol.ai/api/v1/approvals',
    flow: 'EP-APPROVAL-v1',
});
// Acquisition is advertised only when the reference server has a closed,
// independently verifiable ceremony for the action type. Receipt-required
// actions outside this registry remain enforceable, but challenge-only.
export const ACTION_CONTROL_ACQUISITION_ACTION_TYPES = Object.freeze([
    'payment.release',
]);
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical']);
const ASSURANCE_CLASSES = new Set(['software', 'class_a', 'quorum']);
const ENFORCEMENT_POINTS = new Set(['pre_execution', 'pre_effect_commit']);
export const ACTION_CONTROL_DEFAULTS = Object.freeze({
    decision_point: 'pre_effect_commit',
    missing_receipt: 'refuse',
    invalid_receipt: 'refuse',
    stale_receipt: 'refuse',
    replay: 'one_time_consumption',
    evidence_log: 'strict',
});
export const ACTION_CONTROL_EVIDENCE_PROFILES = Object.freeze({
    authorization_receipt: 'EP-RECEIPT-v1',
    execution_attestation: 'EP-EXECUTION-ATTESTATION-v1',
    reliance_packet: 'EP-RELIANCE-PACKET-v1',
    transparency: 'SCITT-compatible Signed Statement',
});
export const ACTION_CONTROL_CONFORMANCE_CHECKS = Object.freeze([
    'missing_receipt_refused',
    'software_on_classA_refused',
    'execution_drift_refused',
    'valid_classA_runs',
    'replay_refused',
    'tampered_refused',
    'execution_proof_binds',
    'reliance_packet_rely',
]);
function cloneJson(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value));
}
function normalizeRisk(risk) {
    return RISK_LEVELS.has(risk) ? risk : 'high';
}
function normalizeAssurance(value) {
    return ASSURANCE_CLASSES.has(value) ? value : 'software';
}
function supportsReferenceAcquisition(actionType) {
    return typeof actionType === 'string'
        && ACTION_CONTROL_ACQUISITION_ACTION_TYPES.includes(actionType);
}
function defaultControlForAction(action) {
    const requiredFields = action.execution_binding?.required_fields || [];
    const caidSelector = action.execution_binding?.caid_selector;
    if (!action.receipt_required) {
        return {
            enforcement_point: 'none',
            authorization_receipt: { required: false },
            evidence_output: { audit_event: true },
        };
    }
    const control = {
        enforcement_point: 'pre_effect_commit',
        status: 428,
        challenge_header: 'Receipt-Required',
        proof_header: 'X-EMILIA-Receipt',
        authorization_receipt: {
            required: true,
            profile: 'EP-RECEIPT-v1',
            signature: 'Ed25519 over RFC 8785 canonical JSON',
            verifier: 'offline',
        },
        replay: {
            mode: 'one_time_consumption',
            receipt_id_required: true,
        },
        execution_binding: {
            required: true,
            source: 'system_of_record',
            required_fields: [...requiredFields],
            ...(caidSelector ? { caid_selector: cloneJson(caidSelector) } : {}),
        },
        transparency: {
            mode: 'registerable',
            profile: 'SCITT Signed Statement',
            required: false,
        },
        evidence_output: {
            audit_event: true,
            execution_attestation: true,
            reliance_packet: true,
            blocked_attempts: true,
        },
    };
    if (supportsReferenceAcquisition(action.action_type)) {
        control.authorization = { ...ACTION_CONTROL_AUTHORIZATION };
    }
    return control;
}
export function toActionControl(action) {
    const out = {
        id: action.id,
        label: action.label || action.description || action.id,
        action_type: action.action_type,
        risk: normalizeRisk(action.risk || (action.receipt_required ? 'high' : 'low')),
        receipt_required: !!action.receipt_required,
        assurance_class: normalizeAssurance(action.assurance_class),
        max_age_sec: action.max_age_sec || 900,
        match: cloneJson(action.match || {}),
        why: action.why || action.description || null,
        control: cloneJson(action.control || defaultControlForAction(action)),
        conformance: {
            level: ACTION_CONTROL_CONFORMANCE_LEVEL,
            checks: [...ACTION_CONTROL_CONFORMANCE_CHECKS],
            ...(action.conformance || {}),
        },
    };
    if (action.quorum)
        out.quorum = cloneJson(action.quorum);
    if (action.business_authorization || action.businessAuthorization) {
        out.business_authorization = cloneJson(action.business_authorization || action.businessAuthorization);
    }
    return out;
}
/**
 * @param {object} [o]
 * @param {{ name?: string, issuer?: string, manifest_url?: string }} [o.service]
 * @param {boolean} [o.includePassThrough]
 * @param {Array<object>} [o.extraActions]
 */
export function createDefaultActionControlManifest({ service = {}, includePassThrough = true, extraActions = [], } = {}) {
    const actions = [
        ...HIGH_RISK_ACTION_PACKS.map(toActionControl),
        ...(includePassThrough ? DEFAULT_PASS_THROUGH_ACTIONS.map(toActionControl) : []),
    ];
    // `extraActions` is also the supported customization mechanism. An exact id
    // or exact transport-selector match replaces the built-in entry; leaving
    // both would create an ambiguous manifest that the validator correctly
    // rejects. Broader/partial overlaps are not silently normalized and remain
    // validation errors.
    for (const candidate of extraActions.map(toActionControl)) {
        const index = actions.findIndex((current) => current.id === candidate.id
            || selectorsEqual(current, candidate));
        if (index >= 0)
            actions.splice(index, 1, candidate);
        else
            actions.push(candidate);
    }
    return {
        '@version': ACTION_CONTROL_MANIFEST_VERSION,
        '$schema': ACTION_CONTROL_SCHEMA_URL,
        profile: 'agent-action-control',
        service: {
            name: service.name || 'EMILIA Gate default action controls',
            issuer: service.issuer || 'https://www.emiliaprotocol.ai',
            manifest_url: service.manifest_url || 'https://www.emiliaprotocol.ai/.well-known/agent-action-control.json',
            ...service,
        },
        defaults: { ...ACTION_CONTROL_DEFAULTS },
        evidence_profiles: { ...ACTION_CONTROL_EVIDENCE_PROFILES },
        actions,
    };
}
function selectorMatches(action, selector = {}) {
    if (!action || typeof action !== 'object' || Array.isArray(action)
        || !selector || typeof selector !== 'object' || Array.isArray(selector))
        return false;
    const match = action.match;
    if (!match || typeof match !== 'object' || Array.isArray(match))
        return false;
    const matchEntries = Object.entries(match);
    if (matchEntries.length === 0)
        return false;
    // action_type is an additional constraint; it may never bypass a conflicting
    // transport selector. Other selector metadata (for example manifestUrl) is
    // not part of the action's transport identity.
    if (Object.prototype.hasOwnProperty.call(selector, 'action_type')
        && selector.action_type !== action.action_type)
        return false;
    return matchEntries.every(([key, value]) => (Object.prototype.hasOwnProperty.call(selector, key) && selector[key] === value));
}
export function findActionControl(manifest, selector = {}) {
    const resolved = resolveActionControl(manifest, selector);
    return resolved.status === 'one' ? resolved.action : null;
}
export function resolveActionControl(manifest, selector = {}) {
    if (!manifest || !Array.isArray(manifest.actions))
        return { status: 'none', action: null };
    const matches = manifest.actions.filter((action) => selectorMatches(action, selector));
    if (matches.length === 0)
        return { status: 'none', action: null };
    if (matches.length === 1)
        return { status: 'one', action: matches[0] };
    return {
        status: 'ambiguous',
        action: null,
        action_ids: matches.map((action) => String(action.id || '')).sort(),
    };
}
function selectorsOverlap(left, right) {
    const a = left?.match;
    const b = right?.match;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object'
        || Array.isArray(a) || Array.isArray(b))
        return false;
    const shared = Object.keys(a).filter((key) => Object.prototype.hasOwnProperty.call(b, key));
    return shared.every((key) => a[key] === b[key]);
}
function selectorsEqual(left, right) {
    const a = left?.match;
    const b = right?.match;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object'
        || Array.isArray(a) || Array.isArray(b))
        return false;
    const aKeys = Object.keys(a).sort();
    const bKeys = Object.keys(b).sort();
    return aKeys.length > 0
        && aKeys.length === bKeys.length
        && aKeys.every((key, index) => key === bKeys[index] && a[key] === b[key]);
}
function validateAuthorizationDescriptor(authorization, prefix, errors) {
    if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) {
        errors.push(`${prefix}.control.authorization must be an object`);
        return;
    }
    const prototype = Object.getPrototypeOf(authorization);
    const keys = Object.keys(authorization).sort();
    if ((prototype !== Object.prototype && prototype !== null)
        || keys.length !== 2
        || keys[0] !== 'authorization_endpoint'
        || keys[1] !== 'flow') {
        errors.push(`${prefix}.control.authorization must contain only authorization_endpoint and flow`);
    }
    if (authorization.flow !== 'EP-APPROVAL-v1') {
        errors.push(`${prefix}.control.authorization.flow must be EP-APPROVAL-v1`);
    }
    let endpoint = null;
    try {
        endpoint = new URL(authorization.authorization_endpoint);
    }
    catch {
        // The common error below intentionally covers both malformed and relative URLs.
    }
    if (!endpoint
        || endpoint.protocol !== 'https:'
        || !endpoint.hostname
        || endpoint.username
        || endpoint.password
        || endpoint.search
        || endpoint.hash) {
        errors.push(`${prefix}.control.authorization.authorization_endpoint must be an absolute HTTPS URL without credentials, query, or fragment`);
    }
}
export function validateActionControlManifest(manifest, { requireAcquisition = false } = {}) {
    const errors = [];
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
        return { ok: false, errors: ['manifest must be an object'] };
    }
    if (manifest['@version'] !== ACTION_CONTROL_MANIFEST_VERSION) {
        errors.push(`@version must be ${ACTION_CONTROL_MANIFEST_VERSION}`);
    }
    if (manifest.profile !== 'agent-action-control' && manifest.profile !== 'emilia.action-control') {
        errors.push('profile must be agent-action-control (or the deployed alias emilia.action-control)');
    }
    if (!manifest.service || typeof manifest.service !== 'object') {
        errors.push('service object is required');
    }
    if (!manifest.defaults || typeof manifest.defaults !== 'object') {
        errors.push('defaults object is required');
    }
    if (!Array.isArray(manifest.actions) || manifest.actions.length === 0) {
        errors.push('actions must be a non-empty array');
    }
    const ids = new Map();
    for (const [idx, action] of (manifest.actions || []).entries()) {
        const prefix = `actions[${idx}]`;
        if (!action || typeof action !== 'object') {
            errors.push(`${prefix} must be an object`);
            continue;
        }
        if (!action.id || typeof action.id !== 'string')
            errors.push(`${prefix}.id is required`);
        else if (ids.has(action.id))
            errors.push(`${prefix}.id duplicates actions[${ids.get(action.id)}].id`);
        else
            ids.set(action.id, idx);
        if (!action.action_type || typeof action.action_type !== 'string')
            errors.push(`${prefix}.action_type is required`);
        if (!action.match || typeof action.match !== 'object')
            errors.push(`${prefix}.match is required`);
        if (typeof action.receipt_required !== 'boolean')
            errors.push(`${prefix}.receipt_required must be boolean`);
        if (!RISK_LEVELS.has(action.risk))
            errors.push(`${prefix}.risk must be low|medium|high|critical`);
        if (!ASSURANCE_CLASSES.has(action.assurance_class))
            errors.push(`${prefix}.assurance_class must be software|class_a|quorum`);
        // Key-class floor: a critical action must be bound to a human key. normalizeAssurance()
        // defaults a missing or unrecognized tier to the weakest 'software', so this also fails
        // closed on a critical action whose tier was omitted rather than silently downgrading it.
        if (action.receipt_required && action.risk === 'critical' && action.assurance_class === 'software') {
            errors.push(`${prefix}.assurance_class must be class_a or quorum when risk is critical`);
        }
        const authorization = action.control?.authorization;
        if (authorization !== undefined) {
            validateAuthorizationDescriptor(authorization, prefix, errors);
            if (!supportsReferenceAcquisition(action.action_type)) {
                errors.push(`${prefix}.control.authorization is advertised for an unsupported acquisition action_type`);
            }
        }
        if (action.receipt_required) {
            if (!Number.isFinite(action.max_age_sec) || action.max_age_sec <= 0)
                errors.push(`${prefix}.max_age_sec must be positive`);
            const control = action.control;
            if (!control || typeof control !== 'object') {
                errors.push(`${prefix}.control is required when receipt_required=true`);
                continue;
            }
            if (requireAcquisition
                && supportsReferenceAcquisition(action.action_type)
                && authorization === undefined) {
                errors.push(`${prefix}.control.authorization is required for acquisition conformance`);
            }
            if (!ENFORCEMENT_POINTS.has(control.enforcement_point)) {
                errors.push(`${prefix}.control.enforcement_point must be pre_execution or pre_effect_commit`);
            }
            if (control.status !== 428)
                errors.push(`${prefix}.control.status must be 428`);
            if (control.authorization_receipt?.required !== true)
                errors.push(`${prefix}.control.authorization_receipt.required must be true`);
            if (control.authorization_receipt?.profile !== 'EP-RECEIPT-v1')
                errors.push(`${prefix}.control.authorization_receipt.profile must be EP-RECEIPT-v1`);
            if (control.authorization_receipt?.verifier !== 'offline')
                errors.push(`${prefix}.control.authorization_receipt.verifier must be offline`);
            if (control.replay?.mode !== 'one_time_consumption')
                errors.push(`${prefix}.control.replay.mode must be one_time_consumption`);
            if (control.replay?.receipt_id_required !== true)
                errors.push(`${prefix}.control.replay.receipt_id_required must be true`);
            const fields = control.execution_binding?.required_fields;
            if (control.execution_binding?.required !== true)
                errors.push(`${prefix}.control.execution_binding.required must be true`);
            if (control.execution_binding?.source !== 'system_of_record')
                errors.push(`${prefix}.control.execution_binding.source must be system_of_record`);
            if (!Array.isArray(fields) || fields.length === 0 || fields.some((f) => typeof f !== 'string' || !f)) {
                errors.push(`${prefix}.control.execution_binding.required_fields must be a non-empty string array`);
            }
            const caidSelector = control.execution_binding?.caid_selector;
            if (caidSelector !== undefined
                && (!caidSelector || typeof caidSelector !== 'object' || Array.isArray(caidSelector)
                    || Object.keys(caidSelector).length !== 1
                    || typeof caidSelector.field !== 'string'
                    || !/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(caidSelector.field))) {
                errors.push(`${prefix}.control.execution_binding.caid_selector must select one safe action field`);
            }
            if (control.evidence_output?.execution_attestation !== true)
                errors.push(`${prefix}.control.evidence_output.execution_attestation must be true`);
            if (control.evidence_output?.reliance_packet !== true)
                errors.push(`${prefix}.control.evidence_output.reliance_packet must be true`);
            if (action.conformance?.level !== ACTION_CONTROL_CONFORMANCE_LEVEL)
                errors.push(`${prefix}.conformance.level must be ${ACTION_CONTROL_CONFORMANCE_LEVEL}`);
            if (action.business_authorization !== undefined) {
                const business = action.business_authorization;
                const policy = business?.policy;
                const approvers = business?.allowed_approvers;
                if (!business || typeof business !== 'object' || Array.isArray(business)) {
                    errors.push(`${prefix}.business_authorization must be an object`);
                }
                else {
                    if (!policy || typeof policy !== 'object' || Array.isArray(policy)
                        || typeof policy.id !== 'string' || !policy.id
                        || typeof policy.hash !== 'string' || !policy.hash) {
                        errors.push(`${prefix}.business_authorization.policy must pin non-empty id and hash`);
                    }
                    if (typeof business.tenant_id !== 'string' || !business.tenant_id) {
                        errors.push(`${prefix}.business_authorization.tenant_id must be a non-empty string`);
                    }
                    if (!Array.isArray(approvers) || approvers.length === 0
                        || approvers.some((entry) => !entry || typeof entry !== 'object'
                            || typeof entry.subject !== 'string' || !entry.subject
                            || typeof entry.role !== 'string' || !entry.role)) {
                        errors.push(`${prefix}.business_authorization.allowed_approvers must name subject and role`);
                    }
                }
            }
        }
    }
    for (let left = 0; left < (manifest.actions || []).length; left += 1) {
        for (let right = left + 1; right < manifest.actions.length; right += 1) {
            if (selectorsOverlap(manifest.actions[left], manifest.actions[right])) {
                errors.push(`actions[${left}].match overlaps actions[${right}].match`);
            }
        }
    }
    return { ok: errors.length === 0, errors };
}
export default {
    ACTION_CONTROL_MANIFEST_VERSION,
    ACTION_CONTROL_SCHEMA_URL,
    ACTION_CONTROL_CONFORMANCE_LEVEL,
    ACTION_CONTROL_AUTHORIZATION,
    ACTION_CONTROL_DEFAULTS,
    ACTION_CONTROL_EVIDENCE_PROFILES,
    ACTION_CONTROL_CONFORMANCE_CHECKS,
    toActionControl,
    createDefaultActionControlManifest,
    findActionControl,
    resolveActionControl,
    validateActionControlManifest,
};
//# sourceMappingURL=action-control-manifest.js.map