// SPDX-License-Identifier: Apache-2.0
// Generated from index.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Mechanism-neutral operator projection over existing EMILIA authority
// primitives. This module does not issue authority, execute an action, or
// establish provider truth. It shows what an AI Operations interface can
// expose without collapsing policy, authorization, admission, and outcome.
import { hashCanonical } from '../../packages/gate/execution-binding.js';
export const AUTHORITY_OPERATIONS_INTERFACE_VERSION = 'EMILIA-AUTHORITY-OPERATIONS-REFERENCE-v0';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const MODES = new Set([
    'AUTOMATIC_WITHIN_ENVELOPE',
    'FRESH_AUTHORIZATION_REQUIRED',
    'PROHIBITED',
]);
const POLICY_RESULTS = new Set(['WITHIN_ENVELOPE', 'OUTSIDE_ENVELOPE', 'INDETERMINATE']);
const OUTCOMES = new Set(['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE']);
function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function safeIdentifier(value) {
    return typeof value === 'string'
        && value.length >= 3
        && value.length <= 256
        && /^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$/.test(value);
}
function iso(value) {
    return typeof value === 'string'
        && Number.isFinite(Date.parse(value))
        && new Date(value).toISOString() === value;
}
function copy(value) {
    return structuredClone(value);
}
function exactAction(value) {
    return isPlainObject(value)
        && safeIdentifier(value.action_type)
        && isPlainObject(value.target)
        && Object.keys(value.target).length > 0
        && isPlainObject(value.parameters);
}
function validateRequirements(value) {
    if (!Array.isArray(value) || value.length > 16)
        return false;
    const keys = new Set();
    for (const item of value) {
        if (!isPlainObject(item)
            || !safeIdentifier(item.evidence_type)
            || !safeIdentifier(item.role)
            || !Number.isSafeInteger(item.minimum)
            || item.minimum < 1
            || item.minimum > 16
            || Object.keys(item).some((key) => !['evidence_type', 'role', 'minimum'].includes(key))) {
            return false;
        }
        const key = `${item.evidence_type}\u0000${item.role}`;
        if (keys.has(key))
            return false;
        keys.add(key);
    }
    return true;
}
function validatePolicy(value, actionType) {
    if (!isPlainObject(value)
        || !safeIdentifier(value.policy_id)
        || !DIGEST.test(value.policy_digest || '')
        || value.action_type !== actionType
        || !MODES.has(value.mode)
        || !safeIdentifier(value.evaluator_profile)
        || !['FRESH_AUTHORIZATION_REQUIRED', 'REFUSE'].includes(value.outside_envelope)
        || value.indeterminate !== 'REFUSE'
        || !validateRequirements(value.required_evidence)
        || Object.keys(value).some((key) => ![
            'policy_id', 'policy_digest', 'action_type', 'mode', 'evaluator_profile',
            'outside_envelope', 'indeterminate', 'required_evidence',
        ].includes(key))) {
        throw new TypeError('authority_operations:policy_invalid');
    }
    if (value.mode === 'FRESH_AUTHORIZATION_REQUIRED' && value.required_evidence.length === 0) {
        throw new TypeError('authority_operations:required_evidence_missing');
    }
    if (value.mode === 'AUTOMATIC_WITHIN_ENVELOPE'
        && value.outside_envelope === 'FRESH_AUTHORIZATION_REQUIRED'
        && value.required_evidence.length === 0) {
        throw new TypeError('authority_operations:required_evidence_missing');
    }
}
function event(operation, at, type, details = {}) {
    if (!iso(at))
        throw new TypeError('authority_operations:timestamp_invalid');
    const previous = operation.history.at(-1);
    if (previous && Date.parse(at) < Date.parse(previous.at)) {
        throw new TypeError('authority_operations:history_time_regressed');
    }
    operation.history.push({ sequence: operation.history.length + 1, at, type, ...details });
}
function deriveInitialState(policy, result) {
    if (policy.mode === 'PROHIBITED') {
        return { authorization: 'NOT_REQUIRED', execution: 'REFUSED', reason: 'policy_prohibited' };
    }
    if (policy.mode === 'FRESH_AUTHORIZATION_REQUIRED') {
        return { authorization: 'REQUIRED', execution: 'AUTHORIZATION_REQUIRED', reason: 'fresh_authorization_required' };
    }
    if (result === 'WITHIN_ENVELOPE') {
        return { authorization: 'NOT_REQUIRED', execution: 'READY', reason: null };
    }
    if (result === 'OUTSIDE_ENVELOPE' && policy.outside_envelope === 'FRESH_AUTHORIZATION_REQUIRED') {
        return { authorization: 'REQUIRED', execution: 'AUTHORIZATION_REQUIRED', reason: 'outside_authority_envelope' };
    }
    if (result === 'INDETERMINATE') {
        return { authorization: 'INDETERMINATE', execution: 'REFUSED', reason: 'policy_result_indeterminate' };
    }
    return { authorization: 'NOT_REQUIRED', execution: 'REFUSED', reason: 'outside_authority_envelope' };
}
export function createAuthorityOperation(input) {
    if (!isPlainObject(input)
        || !safeIdentifier(input.operation_id)
        || !exactAction(input.action)
        || !POLICY_RESULTS.has(input.policy_result)
        || !iso(input.observed_at)) {
        throw new TypeError('authority_operations:operation_invalid');
    }
    validatePolicy(input.policy, input.action.action_type);
    const initial = deriveInitialState(input.policy, input.policy_result);
    const operation = {
        '@version': AUTHORITY_OPERATIONS_INTERFACE_VERSION,
        operation_id: input.operation_id,
        action: copy(input.action),
        action_digest: `sha256:${hashCanonical(input.action)}`,
        policy: copy(input.policy),
        policy_result: input.policy_result,
        authorization: {
            state: initial.authorization,
            required_evidence: copy(input.policy.required_evidence),
            accepted_evidence: [],
        },
        execution: {
            state: initial.execution,
            provider_attempt: 'NOT_ENTERED',
            outcome: 'NOT_ASSESSED',
            resulting_state: null,
        },
        control_state: 'ACTIVE',
        history: [],
    };
    event(operation, input.observed_at, 'ACTION_PROPOSED');
    if (initial.execution === 'AUTHORIZATION_REQUIRED') {
        event(operation, input.observed_at, 'AUTHORIZATION_REQUIRED', { reason: initial.reason || undefined });
    }
    else if (initial.execution === 'REFUSED') {
        event(operation, input.observed_at, 'ACTION_REFUSED', { reason: initial.reason || undefined });
    }
    else {
        event(operation, input.observed_at, 'ACTION_READY');
    }
    assertOperationIntegrity(operation);
    return operation;
}
function evidenceReason(operation, evidence) {
    if (!isPlainObject(evidence)
        || !safeIdentifier(evidence.evidence_type)
        || !safeIdentifier(evidence.role)
        || !DIGEST.test(evidence.evidence_digest || '')
        || !DIGEST.test(evidence.action_digest || '')
        || !['VERIFIED', 'REJECTED', 'INDETERMINATE'].includes(evidence.verification)
        || !Array.isArray(evidence.subjects)
        || evidence.subjects.some((subject) => !safeIdentifier(subject))) {
        return 'evidence_invalid';
    }
    if (evidence.action_digest !== operation.action_digest)
        return 'action_binding_mismatch';
    if (evidence.verification !== 'VERIFIED')
        return 'evidence_not_verified';
    const requirement = operation.authorization.required_evidence.find((candidate) => candidate.evidence_type === evidence.evidence_type && candidate.role === evidence.role);
    if (!requirement)
        return 'evidence_requirement_mismatch';
    if (new Set(evidence.subjects).size < requirement.minimum)
        return 'insufficient_distinct_subjects';
    return null;
}
function assertOperationIntegrity(value) {
    if (!isPlainObject(value)
        || value['@version'] !== AUTHORITY_OPERATIONS_INTERFACE_VERSION
        || !safeIdentifier(value.operation_id)
        || !exactAction(value.action)
        || !DIGEST.test(value.action_digest || '')
        || !POLICY_RESULTS.has(value.policy_result)
        || !['NOT_REQUIRED', 'REQUIRED', 'SATISFIED', 'INDETERMINATE'].includes(value.authorization?.state)
        || !Array.isArray(value.authorization?.required_evidence)
        || !Array.isArray(value.authorization?.accepted_evidence)
        || !['READY', 'AUTHORIZATION_REQUIRED', 'RESERVED', 'PROVIDER_ENTERED',
            'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE', 'REFUSED'].includes(value.execution?.state)
        || !['NOT_ENTERED', 'ENTERED'].includes(value.execution?.provider_attempt)
        || !['NOT_ASSESSED', 'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(value.execution?.outcome)
        || !['ACTIVE', 'FROZEN'].includes(value.control_state)) {
        throw new TypeError('authority_operations:operation_integrity_invalid');
    }
    validatePolicy(value.policy, value.action.action_type);
    if (`sha256:${hashCanonical(value.action)}` !== value.action_digest) {
        throw new TypeError('authority_operations:action_digest_mismatch');
    }
    if (!Array.isArray(value.history)
        || value.history.some((entry, index) => !isPlainObject(entry)
            || entry.sequence !== index + 1
            || !iso(entry.at)
            || !safeIdentifier(entry.type)
            || (index > 0 && Date.parse(entry.at) < Date.parse(value.history[index - 1].at)))) {
        throw new TypeError('authority_operations:history_invalid');
    }
}
function allRequirementsSatisfied(operation) {
    return operation.authorization.required_evidence.every((requirement) => operation.authorization.accepted_evidence.some((evidence) => evidence.evidence_type === requirement.evidence_type
        && evidence.role === requirement.role
        && new Set(evidence.subjects).size >= requirement.minimum));
}
export function presentAuthorizationEvidence(current, evidence, at) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    if (operation.execution.state !== 'AUTHORIZATION_REQUIRED'
        || operation.authorization.state !== 'REQUIRED'
        || operation.execution.provider_attempt !== 'NOT_ENTERED') {
        throw new Error('authority_operations:authorization_not_accepted_in_state');
    }
    const reason = evidenceReason(operation, evidence);
    if (reason) {
        event(operation, at, 'AUTHORIZATION_REJECTED', {
            reason,
            evidence_digest: DIGEST.test(evidence?.evidence_digest || '') ? evidence.evidence_digest : undefined,
        });
        return operation;
    }
    if (!operation.authorization.accepted_evidence.some((candidate) => candidate.evidence_digest === evidence.evidence_digest)) {
        operation.authorization.accepted_evidence.push(copy(evidence));
    }
    if (allRequirementsSatisfied(operation)) {
        operation.authorization.state = 'SATISFIED';
        operation.execution.state = 'READY';
    }
    event(operation, at, 'AUTHORIZATION_ACCEPTED', { evidence_digest: evidence.evidence_digest });
    return operation;
}
export function reserveAuthorityOperation(current, at) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    if (operation.control_state !== 'ACTIVE')
        throw new Error('authority_operations:control_domain_frozen');
    if (operation.execution.state !== 'READY' || operation.execution.provider_attempt !== 'NOT_ENTERED') {
        throw new Error('authority_operations:not_ready');
    }
    operation.execution.state = 'RESERVED';
    event(operation, at, 'AUTHORITY_RESERVED');
    return operation;
}
export function beginProviderEntry(current, at) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    if (operation.control_state !== 'ACTIVE')
        throw new Error('authority_operations:control_domain_frozen');
    if (operation.execution.state !== 'RESERVED' || operation.execution.provider_attempt !== 'NOT_ENTERED') {
        throw new Error('authority_operations:not_reserved');
    }
    operation.execution.state = 'PROVIDER_ENTERED';
    operation.execution.provider_attempt = 'ENTERED';
    event(operation, at, 'PROVIDER_ENTERED');
    return operation;
}
export function recordProviderOutcome(current, outcome, at) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    if (operation.execution.state !== 'PROVIDER_ENTERED'
        || operation.execution.provider_attempt !== 'ENTERED'
        || !isPlainObject(outcome)
        || !OUTCOMES.has(outcome.value)
        || (outcome.value !== 'INDETERMINATE' && !DIGEST.test(outcome.evidence_digest || ''))
        || (outcome.resulting_state !== null && !isPlainObject(outcome.resulting_state))) {
        throw new Error('authority_operations:provider_outcome_invalid');
    }
    operation.execution.state = outcome.value;
    operation.execution.outcome = outcome.value;
    operation.execution.resulting_state = copy(outcome.resulting_state);
    event(operation, at, 'PROVIDER_OUTCOME_RECORDED', {
        outcome: outcome.value,
        evidence_digest: outcome.evidence_digest || undefined,
    });
    return operation;
}
export function intervene(current, intervention, at) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    if (!isPlainObject(intervention)
        || !['CANCEL_BEFORE_ENTRY', 'FREEZE_NEW_ADMISSIONS'].includes(intervention.type)
        || !safeIdentifier(intervention.actor_id)
        || !safeIdentifier(intervention.reason)) {
        throw new TypeError('authority_operations:intervention_invalid');
    }
    if (intervention.type === 'CANCEL_BEFORE_ENTRY') {
        if (operation.execution.provider_attempt === 'ENTERED') {
            event(operation, at, 'INTERVENTION_REFUSED', {
                reason: 'provider_already_entered', actor_id: intervention.actor_id,
            });
            return operation;
        }
        operation.execution.state = 'REFUSED';
        event(operation, at, 'OPERATOR_CANCELLED', {
            reason: intervention.reason, actor_id: intervention.actor_id,
        });
        return operation;
    }
    operation.control_state = 'FROZEN';
    if (operation.execution.provider_attempt === 'NOT_ENTERED'
        && !['COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(operation.execution.state)) {
        operation.execution.state = 'REFUSED';
    }
    event(operation, at, 'NEW_ADMISSIONS_FROZEN', {
        reason: intervention.reason, actor_id: intervention.actor_id,
    });
    return operation;
}
function availableInterventions(operation) {
    const result = [];
    if (operation.execution.provider_attempt === 'NOT_ENTERED'
        && !['REFUSED', 'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE'].includes(operation.execution.state)) {
        result.push('cancel_before_entry');
    }
    if (operation.control_state === 'ACTIVE')
        result.push('freeze_new_admissions');
    if (operation.execution.state === 'PROVIDER_ENTERED' || operation.execution.state === 'INDETERMINATE') {
        result.push('reconcile');
    }
    return result;
}
export function projectAuthorityOperation(current) {
    assertOperationIntegrity(current);
    const operation = copy(current);
    const authorizationSignal = operation.authorization.state === 'REQUIRED'
        ? {
            code: 'additional_authorization_required',
            requirements: copy(operation.authorization.required_evidence),
        }
        : null;
    return {
        '@version': operation['@version'],
        operation_id: operation.operation_id,
        proposed_action: {
            action: copy(operation.action),
            action_digest: operation.action_digest,
        },
        autonomy: {
            policy_id: operation.policy.policy_id,
            policy_digest: operation.policy.policy_digest,
            evaluator_profile: operation.policy.evaluator_profile,
            configured_mode: operation.policy.mode,
            policy_result: operation.policy_result,
        },
        authorization: {
            state: operation.authorization.state,
            signal: authorizationSignal,
            accepted_evidence: copy(operation.authorization.accepted_evidence),
        },
        execution: {
            state: operation.execution.state,
            provider_attempt: operation.execution.provider_attempt,
            outcome: operation.execution.outcome,
            reconciliation_required: operation.execution.state === 'PROVIDER_ENTERED'
                || operation.execution.state === 'INDETERMINATE',
            retry_safe: false,
            resulting_state: copy(operation.execution.resulting_state),
        },
        management: {
            control_state: operation.control_state,
            available_interventions: availableInterventions(operation),
            limitations: [
                'This is a management projection. It does not issue authority or execute the action.',
                'A freeze blocks new admissions at covered boundaries; it does not stop computation or undo an entered effect.',
                'INDETERMINATE preserves an unknown provider outcome and never licenses a blind retry.',
            ],
        },
        history: copy(operation.history),
    };
}
