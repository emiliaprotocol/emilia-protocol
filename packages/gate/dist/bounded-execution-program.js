// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Signed, closed execution programs for bounded autonomous action.
 *
 * This module owns immutable program syntax and verification only. Runtime
 * reachability and attempt-budget transitions are enforced by a program-aware
 * AdmissionStore in the same linearizable execution-right domain.
 */
import { RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
export const BOUNDED_EXECUTION_PROGRAM_VERSION = 'EP-BOUNDED-EXECUTION-PROGRAM-v1';
export const EXECUTION_PROGRAM_CLAIM_BOUNDARY = 'typed_reachability_and_attempt_budget_not_intent_safety_effect_truth_or_complete_mediation';
export const EXECUTION_PROGRAM_LIMITS = Object.freeze({
    budgets: 64,
    nodes: 256,
    dependenciesPerNode: 64,
    chargesPerNode: 64,
    maxOccurrences: 1_000_000,
    maxTotalOccurrences: 1_000_000,
    maxBudget: Number.MAX_SAFE_INTEGER,
});
const PROGRAM_KEYS = [
    '@version', 'program_id', 'tenant_id', 'version', 'subject_id', 'audience',
    'objective_digest', 'authorization_digest', 'presentation_digest',
    'supersedes_program_digest', 'issued_at', 'valid_from', 'expires_at',
    'max_total_occurrences', 'budgets', 'nodes', 'claim_boundary',
];
const BUDGET_KEYS = ['budget_id', 'unit', 'limit'];
const NODE_KEYS = [
    'node_id', 'action', 'trust_program_digest', 'depends_on',
    'max_occurrences', 'charges',
];
const EXACT_ACTION_KEYS = ['mode', 'caid', 'action_digest'];
const PROFILE_ACTION_KEYS = ['mode', 'profile_id', 'profile_digest'];
const DEPENDENCY_KEYS = ['node_id', 'outcomes'];
const CHARGE_KEYS = ['budget_id', 'amount'];
const TERMINAL_DEPENDENCY_OUTCOMES = new Set(['COMMITTED', 'PROVEN_NOT_COMMITTED']);
function byteOrder(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function positiveInteger(value, max = Number.MAX_SAFE_INTEGER) {
    return Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= max;
}
function normalizeAction(value) {
    if (riskExact(value, EXACT_ACTION_KEYS) && value.mode === 'exact'
        && typeof value.caid === 'string' && RISK_CAID.test(value.caid)
        && typeof value.action_digest === 'string' && RISK_DIGEST.test(value.action_digest)) {
        return riskClone(value);
    }
    if (riskExact(value, PROFILE_ACTION_KEYS) && value.mode === 'profile'
        && riskIdentifier(value.profile_id)
        && typeof value.profile_digest === 'string' && RISK_DIGEST.test(value.profile_digest)) {
        return riskClone(value);
    }
    throw new TypeError('program action is invalid');
}
function normalizeBudgets(value) {
    if (!Array.isArray(value) || value.length < 1
        || value.length > EXECUTION_PROGRAM_LIMITS.budgets) {
        throw new TypeError('program budgets are invalid');
    }
    const seen = new Set();
    const budgets = value.map((entry) => {
        if (!riskExact(entry, BUDGET_KEYS)
            || !riskIdentifier(entry.budget_id)
            || !riskIdentifier(entry.unit)
            || !positiveInteger(entry.limit, EXECUTION_PROGRAM_LIMITS.maxBudget)) {
            throw new TypeError('program budget is invalid');
        }
        if (seen.has(entry.budget_id))
            throw new TypeError('program budget is duplicated');
        seen.add(entry.budget_id);
        return riskClone(entry);
    });
    return budgets.sort((left, right) => byteOrder(left.budget_id, right.budget_id));
}
function normalizeDependencies(value) {
    if (!Array.isArray(value) || value.length > EXECUTION_PROGRAM_LIMITS.dependenciesPerNode) {
        throw new TypeError('program dependencies are invalid');
    }
    const seen = new Set();
    const dependencies = value.map((entry) => {
        if (!riskExact(entry, DEPENDENCY_KEYS)
            || !riskIdentifier(entry.node_id)
            || !Array.isArray(entry.outcomes)
            || entry.outcomes.length < 1
            || entry.outcomes.length > TERMINAL_DEPENDENCY_OUTCOMES.size
            || !entry.outcomes.every((outcome) => (typeof outcome === 'string' && TERMINAL_DEPENDENCY_OUTCOMES.has(outcome)))) {
            throw new TypeError('program dependency is invalid');
        }
        if (seen.has(entry.node_id))
            throw new TypeError('program dependency is duplicated');
        seen.add(entry.node_id);
        const outcomes = [...entry.outcomes].sort();
        if (new Set(outcomes).size !== outcomes.length) {
            throw new TypeError('program dependency outcome is duplicated');
        }
        return { node_id: entry.node_id, outcomes };
    });
    return dependencies.sort((left, right) => byteOrder(left.node_id, right.node_id));
}
function normalizeCharges(value, budgets) {
    if (!Array.isArray(value) || value.length < 1
        || value.length > EXECUTION_PROGRAM_LIMITS.chargesPerNode) {
        throw new TypeError('program charges are invalid');
    }
    const seen = new Set();
    const charges = value.map((entry) => {
        if (!riskExact(entry, CHARGE_KEYS)
            || !riskIdentifier(entry.budget_id)
            || !positiveInteger(entry.amount, EXECUTION_PROGRAM_LIMITS.maxBudget)) {
            throw new TypeError('program charge is invalid');
        }
        const budget = budgets.get(entry.budget_id);
        if (!budget)
            throw new TypeError('program charge references an unknown budget');
        if (entry.amount > budget.limit)
            throw new TypeError('node charge exceeds its program budget');
        if (seen.has(entry.budget_id))
            throw new TypeError('program charge is duplicated');
        seen.add(entry.budget_id);
        return riskClone(entry);
    });
    return charges.sort((left, right) => byteOrder(left.budget_id, right.budget_id));
}
function ensureAcyclic(nodes) {
    const byId = new Map(nodes.map((node) => [node.node_id, node]));
    for (const node of nodes) {
        for (const dependency of node.depends_on) {
            if (!byId.has(dependency.node_id)) {
                throw new TypeError('program dependency references an unknown node');
            }
            if (dependency.node_id === node.node_id)
                throw new TypeError('program graph contains a cycle');
        }
    }
    const visiting = new Set();
    const visited = new Set();
    const visit = (nodeId) => {
        if (visiting.has(nodeId))
            throw new TypeError('program graph contains a cycle');
        if (visited.has(nodeId))
            return;
        visiting.add(nodeId);
        for (const dependency of byId.get(nodeId).depends_on)
            visit(dependency.node_id);
        visiting.delete(nodeId);
        visited.add(nodeId);
    };
    for (const node of nodes)
        visit(node.node_id);
    if (!nodes.some((node) => node.depends_on.length === 0)) {
        throw new TypeError('program graph contains no root');
    }
}
function normalizeProgram(input) {
    if (!riskRecord(input))
        throw new TypeError('program shape is invalid');
    if (!Object.hasOwn(input, 'max_total_occurrences')) {
        throw new TypeError('program occurrence ceiling is invalid');
    }
    if (!riskExact(input, [
        'program_id', 'tenant_id', 'version', 'subject_id', 'audience',
        'objective_digest', 'authorization_digest', 'presentation_digest',
        'supersedes_program_digest', 'issued_at', 'valid_from', 'expires_at',
        'max_total_occurrences', 'budgets', 'nodes',
    ]))
        throw new TypeError('program shape is invalid');
    if (!riskIdentifier(input.program_id)
        || !riskIdentifier(input.tenant_id)
        || !positiveInteger(input.version)
        || !riskIdentifier(input.subject_id)
        || !riskIdentifier(input.audience)
        || !RISK_DIGEST.test(input.objective_digest)
        || !RISK_DIGEST.test(input.authorization_digest)
        || !RISK_DIGEST.test(input.presentation_digest)
        || (input.supersedes_program_digest !== null
            && !RISK_DIGEST.test(input.supersedes_program_digest))) {
        throw new TypeError('program identity binding is invalid');
    }
    if ((input.version === 1 && input.supersedes_program_digest !== null)
        || (input.version > 1 && input.supersedes_program_digest === null)) {
        throw new TypeError('program supersession binding is invalid');
    }
    if (!positiveInteger(input.max_total_occurrences, EXECUTION_PROGRAM_LIMITS.maxTotalOccurrences)) {
        throw new TypeError('program occurrence ceiling is invalid');
    }
    const issued = riskInstant(input.issued_at);
    const active = riskInstant(input.valid_from);
    const expires = riskInstant(input.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(active) || !Number.isFinite(expires)
        || issued > active || expires <= active) {
        throw new TypeError('program validity window is invalid');
    }
    const budgets = normalizeBudgets(input.budgets);
    const budgetsById = new Map(budgets.map((budget) => [budget.budget_id, budget]));
    if (!Array.isArray(input.nodes) || input.nodes.length < 1
        || input.nodes.length > EXECUTION_PROGRAM_LIMITS.nodes) {
        throw new TypeError('program nodes are invalid');
    }
    const nodeIds = new Set();
    const nodes = input.nodes.map((entry) => {
        if (!riskExact(entry, NODE_KEYS)
            || !riskIdentifier(entry.node_id)
            || !RISK_DIGEST.test(entry.trust_program_digest)
            || !positiveInteger(entry.max_occurrences, EXECUTION_PROGRAM_LIMITS.maxOccurrences)) {
            throw new TypeError('program node is invalid');
        }
        if (nodeIds.has(entry.node_id))
            throw new TypeError('program node is duplicated');
        nodeIds.add(entry.node_id);
        return {
            node_id: entry.node_id,
            action: normalizeAction(entry.action),
            trust_program_digest: entry.trust_program_digest,
            depends_on: normalizeDependencies(entry.depends_on),
            max_occurrences: entry.max_occurrences,
            charges: normalizeCharges(entry.charges, budgetsById),
        };
    }).sort((left, right) => byteOrder(left.node_id, right.node_id));
    ensureAcyclic(nodes);
    return {
        program_id: input.program_id,
        tenant_id: input.tenant_id,
        version: input.version,
        subject_id: input.subject_id,
        audience: input.audience,
        objective_digest: input.objective_digest,
        authorization_digest: input.authorization_digest,
        presentation_digest: input.presentation_digest,
        supersedes_program_digest: input.supersedes_program_digest,
        issued_at: new Date(issued).toISOString(),
        valid_from: new Date(active).toISOString(),
        expires_at: new Date(expires).toISOString(),
        max_total_occurrences: input.max_total_occurrences,
        budgets,
        nodes,
    };
}
function validatePayload(value) {
    if (!riskExact(value, PROGRAM_KEYS)
        || value['@version'] !== BOUNDED_EXECUTION_PROGRAM_VERSION
        || value.claim_boundary !== EXECUTION_PROGRAM_CLAIM_BOUNDARY) {
        throw new TypeError('program payload is invalid');
    }
    const normalized = normalizeProgram(Object.fromEntries(Object.entries(value).filter(([key]) => !['@version', 'claim_boundary'].includes(key))));
    if (riskDigest(normalized) !== riskDigest(Object.fromEntries(Object.entries(value).filter(([key]) => !['@version', 'claim_boundary'].includes(key)))))
        throw new TypeError('program payload is not canonical');
}
export function signBoundedExecutionProgram(input, signer) {
    const normalized = normalizeProgram(input);
    const body = {
        '@version': BOUNDED_EXECUTION_PROGRAM_VERSION,
        ...normalized,
        claim_boundary: EXECUTION_PROGRAM_CLAIM_BOUNDARY,
    };
    validatePayload(body);
    return signRiskBody(BOUNDED_EXECUTION_PROGRAM_VERSION, body, signer);
}
export function executionProgramDigest(artifact) {
    if (!riskRecord(artifact))
        throw new TypeError('program artifact is invalid');
    const { proof: _proof, ...body } = artifact;
    return riskDigest(body);
}
export function verifyBoundedExecutionProgram(artifact, options = {}) {
    const refuse = (reason, verified = false, programDigest = null) => ({
        accepted: false,
        verified,
        reason,
        program_digest: programDigest,
        program: null,
        claim_boundary: EXECUTION_PROGRAM_CLAIM_BOUNDARY,
    });
    const signed = verifyRiskBody(artifact, BOUNDED_EXECUTION_PROGRAM_VERSION, options.trusted_keys);
    if (!signed.valid || !signed.body) {
        return refuse(signed.reason === 'issuer_untrusted' ? 'program_issuer_untrusted' : 'program_signature_invalid');
    }
    const { issuer, ...payload } = signed.body;
    try {
        validatePayload(payload);
    }
    catch {
        return refuse('program_schema_invalid', true, signed.body.proof?.body_digest ?? riskDigest(signed.body));
    }
    const programDigest = executionProgramDigest(artifact);
    if (options.expected_program_id === undefined
        || options.expected_tenant_id === undefined
        || options.expected_authorizer_id === undefined
        || options.expected_authorization_digest === undefined
        || options.expected_audience === undefined) {
        return refuse('context_binding_required', true, programDigest);
    }
    if (issuer.id !== options.expected_authorizer_id) {
        return refuse('authorizer_mismatch', true, programDigest);
    }
    if (payload.program_id !== options.expected_program_id) {
        return refuse('program_id_mismatch', true, programDigest);
    }
    if (payload.tenant_id !== options.expected_tenant_id) {
        return refuse('tenant_mismatch', true, programDigest);
    }
    if (payload.authorization_digest !== options.expected_authorization_digest) {
        return refuse('authorization_mismatch', true, programDigest);
    }
    if (payload.audience !== options.expected_audience) {
        return refuse('audience_mismatch', true, programDigest);
    }
    const now = options.now === undefined
        ? Date.now()
        : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
    if (!Number.isFinite(now))
        return refuse('verification_time_invalid', true, programDigest);
    if (now < riskInstant(payload.valid_from))
        return refuse('program_not_active', true, programDigest);
    if (now >= riskInstant(payload.expires_at))
        return refuse('program_expired', true, programDigest);
    return {
        accepted: true,
        verified: true,
        reason: null,
        program_digest: programDigest,
        program: riskFreeze(riskClone(payload)),
        authorizer_id: issuer.id,
        claim_boundary: EXECUTION_PROGRAM_CLAIM_BOUNDARY,
    };
}
//# sourceMappingURL=bounded-execution-program.js.map