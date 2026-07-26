// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Closed composition profile for bounded autonomous execution.
 *
 * This is a compiler/validator over existing EMILIA primitives. It is not a
 * scheduler, goal generator, natural-language entailment oracle, receipt
 * format, or second Trust Program engine.
 */
import { hashCanonical } from './execution-binding.js';
import { TRUST_PROGRAM_VERSION } from './trust-program.js';
export const AUTONOMY_CONTROL_PLANE_VERSION = 'EP-GATE-AUTONOMY-CONTROL-PLANE-PROFILE-v1';
export const AUTONOMY_ROOT_EVIDENCE_TYPE = 'ep-root-objective';
export const AUTONOMY_FITNESS_EVIDENCE_TYPE = 'agent-fitness-report';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,255}$/;
const PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\u007f]{1,1024}$/;
const HUMAN_EVIDENCE = new Set(['ep-class-a-signoff', 'ep-quorum']);
const PHASES = new Set(['execute', 'canary', 'promote', 'rollback']);
const TOP_KEYS = new Set(['@version', 'control_plane_id', 'version', 'valid_from', 'expires_at', 'root', 'status', 'children']);
const ROOT_KEYS = new Set(['objective_id', 'root_caid', 'action_digest', 'actions', 'audiences', 'budget', 'expires_at', 'initiator_id', 'authorization']);
const AUTH_KEYS = new Set(['evidence_type', 'verifier_profile', 'policy_digest', 'max_age_sec', 'require_initiator_exclusion']);
const STATUS_KEYS = new Set(['verifier_profile', 'policy_digest', 'max_age_sec']);
const CHILD_KEYS = new Set(['goal_id', 'parent_goal_id', 'phase', 'caid', 'action_digest', 'action_type', 'audience', 'budget', 'expires_at', 'capability_template_digest', 'proposer_id', 'evaluator_id', 'executor_id', 'change', 'fitness', 'canary', 'rollback']);
const BUDGET_KEYS = new Set(['cents', 'calls']);
const CHANGE_KEYS = new Set(['before_digest', 'after_digest', 'changed_paths']);
const FITNESS_KEYS = new Set(['suite_digest', 'environment_digest', 'policy_digest', 'max_age_sec']);
const CANARY_KEYS = new Set(['exposure_percent', 'max_exposure_percent', 'policy_digest', 'max_age_sec']);
const PROMOTION_CANARY_KEYS = new Set(['goal_id', 'exposure_percent', 'max_exposure_percent', 'policy_digest', 'max_age_sec']);
const ROLLBACK_KEYS = new Set(['original_caid', 'authorization_policy_digest']);
export class AutonomyControlPlaneValidationError extends TypeError {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'AutonomyControlPlaneValidationError';
        this.code = code;
    }
}
function refuse(code, message) {
    throw new AutonomyControlPlaneValidationError(code, message);
}
function isRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exact(value, keys) {
    return isRecord(value)
        && Reflect.ownKeys(value).every((key) => typeof key === 'string')
        && Object.keys(value).length === keys.size
        && Object.keys(value).every((key) => keys.has(key));
}
function identifier(value) {
    return typeof value === 'string' && ID.test(value);
}
function digest(value) {
    return typeof value === 'string' && DIGEST.test(value);
}
function caid(value) {
    return typeof value === 'string' && CAID.test(value);
}
function instant(value) {
    if (typeof value !== 'string'
        || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
        return NaN;
    return Date.parse(value);
}
function exactIdentifiers(value) {
    return Array.isArray(value) && value.length > 0 && value.length <= 256
        && value.every(identifier) && new Set(value).size === value.length;
}
function validBudget(value) {
    return exact(value, BUDGET_KEYS)
        && Number.isSafeInteger(value.cents) && value.cents >= 0
        && Number.isSafeInteger(value.calls) && value.calls >= 0;
}
function validFreshness(value) {
    return Number.isSafeInteger(value) && value >= 1 && value <= 31_536_000;
}
function canonicalDigest(value) {
    return `sha256:${hashCanonical(value)}`;
}
function validateShape(profile) {
    if (!exact(profile, TOP_KEYS)
        || profile['@version'] !== AUTONOMY_CONTROL_PLANE_VERSION
        || !identifier(profile.control_plane_id)
        || !Number.isSafeInteger(profile.version) || profile.version < 1
        || !Number.isFinite(instant(profile.valid_from))
        || !Number.isFinite(instant(profile.expires_at))
        || instant(profile.expires_at) <= instant(profile.valid_from)
        || !exact(profile.root, ROOT_KEYS)
        || !exact(profile.root.authorization, AUTH_KEYS)
        || !exact(profile.root.budget, BUDGET_KEYS)
        || !exact(profile.status, STATUS_KEYS)
        || !Array.isArray(profile.children) || profile.children.length < 1 || profile.children.length > 64
        || profile.children.some((child) => !exact(child, CHILD_KEYS))) {
        refuse('profile_shape_invalid', 'autonomy profile is not a closed, bounded v1 object');
    }
}
function validateRoot(profile) {
    const root = profile.root;
    const authorization = root.authorization;
    if (!identifier(root.objective_id) || !caid(root.root_caid) || !digest(root.action_digest)
        || !exactIdentifiers(root.actions) || !exactIdentifiers(root.audiences)
        || !validBudget(root.budget) || !identifier(root.initiator_id)
        || !Number.isFinite(instant(root.expires_at))
        || instant(root.expires_at) > instant(profile.expires_at)) {
        refuse('root_authority_invalid', 'root objective authority is invalid');
    }
    if (!HUMAN_EVIDENCE.has(authorization.evidence_type)
        || !identifier(authorization.verifier_profile) || !digest(authorization.policy_digest)
        || !validFreshness(authorization.max_age_sec)
        || typeof authorization.require_initiator_exclusion !== 'boolean'
        || (authorization.evidence_type === 'ep-quorum' && authorization.require_initiator_exclusion !== true)) {
        refuse('root_human_authorization_required', 'root objective requires Class-A or initiator-excluding quorum human evidence');
    }
    if (!identifier(profile.status.verifier_profile) || !digest(profile.status.policy_digest)
        || !validFreshness(profile.status.max_age_sec)) {
        refuse('status_policy_invalid', 'a fresh suspension and revocation status policy is required');
    }
}
function validateChildShape(child) {
    if (!identifier(child.goal_id) || !identifier(child.parent_goal_id) || !PHASES.has(child.phase)
        || !caid(child.caid) || !digest(child.action_digest) || !identifier(child.action_type)
        || !identifier(child.audience) || !validBudget(child.budget)
        || !Number.isFinite(instant(child.expires_at)) || !digest(child.capability_template_digest)
        || !identifier(child.proposer_id) || !identifier(child.evaluator_id) || !identifier(child.executor_id)) {
        refuse('child_shape_invalid', `child ${String(child.goal_id)} is invalid`);
    }
    if (new Set([child.proposer_id, child.evaluator_id, child.executor_id]).size !== 3) {
        refuse('independent_roles_required', `child ${child.goal_id} collapses proposer, evaluator, or executor`);
    }
    if (!exact(child.change, CHANGE_KEYS) || !digest(child.change.before_digest)
        || !digest(child.change.after_digest) || child.change.before_digest === child.change.after_digest
        || !Array.isArray(child.change.changed_paths) || child.change.changed_paths.length < 1
        || child.change.changed_paths.length > 512 || !child.change.changed_paths.every((entry) => typeof entry === 'string' && PATH.test(entry))
        || new Set(child.change.changed_paths).size !== child.change.changed_paths.length
        || !child.change.changed_paths.every((entry, index) => index === 0 || child.change.changed_paths[index - 1] < entry)) {
        refuse('change_binding_invalid', `child ${child.goal_id} requires exact before, after, and sorted changed-path bindings`);
    }
    if (!exact(child.fitness, FITNESS_KEYS) || !digest(child.fitness.suite_digest)
        || !digest(child.fitness.environment_digest) || !digest(child.fitness.policy_digest)
        || !validFreshness(child.fitness.max_age_sec)) {
        refuse('fitness_policy_invalid', `child ${child.goal_id} requires pinned, freshness-bounded fitness evidence`);
    }
}
function validateCanary(child, childrenById) {
    if (child.phase === 'promote') {
        if (!exact(child.canary, PROMOTION_CANARY_KEYS) || !identifier(child.canary.goal_id)) {
            refuse('promotion_requires_canary', `promotion ${child.goal_id} has no pinned canary predecessor`);
        }
        const predecessor = childrenById.get(child.canary.goal_id);
        if (!predecessor || predecessor.phase !== 'canary'
            || predecessor.change.before_digest !== child.change.before_digest
            || predecessor.change.after_digest !== child.change.after_digest
            || JSON.stringify(predecessor.change.changed_paths) !== JSON.stringify(child.change.changed_paths)) {
            refuse('promotion_requires_canary', `promotion ${child.goal_id} does not bind the same change as a canary child`);
        }
    }
    else if (child.phase === 'canary') {
        if (!exact(child.canary, CANARY_KEYS)) {
            refuse('canary_policy_invalid', `canary ${child.goal_id} requires a closed exposure policy`);
        }
    }
    else if (child.canary !== null) {
        refuse('canary_policy_invalid', `non-canary child ${child.goal_id} must not carry canary authority`);
    }
    if (child.canary !== null) {
        if (!Number.isInteger(child.canary.exposure_percent) || child.canary.exposure_percent < 1
            || child.canary.exposure_percent > 100
            || !Number.isInteger(child.canary.max_exposure_percent) || child.canary.max_exposure_percent < 1
            || child.canary.max_exposure_percent > 100
            || child.canary.exposure_percent > child.canary.max_exposure_percent
            || !digest(child.canary.policy_digest) || !validFreshness(child.canary.max_age_sec)) {
            refuse('canary_exposure_exceeded', `canary ${child.goal_id} exceeds its pinned exposure ceiling`);
        }
    }
}
function validateGraph(profile) {
    const children = profile.children;
    const byId = new Map();
    const caids = new Set();
    for (const child of children) {
        validateChildShape(child);
        if (byId.has(child.goal_id) || caids.has(child.caid)) {
            refuse('child_identity_replayed', 'child goal ids and CAIDs must be unique');
        }
        byId.set(child.goal_id, child);
        caids.add(child.caid);
    }
    const visiting = new Set();
    const visited = new Set();
    const visit = (id) => {
        if (visiting.has(id))
            refuse('child_goal_cycle', 'child goal derivation must be acyclic');
        if (visited.has(id))
            return;
        const child = byId.get(id);
        if (!child)
            refuse('child_parent_missing', `unknown child goal ${id}`);
        visiting.add(id);
        if (child.parent_goal_id !== 'root') {
            if (!byId.has(child.parent_goal_id))
                refuse('child_parent_missing', `unknown parent ${child.parent_goal_id}`);
            visit(child.parent_goal_id);
        }
        visiting.delete(id);
        visited.add(id);
    };
    for (const id of byId.keys())
        visit(id);
    return byId;
}
function validateAuthority(profile, byId) {
    const root = profile.root;
    const groups = new Map();
    for (const child of byId.values()) {
        const parent = child.parent_goal_id === 'root' ? root : byId.get(child.parent_goal_id);
        const parentActions = child.parent_goal_id === 'root' ? parent.actions : [parent.action_type];
        const parentAudiences = child.parent_goal_id === 'root' ? parent.audiences : [parent.audience];
        if (!parentActions.includes(child.action_type) || !parentAudiences.includes(child.audience)
            || child.budget.cents > parent.budget.cents || child.budget.calls > parent.budget.calls
            || instant(child.expires_at) > instant(parent.expires_at)) {
            refuse('child_authority_widening', `child ${child.goal_id} exceeds parent authority`);
        }
        const siblings = groups.get(child.parent_goal_id) ?? [];
        siblings.push(child);
        groups.set(child.parent_goal_id, siblings);
    }
    for (const [parentId, siblings] of groups) {
        const parent = parentId === 'root' ? root : byId.get(parentId);
        const cents = siblings.reduce((sum, child) => sum + child.budget.cents, 0);
        const calls = siblings.reduce((sum, child) => sum + child.budget.calls, 0);
        if (!Number.isSafeInteger(cents) || !Number.isSafeInteger(calls)
            || cents > parent.budget.cents || calls > parent.budget.calls) {
            refuse('aggregate_sibling_budget_exceeded', `children of ${parentId} exceed aggregate authority`);
        }
    }
}
function validatePhases(profile, byId) {
    for (const child of byId.values()) {
        validateCanary(child, byId);
        if (child.phase === 'rollback') {
            if (!exact(child.rollback, ROLLBACK_KEYS) || !caid(child.rollback.original_caid)
                || !digest(child.rollback.authorization_policy_digest)
                || child.rollback.original_caid === child.caid
                || ![...byId.values()].some((candidate) => candidate.caid === child.rollback.original_caid)) {
                refuse('rollback_requires_new_authority', `rollback ${child.goal_id} requires a new CAID and authorization policy`);
            }
        }
        else if (child.rollback !== null) {
            refuse('rollback_requires_new_authority', `non-rollback child ${child.goal_id} must not carry rollback semantics`);
        }
    }
}
function requirement(requirementId, evidenceType, verifierProfile, policyDigest, maxAgeSec, revocationRequired) {
    return { requirement_id: requirementId, evidence_type: evidenceType, verifier_profile: verifierProfile, policy_digest: policyDigest, max_age_sec: maxAgeSec, revocation_required: revocationRequired };
}
function compileProgram(profile, child, index) {
    const rootPolicy = canonicalDigest({
        version: AUTONOMY_CONTROL_PLANE_VERSION,
        objective_id: profile.root.objective_id,
        root_caid: profile.root.root_caid,
        root_action_digest: profile.root.action_digest,
        child_goal_id: child.goal_id,
        child_caid: child.caid,
        child_action_digest: child.action_digest,
        authorization_policy_digest: profile.root.authorization.policy_digest,
        require_initiator_exclusion: profile.root.authorization.require_initiator_exclusion,
    });
    const allocationPolicy = canonicalDigest({
        authority_head_required: true, authority_epoch_required: true,
        parent_goal_id: child.parent_goal_id, action_type: child.action_type, audience: child.audience,
        budget: child.budget, expires_at: child.expires_at, capability_template_digest: child.capability_template_digest,
    });
    const stages = [
        {
            stage_id: 'root-objective', depends_on: [],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('human-root-objective', AUTONOMY_ROOT_EVIDENCE_TYPE, profile.root.authorization.verifier_profile, rootPolicy, profile.root.authorization.max_age_sec, true)],
        },
        {
            stage_id: 'authority-containment', depends_on: ['root-objective'],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('bounded-child-authority', 'ep-authority-allocation', 'ep-authority-allocation:v1', allocationPolicy, profile.status.max_age_sec, true)],
        },
        {
            stage_id: 'exact-change', depends_on: ['authority-containment'],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('exact-before-after-diff', 'ep-execution-binding', 'ep-execution-binding:v1', canonicalDigest(child.change), profile.status.max_age_sec, false)],
        },
        {
            stage_id: 'fitness', depends_on: ['exact-change'],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('task-fitness', AUTONOMY_FITNESS_EVIDENCE_TYPE, 'agent-fitness-bench:v1', child.fitness.policy_digest, child.fitness.max_age_sec, true)],
        },
        {
            stage_id: 'status-current', depends_on: ['fitness'],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('not-suspended-or-revoked', 'ep-autonomy-status', profile.status.verifier_profile, profile.status.policy_digest, profile.status.max_age_sec, true)],
        },
    ];
    let terminal = 'status-current';
    if (child.canary !== null) {
        stages.push({
            stage_id: 'canary-evidence', depends_on: [terminal],
            rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
            requirements: [requirement('bounded-canary', 'ep-canary-result', 'ep-canary-result:v1', child.canary.policy_digest, child.canary.max_age_sec, true)],
        });
        terminal = 'canary-evidence';
    }
    if (child.phase === 'rollback') {
        stages.push({
            stage_id: 'rollback-authorization', depends_on: [terminal],
            rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
            requirements: [requirement('new-rollback-authorization', 'ep-class-a-or-quorum', 'ep-human-authorization:v1', child.rollback.authorization_policy_digest, profile.root.authorization.max_age_sec, true)],
        });
        terminal = 'rollback-authorization';
    }
    return {
        '@version': TRUST_PROGRAM_VERSION,
        program_id: `acp.${profile.control_plane_id}.${String(index + 1).padStart(2, '0')}`,
        version: profile.version,
        root_caid: child.caid,
        action_digest: child.action_digest,
        valid_from: profile.valid_from,
        expires_at: child.expires_at,
        stages,
        execution: {
            depends_on: [terminal], consequence_mode: 'receipt-program',
            capability_template_digest: child.capability_template_digest, escrow_profile_digest: null,
        },
    };
}
export function compileAutonomyControlPlaneProfile(value) {
    validateShape(value);
    validateRoot(value);
    const byId = validateGraph(value);
    validateAuthority(value, byId);
    validatePhases(value, byId);
    const programs = value.children.map((child, index) => compileProgram(value, child, index));
    return {
        version: AUTONOMY_CONTROL_PLANE_VERSION,
        profile_digest: canonicalDigest(value),
        control_plane_id: value.control_plane_id,
        programs,
        claim_boundary: 'Typed action, audience, budget, expiry, diff, role, fitness, canary, status, and rollback bindings are validated. Natural-language goal entailment, human understanding, provider truth, and deployment completeness are not established.',
    };
}
//# sourceMappingURL=autonomy-control-plane-profile.js.map