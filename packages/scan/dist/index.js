// SPDX-License-Identifier: Apache-2.0
//
// @emilia-protocol/scan — the integration-overhead collapser.
//
// Point it at the actions an AI app/agent can take (MCP tools, an OpenAPI spec,
// or a plain list) and it does three things, in this order, and NEVER more:
//   1. SCAN     — enumerate the actions it can see.
//   2. CLASSIFY — propose which are consequential enough to require a human
//                 authorization receipt, mapped to an assurance tier, using the
//                 same EP risk packs the Gate ships. Anything it cannot classify
//                 that looks like it mutates state defaults to FAIL-CLOSED
//                 (receipt required) and is flagged for you to confirm.
//   3. REPORT   — emit a proposed agent-action-control manifest, the wrap you add
//                 at your tool-call choke point, and an HONEST coverage report
//                 that names what it could NOT see.
//
// It does NOT decide your risk model (that semantic call is yours; it proposes,
// you confirm), it does NOT silently edit your code, and it NEVER reports that an
// app is "protected." It reduces the plumbing to near-zero and makes the one
// irreducible step — declaring which actions need a human — a review, not a
// research project.
import { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS, createDefaultActionRiskManifest } from '../risk-packs.js';
const MAX_ACTIONS = 10_000;
const SOURCE_CONFUSING_NAME = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const RESERVED_OBJECT_NAMES = new Set(['__proto__', 'prototype', 'constructor']);
// Keyword signals per risk category, keyed to the EP risk-pack ids so a matched
// action inherits that pack's assurance_class, required_fields, and rationale.
// Deliberately conservative: strong verbs/nouns only, so a match is defensible.
const CATEGORY_SIGNALS = [
    // A bank target is not itself a change. Require both the affected banking
    // concept and explicit mutation intent so an outgoing wire to a beneficiary
    // stays money movement while updateBeneficiaryBankDetails lands here.
    {
        pack: 'money_movement.bank_details_change',
        any: ['bank_detail', 'bankdetail', 'payee', 'beneficiary', 'routing', 'ach_detail', 'payroll_account', 'vendor_account', 'account_number', 'iban'],
        requiresAny: ['change', 'update', 'set', 'modify', 'edit', 'replace', 'add', 'create', 'register'],
    },
    { pack: 'money_movement.release', any: ['payment', 'wire', 'transfer', 'remit', 'disburse', 'payout', 'send_money', 'sendmoney', 'settle', 'refund', 'charge', 'invoice_pay', 'pay'] },
    { pack: 'production.deploy', any: ['deploy', 'release_prod', 'rollout', 'ship_prod', 'promote', 'publish_release', 'terraform_apply', 'infra_apply', 'production_push'] },
    { pack: 'permissions.admin_change', any: ['grant', 'role', 'privilege', 'permission', 'entitlement', 'iam', 'make_admin', 'add_admin', 'assign_role', 'elevate', 'sudo_grant'] },
    { pack: 'data.bulk_export', any: ['export', 'download_all', 'bulk_export', 'dump', 'extract_pii', 'data_export', 'exfil', 'share_dataset', 'send_records'] },
    { pack: 'records.delete', any: ['delete', 'remove', 'purge', 'destroy', 'drop_table', 'wipe', 'erase', 'hard_delete'] },
    { pack: 'regulated.decision_override', any: ['override', 'adjudicate', 'dispose', 'approve_case', 'final_decision', 'waive', 'exception_approve'] },
];
// This policy is intentionally data-shaped and exported so reviewers can audit
// the lexical boundary without reverse-engineering control flow. Its precedence
// is security-significant: a read word is evidence only when it is the leading
// action verb, and any state-change signal, write method, or hybrid-operation
// marker wins before pass-through is considered.
export const CLASSIFICATION_POLICY = Object.freeze({
    readOnlyLeadingSignals: Object.freeze([
        'get', 'list', 'read', 'search', 'lookup', 'fetch', 'query', 'describe',
        'view', 'count', 'status', 'summary', 'summarize', 'preview', 'health', 'ping',
    ]),
    stateChangeSignals: Object.freeze([
        'create', 'update', 'set', 'write', 'post', 'put', 'patch', 'modify', 'edit',
        'add', 'remove', 'send', 'submit', 'execute', 'run', 'apply', 'trigger',
        'cancel', 'revoke', 'issue', 'replace', 'register', 'unregister', 'delete',
        'destroy', 'purge', 'erase', 'archive', 'rotate', 'rename', 'move', 'copy',
        'upload', 'import', 'publish', 'unpublish', 'enable', 'disable', 'activate',
        'deactivate', 'start', 'stop', 'restart', 'reset', 'restore', 'invite',
        'assign', 'unassign', 'approve', 'reject', 'accept', 'deny', 'lock', 'unlock',
        'merge', 'commit', 'save', 'schedule', 'reschedule', 'close', 'open',
        'increment', 'decrement',
    ]),
    hybridOperationMarkers: Object.freeze(['and', 'then', 'before', 'after', 'while', 'plus']),
    writeMethods: Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']),
    precedence: Object.freeze([
        'risk_category',
        'destructive_annotation',
        'state_change_or_write_method',
        'hybrid_operation_ambiguity',
        'leading_read_signal',
        'fail_closed_default',
    ]),
});
const packById = Object.fromEntries(HIGH_RISK_ACTION_PACKS.map((p) => [p.id, p]));
function norm(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_');
}
function semanticNorm(s) {
    return String(s || '')
        .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_');
}
function semanticTokens(s) {
    return semanticNorm(s).split('_').filter(Boolean);
}
function hasWholeSignal(hay, signal) {
    return `_${hay}_`.includes(`_${signal}_`);
}
// Classify ONE action. Returns a proposed control with an explicit reason and
// confidence, or a fail-closed "unclassified" when it mutates but doesn't match.
export function classifyAction(action) {
    if (!action || typeof action !== 'object' || Array.isArray(action)) {
        return { decision: 'review_fail_closed', receipt_required: true, assurance_class: 'class_a', reason: 'malformed action — defaults to require a receipt', confidence: 'low' };
    }
    const candidate = action;
    const nameTokens = semanticTokens(candidate.name);
    const descriptionTokens = semanticTokens(candidate.description);
    const semanticTokensCombined = [...nameTokens, ...descriptionTokens];
    const hay = semanticTokensCombined.join('_');
    const ann = candidate.annotations && typeof candidate.annotations === 'object' && !Array.isArray(candidate.annotations)
        ? candidate.annotations : {};
    const cat = matchCategory(hay);
    // Semantic risk signals outrank presenter-authored annotations. A payment or
    // delete tool cannot label itself read-only and bypass review.
    if (cat) {
        const pack = packById[cat.pack];
        return {
            decision: 'gate',
            receipt_required: true,
            category: cat.pack,
            label: pack?.label,
            assurance_class: pack?.assurance_class || 'class_a',
            required_fields: pack?.execution_binding?.required_fields || ['action_type'],
            why: pack?.why,
            reason: `matched category "${cat.pack}" on token "${cat.hit}"${ann.readOnlyHint === true ? '; conflicting readOnlyHint ignored' : ''}`,
            confidence: 'medium',
        };
    }
    if (ann.destructiveHint === true) {
        return { decision: 'gate', receipt_required: true, assurance_class: 'class_a', category: 'annotated_destructive', reason: 'annotation:destructiveHint', confidence: 'high' };
    }
    const leadingReadSignal = CLASSIFICATION_POLICY.readOnlyLeadingSignals.find((signal) => (nameTokens[0] === signal));
    const readSignal = semanticTokensCombined.find((token) => (CLASSIFICATION_POLICY.readOnlyLeadingSignals.includes(token)));
    const stateChangeSignal = semanticTokensCombined.find((token) => (CLASSIFICATION_POLICY.stateChangeSignals.includes(token)));
    const writeMethod = CLASSIFICATION_POLICY.writeMethods.includes(String(candidate.http_method || '').toUpperCase()) ? String(candidate.http_method).toUpperCase() : undefined;
    const hybridMarker = readSignal
        ? semanticTokensCombined.find((token) => CLASSIFICATION_POLICY.hybridOperationMarkers.includes(token))
        : undefined;
    if (stateChangeSignal || writeMethod) {
        const evidence = stateChangeSignal
            ? `state-change signal "${stateChangeSignal}"`
            : `write method "${writeMethod}"`;
        return {
            decision: 'review_fail_closed',
            receipt_required: true,
            assurance_class: 'class_a',
            reason: `${evidence} outranks read-only words — defaults to require a receipt; confirm or downgrade`,
            confidence: 'low',
        };
    }
    if (hybridMarker) {
        return {
            decision: 'review_fail_closed',
            receipt_required: true,
            assurance_class: 'class_a',
            reason: `hybrid operation marker "${hybridMarker}" makes read-only semantics ambiguous — defaults to require a receipt`,
            confidence: 'low',
        };
    }
    if (leadingReadSignal) {
        return {
            decision: 'pass_through',
            receipt_required: false,
            reason: ann.readOnlyHint === true
                ? `leading read-only verb "${leadingReadSignal}" plus advisory readOnlyHint; confirm handler behavior`
                : `leading read-only verb "${leadingReadSignal}", no higher-precedence mutation or ambiguity signal; confirm handler behavior`,
            confidence: 'low',
        };
    }
    return {
        decision: 'review_fail_closed',
        receipt_required: true,
        assurance_class: 'class_a',
        reason: readSignal
            ? `read-only signal "${readSignal}" is not the leading action verb — ambiguous and defaulted to require a receipt`
            : ann.readOnlyHint === true
                ? 'readOnlyHint is advisory and no independent read-only signal was found — defaults to require a receipt'
                : 'no strong read-only signal — defaults to require a receipt; confirm or downgrade',
        confidence: 'low',
    };
}
function matchCategory(hay) {
    for (const cat of CATEGORY_SIGNALS) {
        const hit = cat.any.find((k) => k === 'pay' ? hasWholeSignal(hay, k) : hay.includes(k));
        const requiredSignals = 'requiresAny' in cat && Array.isArray(cat.requiresAny)
            ? cat.requiresAny
            : undefined;
        const requiredHit = requiredSignals?.find((k) => hasWholeSignal(hay, k));
        if (hit && (!requiredSignals || requiredHit)) {
            return { pack: cat.pack, hit: requiredHit ? `${requiredHit}+${hit}` : hit };
        }
    }
    return null;
}
// Scan a list of actions -> full report. Actions: [{name, description?, annotations?, http_method?}].
export function scanActions(actions, { source = 'list', blindSpots = [] } = {}) {
    if (!Array.isArray(actions) || actions.length > MAX_ACTIONS) {
        throw new Error(`scan: actions must be an array with at most ${MAX_ACTIONS} entries`);
    }
    const exactNames = new Set();
    const normalizedNames = new Map();
    for (const action of actions) {
        if (!action || typeof action !== 'object' || Array.isArray(action)
            || typeof action.name !== 'string' || !action.name || action.name.length > 256
            || (action.description !== undefined && (typeof action.description !== 'string' || action.description.length > 16_384))) {
            throw new Error('scan: each action requires a non-empty name and bounded string description');
        }
        if (SOURCE_CONFUSING_NAME.test(action.name) || RESERVED_OBJECT_NAMES.has(action.name)) {
            throw new Error(`scan: action name is unsafe for generated source: ${JSON.stringify(action.name)}`);
        }
        if (source === 'openapi'
            && (typeof action.http_method !== 'string'
                || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(action.http_method.toUpperCase())
                || typeof action.route_path !== 'string'
                || !action.route_path.startsWith('/')
                || action.route_path.length > 2_048
                || SOURCE_CONFUSING_NAME.test(action.route_path))) {
            throw new Error('scan: each OpenAPI action requires a bounded HTTP method and route path');
        }
        if (exactNames.has(action.name)) {
            throw new Error(`scan: duplicate action name: ${JSON.stringify(action.name)}`);
        }
        exactNames.add(action.name);
        const normalized = norm(action.name);
        if (!normalized) {
            throw new Error(`scan: action name is unsafe after normalization: ${JSON.stringify(action.name)}`);
        }
        const collision = normalizedNames.get(normalized);
        if (collision) {
            throw new Error(`scan: normalized action name collision: ${JSON.stringify(collision)} and ${JSON.stringify(action.name)}`);
        }
        normalizedNames.set(normalized, action.name);
    }
    const results = actions.map((a) => ({ action: a, classification: classifyAction(a) }));
    const bucket = (d) => results.filter((r) => r.classification.decision === d);
    const gated = bucket('gate');
    const failClosed = bucket('review_fail_closed');
    const pass = bucket('pass_through');
    const review = bucket('review');
    // Proposed manifest: known-category actions as their pack, discovered ones as
    // extraActions bound to the caller's real tool names. Unclassified-mutating are
    // included receipt_required:true so the manifest itself fails closed.
    const extraActions = [...gated, ...failClosed].map(({ action, classification }) => ({
        id: `discovered.${norm(action.name)}`,
        label: classification.label || action.name,
        action_type: classification.category ? packById[classification.category]?.action_type || `discovered.${norm(action.name)}` : `discovered.${norm(action.name)}`,
        risk: classification.decision === 'gate' ? 'high' : 'unconfirmed',
        receipt_required: true,
        assurance_class: classification.assurance_class || 'class_a',
        match: source === 'openapi'
            ? { protocol: 'http', method: action.http_method.toUpperCase(), path: action.route_path }
            : { protocol: 'mcp', tool: action.name },
        why: classification.why || classification.reason,
        needs_human_confirmation: classification.decision === 'review_fail_closed',
        execution_binding: { required_fields: classification.required_fields || ['action_type'] },
    }));
    // createDefaultActionRiskManifest's `extraActions` param has no JSDoc type in
    // risk-packs.js, so TS infers it from the `= []` default as `never[]` (an
    // inference artifact, not a real constraint — the function spreads it
    // unchanged into the manifest's `actions` array alongside entries of this
    // exact shape). Cast here rather than in the vendored risk-packs.js, which
    // this file does not own.
    const manifest = createDefaultActionRiskManifest({ includePassThrough: false, extraActions });
    return {
        source,
        counts: { total: actions.length, gate: gated.length, review_fail_closed: failClosed.length, pass_through: pass.length, review: review.length },
        results,
        manifest,
        blindSpots,
    };
}
export const KNOWN_CATEGORIES = CATEGORY_SIGNALS.map((c) => c.pack);
export { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS };
//# sourceMappingURL=index.js.map