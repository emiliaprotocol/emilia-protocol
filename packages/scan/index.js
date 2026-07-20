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
import { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS, createDefaultActionRiskManifest } from './risk-packs.js';

const MAX_ACTIONS = 10_000;

// Keyword signals per risk category, keyed to the EP risk-pack ids so a matched
// action inherits that pack's assurance_class, required_fields, and rationale.
// Deliberately conservative: strong verbs/nouns only, so a match is defensible.
const CATEGORY_SIGNALS = [
  // bank-detail changes are checked BEFORE generic money movement so "payee" /
  // "beneficiary" land here rather than matching the "pay" in "payee".
  { pack: 'money_movement.bank_details_change', any: ['bank_detail', 'bankdetail', 'payee', 'beneficiary', 'routing', 'ach_detail', 'payroll_account', 'vendor_account', 'account_number', 'iban'] },
  { pack: 'money_movement.release', any: ['payment', 'wire', 'transfer', 'remit', 'disburse', 'payout', 'send_money', 'sendmoney', 'settle', 'refund', 'charge', 'invoice_pay', 'pay'] },
  { pack: 'production.deploy', any: ['deploy', 'release_prod', 'rollout', 'ship_prod', 'promote', 'publish_release', 'terraform_apply', 'infra_apply', 'production_push'] },
  { pack: 'permissions.admin_change', any: ['grant', 'role', 'privilege', 'permission', 'entitlement', 'iam', 'make_admin', 'add_admin', 'assign_role', 'elevate', 'sudo_grant'] },
  { pack: 'data.bulk_export', any: ['export', 'download_all', 'bulk_export', 'dump', 'extract_pii', 'data_export', 'exfil', 'share_dataset', 'send_records'] },
  { pack: 'records.delete', any: ['delete', 'remove', 'purge', 'destroy', 'drop_table', 'wipe', 'erase', 'hard_delete'] },
  { pack: 'regulated.decision_override', any: ['override', 'adjudicate', 'dispose', 'approve_case', 'final_decision', 'waive', 'exception_approve'] },
];

const READ_ONLY_SIGNALS = ['get', 'list', 'read', 'search', 'lookup', 'fetch', 'query', 'describe', 'view', 'count', 'status', 'summary', 'summarize', 'preview', 'health', 'ping'];
const MUTATING_SIGNALS = ['create', 'update', 'set', 'write', 'post', 'put', 'patch', 'modify', 'edit', 'add', 'remove', 'send', 'submit', 'execute', 'run', 'apply', 'trigger', 'cancel', 'revoke', 'issue'];

const packById = Object.fromEntries(HIGH_RISK_ACTION_PACKS.map((p) => [p.id, p]));

function norm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_');
}

// Classify ONE action. Returns a proposed control with an explicit reason and
// confidence, or a fail-closed "unclassified" when it mutates but doesn't match.
export function classifyAction(action) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    return { decision: 'review_fail_closed', receipt_required: true, assurance_class: 'class_a', reason: 'malformed action — defaults to require a receipt', confidence: 'low' };
  }
  const hay = `${norm(action.name)}_${norm(action.description)}`;
  const ann = action.annotations && typeof action.annotations === 'object' && !Array.isArray(action.annotations)
    ? action.annotations : {};
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

  const looksReadOnly = READ_ONLY_SIGNALS.some((k) => hay.startsWith(k) || hay.includes(`_${k}_`) || hay.endsWith(`_${k}`));
  const looksMutating = MUTATING_SIGNALS.some((k) => hay.startsWith(k) || hay.includes(`_${k}_`) || hay.endsWith(`_${k}`))
    || ['POST', 'PUT', 'PATCH', 'DELETE'].includes(String(action.http_method || '').toUpperCase());

  if (looksReadOnly && !looksMutating) {
    return {
      decision: 'pass_through',
      receipt_required: false,
      reason: ann.readOnlyHint === true ? 'read-only verb plus advisory readOnlyHint; confirm handler behavior' : 'read-only verb, no mutation signal; confirm handler behavior',
      confidence: 'low',
    };
  }
  if (looksMutating) {
    // The honest core: a state-changing action we could not map to a known risk
    // category is NOT waved through. It defaults fail-closed and asks a human.
    return { decision: 'review_fail_closed', receipt_required: true, assurance_class: 'class_a', reason: 'mutating action, unrecognized category — defaults to require a receipt; confirm or downgrade', confidence: 'low' };
  }
  return {
    decision: 'review_fail_closed',
    receipt_required: true,
    assurance_class: 'class_a',
    reason: ann.readOnlyHint === true
      ? 'readOnlyHint is advisory and no independent read-only signal was found — defaults to require a receipt'
      : 'no strong read-only signal — defaults to require a receipt; confirm or downgrade',
    confidence: 'low',
  };
}

function matchCategory(hay) {
  for (const cat of CATEGORY_SIGNALS) {
    const hit = cat.any.find((k) => hay.includes(k));
    if (hit) return { pack: cat.pack, hit };
  }
  return null;
}

// Scan a list of actions -> full report. Actions: [{name, description?, annotations?, http_method?}].
export function scanActions(actions, { source = 'list', blindSpots = [] } = {}) {
  if (!Array.isArray(actions) || actions.length > MAX_ACTIONS) {
    throw new Error(`scan: actions must be an array with at most ${MAX_ACTIONS} entries`);
  }
  for (const action of actions) {
    if (!action || typeof action !== 'object' || Array.isArray(action)
        || typeof action.name !== 'string' || !action.name || action.name.length > 256
        || (action.description !== undefined && (typeof action.description !== 'string' || action.description.length > 16_384))) {
      throw new Error('scan: each action requires a non-empty name and bounded string description');
    }
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
    match: { protocol: source === 'openapi' ? 'http' : 'mcp', tool: action.name },
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
  const manifest = createDefaultActionRiskManifest({ includePassThrough: false, extraActions: /** @type {any} */ (extraActions) });

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
