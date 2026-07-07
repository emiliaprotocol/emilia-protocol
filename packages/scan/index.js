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

// Keyword signals per risk category, keyed to the EP risk-pack ids so a matched
// action inherits that pack's assurance_class, required_fields, and rationale.
// Deliberately conservative: strong verbs/nouns only, so a match is defensible.
const CATEGORY_SIGNALS = [
  // bank-detail changes are checked BEFORE generic money movement so "payee" /
  // "beneficiary" land here rather than matching the "pay" in "payee".
  { pack: 'money_movement.bank_details_change', any: ['bank_detail', 'bankdetail', 'payee', 'beneficiary', 'routing', 'ach_detail', 'payroll_account', 'vendor_account', 'account_number', 'iban'] },
  { pack: 'money_movement.release', any: ['payment', 'wire', 'transfer', 'remit', 'disburse', 'payout', 'send_money', 'sendmoney', 'settle', 'refund', 'charge', 'invoice_pay', 'pay'] },
  { pack: 'production.deploy', any: ['deploy', 'release_prod', 'rollout', 'ship_prod', 'promote', 'publish_release', 'terraform_apply', 'infra_apply', 'production_push'] },
  { pack: 'iam.role_grant', any: ['grant', 'role', 'privilege', 'permission', 'entitlement', 'iam', 'make_admin', 'add_admin', 'assign_role', 'elevate', 'sudo_grant'] },
  { pack: 'data.export', any: ['export', 'download_all', 'bulk_export', 'dump', 'extract_pii', 'data_export', 'exfil', 'share_dataset', 'send_records'] },
  { pack: 'record.delete', any: ['delete', 'remove', 'purge', 'destroy', 'drop_table', 'wipe', 'erase', 'hard_delete'] },
  { pack: 'decision.override', any: ['override', 'adjudicate', 'dispose', 'approve_case', 'final_decision', 'waive', 'exception_approve'] },
];

const READ_ONLY_SIGNALS = ['get', 'list', 'read', 'search', 'lookup', 'fetch', 'query', 'describe', 'view', 'count', 'status', 'summary', 'preview', 'health', 'ping'];
const MUTATING_SIGNALS = ['create', 'update', 'set', 'write', 'post', 'put', 'patch', 'modify', 'edit', 'add', 'remove', 'send', 'submit', 'execute', 'run', 'apply', 'trigger', 'cancel', 'revoke', 'issue'];

const packById = Object.fromEntries(HIGH_RISK_ACTION_PACKS.map((p) => [p.id, p]));

function norm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '_');
}

// Classify ONE action. Returns a proposed control with an explicit reason and
// confidence, or a fail-closed "unclassified" when it mutates but doesn't match.
export function classifyAction(action) {
  const hay = `${norm(action.name)}_${norm(action.description)}`;
  const ann = action.annotations || {};

  // Standard MCP annotations are authoritative when the tool author set them.
  if (ann.readOnlyHint === true) {
    return { decision: 'pass_through', receipt_required: false, reason: 'annotation:readOnlyHint', confidence: 'high' };
  }
  if (ann.destructiveHint === true && !matchCategory(hay)) {
    return { decision: 'gate', receipt_required: true, assurance_class: 'class_a', category: 'annotated_destructive', reason: 'annotation:destructiveHint', confidence: 'high' };
  }

  const cat = matchCategory(hay);
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
      reason: `matched category "${cat.pack}" on token "${cat.hit}"`,
      confidence: 'medium',
    };
  }

  const looksReadOnly = READ_ONLY_SIGNALS.some((k) => hay.startsWith(k) || hay.includes(`_${k}_`) || hay.endsWith(`_${k}`));
  const looksMutating = MUTATING_SIGNALS.some((k) => hay.startsWith(k) || hay.includes(`_${k}_`) || hay.endsWith(`_${k}`))
    || ['POST', 'PUT', 'PATCH', 'DELETE'].includes(String(action.http_method || '').toUpperCase());

  if (looksReadOnly && !looksMutating) {
    return { decision: 'pass_through', receipt_required: false, reason: 'read-only verb, no mutation signal', confidence: 'low' };
  }
  if (looksMutating) {
    // The honest core: a state-changing action we could not map to a known risk
    // category is NOT waved through. It defaults fail-closed and asks a human.
    return { decision: 'review_fail_closed', receipt_required: true, assurance_class: 'class_a', reason: 'mutating action, unrecognized category — defaults to require a receipt; confirm or downgrade', confidence: 'low' };
  }
  return { decision: 'review', receipt_required: false, reason: 'no strong signal either way — confirm', confidence: 'low' };
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
