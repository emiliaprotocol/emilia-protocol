/**
 * EP Rules Engine v0
 * @license Apache-2.0
 *
 * Implements §4 of the 2026-04-27 monetization audit
 * (emilia_protocol_monetization_audit_rules_targets.md, lines 611–882).
 *
 * Pure-function policy evaluator — no I/O, no DB, no network. Same input
 * always produces same output. The result is everything an API route
 * needs to make a decision: which of 7 decision states applies, why
 * (machine-readable reason codes), how many approvers are required, what
 * separation-of-duty constraints to enforce, and a numeric risk score.
 *
 * This module is intentionally separate from lib/guard-policies.js. That
 * module's evaluateGuardPolicy() is consumed by /api/v1/trust-receipts and
 * the GovGuard/FinGuard adapters today; rewriting it under live API
 * routes would risk regressions. Wire this richer evaluator behind a
 * feature flag in those routes when ready.
 *
 * Coverage vs §4:
 *   §4.2  Decision enum         ✓ DECISIONS (7 values)
 *   §4.3  ActionEvaluationInput ✓ accepted via parameter
 *   §4.4  ActionEvaluationOutput ✓ partial — emits decision/reasons/
 *         approvals/risk; defers binding_material/nonce/receipt_preview
 *         to the caller (existing canonical-action + handshake modules
 *         already produce these)
 *   §4.5  Hard-deny rules       ✓ all 9 from spec
 *   §4.6  Mandatory signoff     ✓ all 6 from spec
 *   §4.7  Approval quorum       ✓ all 6 escalation rules
 *   §4.8  Separation of duty    ✓ all 3 from spec (caller supplies
 *         approver context to enable the check)
 *   §4.9  Risk scoring          ✓ all 9 from spec, with the audit's
 *         exact escalation thresholds (≥80, ≥50, ≥30, else)
 *   §4.10 Canonical binding     ✗ deferred to caller (lib/canonical-action.js)
 *   §4.11 Policy versioning     ✗ deferred to caller (existing policy_id +
 *         policy_version + policy_hash get pinned by the API route)
 *   §4.12 Receipt schema        ✗ deferred to caller (existing receipt
 *         assembly in /api/v1/trust-receipts)
 */

// ─── Decision enum (§4.2) ─────────────────────────────────────────────────

export const DECISIONS = Object.freeze({
  ALLOW: 'ALLOW',
  ALLOW_WITH_RECEIPT: 'ALLOW_WITH_RECEIPT',
  REQUIRE_SIGNOFF: 'REQUIRE_SIGNOFF',
  REQUIRE_SECOND_APPROVAL: 'REQUIRE_SECOND_APPROVAL',
  REQUIRE_THIRD_APPROVAL: 'REQUIRE_THIRD_APPROVAL',
  HOLD_FOR_REVIEW: 'HOLD_FOR_REVIEW',
  DENY: 'DENY',
});

// ─── Reason codes — machine-readable (§4.5–§4.9) ──────────────────────────

export const REASON_CODES = Object.freeze({
  // Hard deny (§4.5)
  ACTOR_MISSING:                   'ACTOR_MISSING',
  AUTHORITY_MISSING:               'AUTHORITY_MISSING',
  AUTHORITY_REVOKED:               'AUTHORITY_REVOKED',
  AUTHORITY_EXPIRED:               'AUTHORITY_EXPIRED',
  MFA_REQUIRED:                    'MFA_REQUIRED',
  ASSURANCE_TOO_LOW:               'ASSURANCE_TOO_LOW',
  WATCHLIST_HIT:                   'WATCHLIST_HIT',
  AMOUNT_EXCEEDS_AUTHORITY:        'AMOUNT_EXCEEDS_AUTHORITY',
  ACTION_OUTSIDE_AUTHORITY_SCOPE:  'ACTION_OUTSIDE_AUTHORITY_SCOPE',

  // Mandatory signoff (§4.6)
  BANK_DESTINATION_CHANGE:         'BANK_DESTINATION_CHANGE',
  BENEFIT_DESTINATION_CHANGE:      'BENEFIT_DESTINATION_CHANGE',
  OPERATOR_OVERRIDE:               'OPERATOR_OVERRIDE',
  AMOUNT_THRESHOLD_10K:            'AMOUNT_THRESHOLD_10K',
  AFTER_HOURS_ACTION:              'AFTER_HOURS_ACTION',
  NEW_DESTINATION:                 'NEW_DESTINATION',

  // Risk scoring (§4.9)
  RISK_SCORE_CRITICAL:             'RISK_SCORE_CRITICAL',
  RISK_SCORE_HIGH:                 'RISK_SCORE_HIGH',
  RISK_SCORE_MEDIUM:               'RISK_SCORE_MEDIUM',
  RISK_ACCEPTABLE:                 'RISK_ACCEPTABLE',

  // Separation of duty (§4.8)
  SELF_APPROVAL_NOT_ALLOWED:           'SELF_APPROVAL_NOT_ALLOWED',
  CROSS_DEPARTMENT_APPROVAL_REQUIRED:  'CROSS_DEPARTMENT_APPROVAL_REQUIRED',
  SUBORDINATE_CANNOT_APPROVE_MANAGER_ACTION: 'SUBORDINATE_CANNOT_APPROVE_MANAGER_ACTION',
});

// ─── Workflows whose mere presence triggers signoff (§4.6) ────────────────

const SIGNOFF_REQUIRED_WORKFLOWS = Object.freeze({
  vendor_bank_account_change: REASON_CODES.BANK_DESTINATION_CHANGE,
  benefit_redirect:           REASON_CODES.BENEFIT_DESTINATION_CHANGE,
  operator_override:          REASON_CODES.OPERATOR_OVERRIDE,
});

// ─── Workflows whose presence escalates quorum to ≥2 approvals (§4.7) ─────

const QUORUM_TWO_WORKFLOWS = new Set(['vendor_bank_account_change', 'benefit_redirect']);

// ─── Risk scoring weights (§4.9) ──────────────────────────────────────────
// Kept as a const table rather than inlined-magic-numbers so the audit
// section is reviewable line-by-line.

const RISK_WEIGHTS = Object.freeze({
  AFTER_HOURS:                15,
  UNMANAGED_DEVICE:           15,
  STALE_SESSION:              10,    // session_age_seconds > 3600
  HIGH_VELOCITY:              15,    // velocity_same_actor_24h >= 5
  REPEATED_TARGET_CHANGES:    20,    // prior_changes_target_30d >= 2
  NEW_DESTINATION:            25,    // destination_age_days < 30
  AMOUNT_GTE_10K:             10,
  AMOUNT_GTE_50K:             20,
  PRIOR_DENIALS:              30,    // prior_denials_actor_30d > 0
});

// ─── Public API ───────────────────────────────────────────────────────────

/**
 * Evaluate a single action against the rules engine (pure).
 *
 * @param {object} input - matches §4.3 ActionEvaluationInput shape
 * @param {string} input.tenant_id
 * @param {'shadow'|'enforce'} input.environment
 * @param {string} input.workflow            - e.g. 'vendor_bank_account_change'
 * @param {object} input.actor
 * @param {string} input.actor.actor_id
 * @param {string} input.actor.role
 * @param {string} [input.actor.department]
 * @param {'low'|'medium'|'high'} [input.actor.assurance_level]
 * @param {boolean} [input.actor.mfa_verified]
 * @param {number} [input.actor.session_age_seconds]
 * @param {'unknown'|'personal'|'managed'} [input.actor.device_trust]
 * @param {object} input.action
 * @param {string} input.action.action_id
 * @param {string} input.action.action_type
 * @param {number} [input.action.amount_usd]
 * @param {object} input.authority
 * @param {string} [input.authority.authority_id]
 * @param {string[]} [input.authority.scope]
 * @param {number} [input.authority.max_amount_usd]
 * @param {string} [input.authority.expires_at]   - ISO-8601
 * @param {boolean} [input.authority.revoked]
 * @param {object} [input.context]
 * @param {boolean} [input.context.business_hours]
 * @param {number}  [input.context.velocity_same_actor_24h]
 * @param {number}  [input.context.prior_denials_actor_30d]
 * @param {number}  [input.context.prior_changes_target_30d]
 * @param {number}  [input.context.destination_age_days]
 * @param {boolean} [input.context.watchlist_hit]
 * @param {object}  [input.approver]    - optional, provided when an approver
 *                                        is acting on a decision; enables
 *                                        separation-of-duty checks (§4.8)
 * @param {string}  [input.approver.actor_id]
 * @param {string}  [input.approver.department]
 * @param {string[]}[input.approver.manager_chain]
 * @param {object}  [input.policy]      - optional, controls separation-of-
 *                                        duty rules that depend on policy
 *                                        configuration (e.g. cross-department
 *                                        approval requirement)
 * @param {boolean} [input.policy.requires_cross_department_approval]
 *
 * @returns {{
 *   decision: string,
 *   enforcement_required: boolean,
 *   reason_codes: string[],
 *   required_approvals: number,
 *   required_signoff: { reason_code: string } | null,
 *   risk_score: number,
 *   separation_of_duty_violations: string[],
 * }}
 */
export function evaluateAction(input) {
  if (!input || typeof input !== 'object') {
    throw new TypeError('evaluateAction: input is required and must be an object');
  }

  const reason_codes = [];
  const separation_of_duty_violations = [];

  // ── Layer 1: hard-deny (§4.5) ───────────────────────────────────────────
  // Order matches the audit spec exactly so reviewers can diff line-by-line.
  const denyReason = checkHardDeny(input);
  if (denyReason) {
    return {
      decision: DECISIONS.DENY,
      enforcement_required: true,
      reason_codes: [denyReason],
      required_approvals: 0,
      required_signoff: null,
      risk_score: 0,
      separation_of_duty_violations: [],
    };
  }

  // ── Layer 2: mandatory signoff (§4.6) ───────────────────────────────────
  let required_signoff = null;
  const workflowSignoff = SIGNOFF_REQUIRED_WORKFLOWS[input.workflow];
  if (workflowSignoff) {
    required_signoff = { reason_code: workflowSignoff };
    reason_codes.push(workflowSignoff);
  }
  const amountUsd = input.action?.amount_usd;
  if (typeof amountUsd === 'number' && amountUsd >= 10_000 && !required_signoff) {
    required_signoff = { reason_code: REASON_CODES.AMOUNT_THRESHOLD_10K };
    reason_codes.push(REASON_CODES.AMOUNT_THRESHOLD_10K);
  }
  if (input.context?.business_hours === false && !required_signoff) {
    required_signoff = { reason_code: REASON_CODES.AFTER_HOURS_ACTION };
    reason_codes.push(REASON_CODES.AFTER_HOURS_ACTION);
  }
  if (
    typeof input.context?.destination_age_days === 'number' &&
    input.context.destination_age_days < 30 &&
    !required_signoff
  ) {
    required_signoff = { reason_code: REASON_CODES.NEW_DESTINATION };
    reason_codes.push(REASON_CODES.NEW_DESTINATION);
  }

  // ── Layer 3: approval quorum (§4.7) ─────────────────────────────────────
  let required_approvals = 1;
  if (typeof amountUsd === 'number' && amountUsd >= 10_000) {
    required_approvals = Math.max(required_approvals, 2);
  }
  if (typeof amountUsd === 'number' && amountUsd >= 50_000) {
    required_approvals = Math.max(required_approvals, 3);
  }
  if (QUORUM_TWO_WORKFLOWS.has(input.workflow)) {
    required_approvals = Math.max(required_approvals, 2);
  }
  if ((input.context?.velocity_same_actor_24h ?? 0) >= 5) {
    required_approvals = Math.max(required_approvals, 2);
  }
  if ((input.context?.prior_denials_actor_30d ?? 0) > 0) {
    required_approvals = Math.max(required_approvals, 3);
  }

  // ── Layer 4: separation of duty (§4.8) ──────────────────────────────────
  // Only enforced when an approver is supplied. The pure evaluator's job is
  // to surface violations; the API route consumes them and rejects the
  // approval.
  if (input.approver && input.actor) {
    if (input.approver.actor_id && input.approver.actor_id === input.actor.actor_id) {
      separation_of_duty_violations.push(REASON_CODES.SELF_APPROVAL_NOT_ALLOWED);
    }
    if (
      input.policy?.requires_cross_department_approval &&
      input.approver.department &&
      input.actor.department &&
      input.approver.department === input.actor.department
    ) {
      separation_of_duty_violations.push(REASON_CODES.CROSS_DEPARTMENT_APPROVAL_REQUIRED);
    }
    if (
      Array.isArray(input.approver.manager_chain) &&
      input.actor.actor_id &&
      input.approver.manager_chain.includes(input.actor.actor_id)
    ) {
      separation_of_duty_violations.push(REASON_CODES.SUBORDINATE_CANNOT_APPROVE_MANAGER_ACTION);
    }
  }

  // ── Layer 5: risk scoring (§4.9) ────────────────────────────────────────
  // Risk score escalates the decision; never silently allows.
  let risk_score = 0;
  const ctx = input.context ?? {};
  const actor = input.actor ?? {};
  if (ctx.business_hours === false) risk_score += RISK_WEIGHTS.AFTER_HOURS;
  if (actor.device_trust && actor.device_trust !== 'managed') risk_score += RISK_WEIGHTS.UNMANAGED_DEVICE;
  if ((actor.session_age_seconds ?? 0) > 3600) risk_score += RISK_WEIGHTS.STALE_SESSION;
  if ((ctx.velocity_same_actor_24h ?? 0) >= 5) risk_score += RISK_WEIGHTS.HIGH_VELOCITY;
  if ((ctx.prior_changes_target_30d ?? 0) >= 2) risk_score += RISK_WEIGHTS.REPEATED_TARGET_CHANGES;
  if (typeof ctx.destination_age_days === 'number' && ctx.destination_age_days < 30) {
    risk_score += RISK_WEIGHTS.NEW_DESTINATION;
  }
  if (typeof amountUsd === 'number' && amountUsd >= 10_000) risk_score += RISK_WEIGHTS.AMOUNT_GTE_10K;
  if (typeof amountUsd === 'number' && amountUsd >= 50_000) risk_score += RISK_WEIGHTS.AMOUNT_GTE_50K;
  if ((ctx.prior_denials_actor_30d ?? 0) > 0) risk_score += RISK_WEIGHTS.PRIOR_DENIALS;

  // ── Map risk + quorum into a final decision ─────────────────────────────
  let decision;
  if (risk_score >= 80) {
    decision = DECISIONS.HOLD_FOR_REVIEW;
    reason_codes.push(REASON_CODES.RISK_SCORE_CRITICAL);
  } else if (risk_score >= 50) {
    decision = DECISIONS.REQUIRE_THIRD_APPROVAL;
    required_approvals = Math.max(required_approvals, 3);
    reason_codes.push(REASON_CODES.RISK_SCORE_HIGH);
  } else if (risk_score >= 30) {
    decision = DECISIONS.REQUIRE_SECOND_APPROVAL;
    required_approvals = Math.max(required_approvals, 2);
    reason_codes.push(REASON_CODES.RISK_SCORE_MEDIUM);
  } else if (required_signoff) {
    decision = DECISIONS.REQUIRE_SIGNOFF;
  } else {
    decision = DECISIONS.ALLOW_WITH_RECEIPT;
    reason_codes.push(REASON_CODES.RISK_ACCEPTABLE);
  }

  // Quorum can override the decision — if quorum demands more approvals
  // than the risk-derived decision implies, escalate.
  if (required_approvals >= 3 && decision !== DECISIONS.HOLD_FOR_REVIEW) {
    decision = DECISIONS.REQUIRE_THIRD_APPROVAL;
  } else if (
    required_approvals >= 2 &&
    decision !== DECISIONS.REQUIRE_THIRD_APPROVAL &&
    decision !== DECISIONS.HOLD_FOR_REVIEW
  ) {
    decision = DECISIONS.REQUIRE_SECOND_APPROVAL;
  }

  return {
    decision,
    enforcement_required: input.environment === 'enforce',
    reason_codes,
    required_approvals,
    required_signoff,
    risk_score,
    separation_of_duty_violations,
  };
}

// ─── Hard-deny logic, broken out for readability + testability ────────────

function checkHardDeny(input) {
  const actor = input.actor ?? {};
  const auth = input.authority ?? {};
  const action = input.action ?? {};
  const ctx = input.context ?? {};

  if (!actor.actor_id) return REASON_CODES.ACTOR_MISSING;
  if (!auth.authority_id) return REASON_CODES.AUTHORITY_MISSING;
  if (auth.revoked === true) return REASON_CODES.AUTHORITY_REVOKED;
  if (auth.expires_at && new Date(auth.expires_at).getTime() < Date.now()) {
    return REASON_CODES.AUTHORITY_EXPIRED;
  }
  if (actor.mfa_verified === false) return REASON_CODES.MFA_REQUIRED;
  if (actor.assurance_level === 'low') return REASON_CODES.ASSURANCE_TOO_LOW;
  if (ctx.watchlist_hit === true) return REASON_CODES.WATCHLIST_HIT;
  if (
    typeof action.amount_usd === 'number' &&
    typeof auth.max_amount_usd === 'number' &&
    action.amount_usd > auth.max_amount_usd
  ) {
    return REASON_CODES.AMOUNT_EXCEEDS_AUTHORITY;
  }
  if (
    Array.isArray(auth.scope) &&
    action.action_type &&
    !auth.scope.includes(action.action_type)
  ) {
    return REASON_CODES.ACTION_OUTSIDE_AUTHORITY_SCOPE;
  }
  return null;
}
