/**
 * EP GovGuard + FinGuard — pre-execution policy templates.
 * @license Apache-2.0
 *
 * Implements the policy decision logic from
 * /Users/imanschrock/Desktop/Ventures/emilia_govguard_finguard_coding_changes.md
 * §4 ("Policy Engine"), backed by EP's existing handshake/policy primitives.
 *
 * Modes (per MD §9):
 *   - observe — evaluate, generate receipt, log decision, NEVER block
 *   - warn    — evaluate, return decision, allow caller to choose
 *   - enforce — evaluate, fail-closed if signoff missing or policy denies
 *
 * Decision semantics (per MD §4.2):
 *   allow              — execute without further gating
 *   observe            — log only (used in observe mode)
 *   allow_with_signoff — require human approval before consume
 *   deny               — refuse outright (impossible travel, compromised device)
 */

import crypto from 'node:crypto';

// ─── Action types (per MD §4.3) ───────────────────────────────────────────

export const GUARD_ACTION_TYPES = Object.freeze({
  // GovGuard
  BENEFIT_BANK_ACCOUNT_CHANGE: 'benefit_bank_account_change',
  BENEFIT_ADDRESS_CHANGE: 'benefit_address_change',
  CASEWORKER_OVERRIDE: 'caseworker_override',
  // FinGuard
  VENDOR_BANK_ACCOUNT_CHANGE: 'vendor_bank_account_change',
  BENEFICIARY_CREATION: 'beneficiary_creation',
  LARGE_PAYMENT_RELEASE: 'large_payment_release',
  AI_AGENT_PAYMENT_ACTION: 'ai_agent_payment_action',
});

export const GUARD_DECISIONS = Object.freeze({
  ALLOW: 'allow',
  OBSERVE: 'observe',
  ALLOW_WITH_SIGNOFF: 'allow_with_signoff',
  DENY: 'deny',
});

export const ENFORCEMENT_MODES = Object.freeze({
  OBSERVE: 'observe',
  WARN: 'warn',
  ENFORCE: 'enforce',
});

/**
 * Fields whose change indicates the destination of money is moving.
 * Per MD §4.4 — any change to these requires accountable signoff.
 */
const MONEY_DESTINATION_FIELDS = Object.freeze([
  'bank_account',
  'routing_number',
  'iban',
  'swift_bic',
  'beneficiary_name',
  'payment_address',
]);

/**
 * Risk flags that fail closed (deny outright, no signoff path).
 */
const HARD_DENY_FLAGS = Object.freeze(['impossible_travel', 'known_compromised_device']);

/**
 * Threshold above which a payment release requires signoff regardless of
 * other factors. Per MD §4.4 — $50,000.
 */
const LARGE_PAYMENT_THRESHOLD_USD = 50_000;

/**
 * Evaluate a guard policy against an action input. Pure function — no I/O.
 *
 * @param {object} input - the policy input
 * @param {string} input.organizationId
 * @param {string} input.actorId
 * @param {string} input.actorRole
 * @param {string} input.actionType
 * @param {string[]} input.targetChangedFields
 * @param {number} [input.amount]
 * @param {string} [input.currency]
 * @param {string[]} input.riskFlags
 * @param {'password'|'mfa'|'phishing_resistant_mfa'|'service_account'} input.authStrength
 * @param {string} [input.initiatorId]
 * @param {string} [input.approverId]
 * @returns {{ decision: string, reasons: string[], signoffRequired: boolean }}
 */
export function evaluateGuardPolicy(input) {
  const reasons = [];

  // ── Layer 1: hard-deny risk flags (per MD §4.4) ────────────────────────
  for (const flag of HARD_DENY_FLAGS) {
    if (input.riskFlags?.includes(flag)) {
      return {
        decision: GUARD_DECISIONS.DENY,
        reasons: [denyReason(flag)],
        signoffRequired: false,
      };
    }
  }

  // ── Layer 2: money-destination changes always require signoff ──────────
  const touchesMoneyDestination = (input.targetChangedFields || []).some((f) =>
    MONEY_DESTINATION_FIELDS.includes(f),
  );
  if (touchesMoneyDestination) {
    reasons.push('Money destination change requires accountable signoff.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  // ── Layer 3: action-type-specific gates ────────────────────────────────
  if (
    input.actionType === GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE &&
    typeof input.amount === 'number' &&
    input.amount >= LARGE_PAYMENT_THRESHOLD_USD
  ) {
    reasons.push(
      `Payment release of $${input.amount} >= $${LARGE_PAYMENT_THRESHOLD_USD} requires accountable signoff.`,
    );
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION) {
    reasons.push('AI-agent initiated financial action requires human accountability.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  if (input.actionType === GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE) {
    reasons.push('Caseworker override requires supervisor signoff.');
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      reasons,
      signoffRequired: true,
    };
  }

  // ── Layer 4: default-allow ─────────────────────────────────────────────
  return {
    decision: GUARD_DECISIONS.ALLOW,
    reasons: ['Policy satisfied.'],
    signoffRequired: false,
  };
}

/**
 * Apply enforcement mode to a base decision (per MD §9).
 *
 * Observe mode: any blocking decision becomes observe; signoffRequired stays
 * true so the receipt records what *would* have been required, but the
 * caller is not blocked.
 *
 * Warn mode: returns the decision verbatim; the caller decides whether to
 * proceed (used for staged rollouts).
 *
 * Enforce mode: returns the decision verbatim; caller MUST honor it.
 *
 * @param {{decision: string, reasons: string[], signoffRequired: boolean}} base
 * @param {string} mode - one of ENFORCEMENT_MODES
 */
export function applyEnforcementMode(base, mode) {
  if (mode === ENFORCEMENT_MODES.OBSERVE) {
    if (base.decision === GUARD_DECISIONS.DENY || base.decision === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF) {
      return {
        ...base,
        decision: GUARD_DECISIONS.OBSERVE,
        observed_decision: base.decision,
        reasons: [
          ...base.reasons,
          'Mode=observe: this would have been blocked or required signoff in enforce mode.',
        ],
      };
    }
  }
  return base;
}

/**
 * Canonical action hash (per MD §3.1). Deterministic JSON serialization
 * with sorted keys. NOT a security boundary by itself — it is the
 * binding-key that pins a receipt to the exact action. EP's existing
 * lib/handshake/invariants.js sha256() helper uses the same shape.
 *
 * @param {Record<string, unknown>} action
 * @returns {string} hex-encoded sha256
 */
export function hashCanonicalAction(action) {
  return crypto.createHash('sha256').update(canonicalize(action)).digest('hex');
}

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function denyReason(flag) {
  if (flag === 'impossible_travel') return 'Impossible travel detected.';
  if (flag === 'known_compromised_device') return 'Known compromised device.';
  return `Risk flag: ${flag}`;
}
