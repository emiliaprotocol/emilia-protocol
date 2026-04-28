/**
 * EP Rules Engine v0 — unit tests.
 * @license Apache-2.0
 *
 * Covers lib/rules-engine.js — every branch of evaluateAction() that
 * traces back to a specific clause in §4 of the 2026-04-27 monetization
 * audit (emilia_protocol_monetization_audit_rules_targets.md).
 *
 * Test groups mirror the audit's section numbering so a reviewer can diff
 * spec-against-tests without translation.
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateAction,
  DECISIONS,
  REASON_CODES,
} from '../lib/rules-engine.js';

// ─── Test helpers ─────────────────────────────────────────────────────────

function baseInput(overrides = {}) {
  return {
    tenant_id: 'tenant_demo',
    environment: 'enforce',
    workflow: 'vendor_payment',
    actor: {
      actor_id: 'user_1',
      role: 'finance_operator',
      department: 'finance',
      assurance_level: 'high',
      mfa_verified: true,
      session_age_seconds: 300,
      device_trust: 'managed',
    },
    action: {
      action_id: 'ACT-1',
      action_type: 'vendor_payment',
      amount_usd: 500,
    },
    authority: {
      authority_id: 'AUTH-1',
      scope: ['vendor_payment', 'vendor_bank_account_change', 'benefit_redirect', 'operator_override'],
      max_amount_usd: 1_000_000,
      revoked: false,
    },
    context: {
      business_hours: true,
      velocity_same_actor_24h: 1,
      prior_denials_actor_30d: 0,
      prior_changes_target_30d: 0,
      watchlist_hit: false,
    },
    ...overrides,
  };
}

// ─── §4.5 Hard-deny ───────────────────────────────────────────────────────

describe('§4.5 hard-deny rules', () => {
  it('denies when actor_id is missing', () => {
    const r = evaluateAction(baseInput({ actor: { role: 'x' } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.ACTOR_MISSING]);
  });

  it('denies when authority_id is missing', () => {
    const r = evaluateAction(baseInput({ authority: { scope: ['vendor_payment'] } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.AUTHORITY_MISSING]);
  });

  it('denies when authority is revoked', () => {
    const r = evaluateAction(baseInput({ authority: { authority_id: 'A', revoked: true, scope: ['vendor_payment'] } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.AUTHORITY_REVOKED]);
  });

  it('denies when authority has expired', () => {
    const r = evaluateAction(baseInput({
      authority: { authority_id: 'A', expires_at: '2020-01-01T00:00:00Z', scope: ['vendor_payment'] },
    }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.AUTHORITY_EXPIRED]);
  });

  it('denies when MFA is not verified', () => {
    const r = evaluateAction(baseInput({ actor: { actor_id: 'u', mfa_verified: false, assurance_level: 'high' } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.MFA_REQUIRED]);
  });

  it('denies when assurance_level is low', () => {
    const r = evaluateAction(baseInput({ actor: { actor_id: 'u', mfa_verified: true, assurance_level: 'low' } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.ASSURANCE_TOO_LOW]);
  });

  it('denies on watchlist hit', () => {
    const r = evaluateAction(baseInput({ context: { business_hours: true, watchlist_hit: true } }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.WATCHLIST_HIT]);
  });

  it('denies when amount_usd exceeds authority.max_amount_usd', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 2_000_000 },
    }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.AMOUNT_EXCEEDS_AUTHORITY]);
  });

  it('denies when action_type is outside authority scope', () => {
    const r = evaluateAction(baseInput({
      authority: { authority_id: 'A', scope: ['only_a_different_action'], max_amount_usd: 1_000_000 },
    }));
    expect(r.decision).toBe(DECISIONS.DENY);
    expect(r.reason_codes).toEqual([REASON_CODES.ACTION_OUTSIDE_AUTHORITY_SCOPE]);
  });

  it('hard-deny short-circuits — no risk score, no signoff fields populated', () => {
    const r = evaluateAction(baseInput({ actor: { mfa_verified: false, actor_id: 'u' } }));
    expect(r.required_approvals).toBe(0);
    expect(r.required_signoff).toBeNull();
    expect(r.risk_score).toBe(0);
  });
});

// ─── §4.6 Mandatory signoff ───────────────────────────────────────────────

describe('§4.6 mandatory signoff rules', () => {
  it('requires signoff for vendor_bank_account_change', () => {
    const r = evaluateAction(baseInput({ workflow: 'vendor_bank_account_change' }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.BANK_DESTINATION_CHANGE);
    expect(r.reason_codes).toContain(REASON_CODES.BANK_DESTINATION_CHANGE);
  });

  it('requires signoff for benefit_redirect', () => {
    const r = evaluateAction(baseInput({ workflow: 'benefit_redirect' }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.BENEFIT_DESTINATION_CHANGE);
  });

  it('requires signoff for operator_override', () => {
    const r = evaluateAction(baseInput({ workflow: 'operator_override' }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.OPERATOR_OVERRIDE);
  });

  it('requires signoff when amount_usd >= 10000 (no other workflow trigger)', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 10_000 },
    }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.AMOUNT_THRESHOLD_10K);
  });

  it('requires signoff after-hours when no other rule has fired first', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 500 },
      context: { business_hours: false },
    }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.AFTER_HOURS_ACTION);
  });

  it('requires signoff when destination is new (<30 days)', () => {
    const r = evaluateAction(baseInput({
      context: { business_hours: true, destination_age_days: 5 },
    }));
    expect(r.required_signoff?.reason_code).toBe(REASON_CODES.NEW_DESTINATION);
  });

  it('does not require signoff for benign vendor_payment under 10K, business hours, established destination', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 500 },
      context: { business_hours: true, destination_age_days: 365 },
    }));
    expect(r.required_signoff).toBeNull();
    expect(r.decision).toBe(DECISIONS.ALLOW_WITH_RECEIPT);
  });
});

// ─── §4.7 Approval quorum ─────────────────────────────────────────────────

describe('§4.7 approval quorum', () => {
  it('requires >= 2 approvals when amount >= 10000', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 25_000 },
    }));
    expect(r.required_approvals).toBeGreaterThanOrEqual(2);
  });

  it('requires >= 3 approvals when amount >= 50000', () => {
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 75_000 },
    }));
    expect(r.required_approvals).toBeGreaterThanOrEqual(3);
  });

  it('requires >= 2 approvals for vendor_bank_account_change (no amount needed)', () => {
    const r = evaluateAction(baseInput({ workflow: 'vendor_bank_account_change' }));
    expect(r.required_approvals).toBeGreaterThanOrEqual(2);
  });

  it('requires >= 2 approvals when velocity_same_actor_24h >= 5', () => {
    const r = evaluateAction(baseInput({
      context: { business_hours: true, velocity_same_actor_24h: 5 },
    }));
    expect(r.required_approvals).toBeGreaterThanOrEqual(2);
  });

  it('requires >= 3 approvals when actor has prior denials in last 30 days', () => {
    const r = evaluateAction(baseInput({
      context: { business_hours: true, prior_denials_actor_30d: 1 },
    }));
    expect(r.required_approvals).toBeGreaterThanOrEqual(3);
  });
});

// ─── §4.8 Separation of duty ──────────────────────────────────────────────

describe('§4.8 separation of duty', () => {
  it('flags self-approval', () => {
    const r = evaluateAction(baseInput({
      approver: { actor_id: 'user_1' }, // same as actor.actor_id
    }));
    expect(r.separation_of_duty_violations).toContain(REASON_CODES.SELF_APPROVAL_NOT_ALLOWED);
  });

  it('flags cross-department violation when policy demands it', () => {
    const r = evaluateAction(baseInput({
      approver: { actor_id: 'user_2', department: 'finance' },
      policy: { requires_cross_department_approval: true },
    }));
    expect(r.separation_of_duty_violations).toContain(REASON_CODES.CROSS_DEPARTMENT_APPROVAL_REQUIRED);
  });

  it('does not flag cross-department when policy does not require it', () => {
    const r = evaluateAction(baseInput({
      approver: { actor_id: 'user_2', department: 'finance' },
    }));
    expect(r.separation_of_duty_violations).not.toContain(REASON_CODES.CROSS_DEPARTMENT_APPROVAL_REQUIRED);
  });

  it('flags subordinate-approving-manager', () => {
    const r = evaluateAction(baseInput({
      approver: { actor_id: 'user_2', manager_chain: ['user_1'] }, // user_1 is in user_2's manager chain
    }));
    expect(r.separation_of_duty_violations).toContain(REASON_CODES.SUBORDINATE_CANNOT_APPROVE_MANAGER_ACTION);
  });

  it('emits no violations when no approver context is provided', () => {
    const r = evaluateAction(baseInput());
    expect(r.separation_of_duty_violations).toEqual([]);
  });
});

// ─── §4.9 Risk scoring ────────────────────────────────────────────────────

describe('§4.9 risk scoring', () => {
  it('scores after-hours action (+15)', () => {
    const r = evaluateAction(baseInput({ context: { business_hours: false } }));
    expect(r.risk_score).toBeGreaterThanOrEqual(15);
  });

  it('scores unmanaged device (+15)', () => {
    const r = evaluateAction(baseInput({
      actor: { actor_id: 'u', mfa_verified: true, assurance_level: 'high', device_trust: 'personal' },
    }));
    expect(r.risk_score).toBeGreaterThanOrEqual(15);
  });

  it('escalates to HOLD_FOR_REVIEW at risk >= 80', () => {
    // Stack signals so risk_score crosses 80:
    // after-hours (15) + unmanaged (15) + stale-session (10) + velocity (15)
    // + new-destination (25) = 80
    const r = evaluateAction(baseInput({
      actor: { actor_id: 'u', mfa_verified: true, assurance_level: 'high', device_trust: 'personal', session_age_seconds: 7200 },
      context: { business_hours: false, velocity_same_actor_24h: 5, destination_age_days: 5 },
    }));
    expect(r.risk_score).toBeGreaterThanOrEqual(80);
    expect(r.decision).toBe(DECISIONS.HOLD_FOR_REVIEW);
    expect(r.reason_codes).toContain(REASON_CODES.RISK_SCORE_CRITICAL);
  });

  it('escalates to REQUIRE_THIRD_APPROVAL at risk >= 50, < 80', () => {
    // Build a 50-point risk score: after-hours (15) + new-destination (25) + amount-10k (10) = 50
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 10_000 },
      context: { business_hours: false, destination_age_days: 5 },
    }));
    expect(r.risk_score).toBeGreaterThanOrEqual(50);
    expect(r.risk_score).toBeLessThan(80);
    expect(r.decision).toBe(DECISIONS.REQUIRE_THIRD_APPROVAL);
  });

  it('escalates to REQUIRE_SECOND_APPROVAL at risk >= 30, < 50', () => {
    // After-hours (15) + new-destination (25) = 40
    const r = evaluateAction(baseInput({
      action: { action_id: 'A', action_type: 'vendor_payment', amount_usd: 500 },
      context: { business_hours: false, destination_age_days: 5 },
    }));
    expect(r.risk_score).toBeGreaterThanOrEqual(30);
    expect(r.risk_score).toBeLessThan(50);
    // Note: at risk 40 + new-destination signoff fired, so quorum=1 and decision
    // is REQUIRE_SECOND_APPROVAL via the risk path (not the signoff path)
    expect(r.decision).toBe(DECISIONS.REQUIRE_SECOND_APPROVAL);
  });

  it('lands at ALLOW_WITH_RECEIPT when nothing is wrong', () => {
    const r = evaluateAction(baseInput());
    expect(r.risk_score).toBeLessThan(30);
    expect(r.decision).toBe(DECISIONS.ALLOW_WITH_RECEIPT);
    expect(r.reason_codes).toContain(REASON_CODES.RISK_ACCEPTABLE);
  });
});

// ─── Output shape ─────────────────────────────────────────────────────────

describe('output shape contract', () => {
  it('returns all documented fields for the happy-path case', () => {
    const r = evaluateAction(baseInput());
    expect(r).toHaveProperty('decision');
    expect(r).toHaveProperty('enforcement_required');
    expect(r).toHaveProperty('reason_codes');
    expect(r).toHaveProperty('required_approvals');
    expect(r).toHaveProperty('required_signoff');
    expect(r).toHaveProperty('risk_score');
    expect(r).toHaveProperty('separation_of_duty_violations');
    expect(Array.isArray(r.reason_codes)).toBe(true);
    expect(Array.isArray(r.separation_of_duty_violations)).toBe(true);
  });

  it('enforcement_required reflects the environment field', () => {
    expect(evaluateAction(baseInput({ environment: 'enforce' })).enforcement_required).toBe(true);
    expect(evaluateAction(baseInput({ environment: 'shadow' })).enforcement_required).toBe(false);
  });

  it('throws TypeError when input is null or non-object', () => {
    expect(() => evaluateAction(null)).toThrow(TypeError);
    expect(() => evaluateAction('not-an-object')).toThrow(TypeError);
  });
});
