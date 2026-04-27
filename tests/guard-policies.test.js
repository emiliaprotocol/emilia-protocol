/**
 * EP Guard Policies — pure-function unit tests.
 * @license Apache-2.0
 *
 * Covers lib/guard-policies.js:
 *   - evaluateGuardPolicy() — every branch from MD §4.4
 *   - applyEnforcementMode() — observe / warn / enforce transforms
 *   - hashCanonicalAction() — deterministic, sorted-keys, tampering detected
 */

import { describe, it, expect } from 'vitest';
import {
  evaluateGuardPolicy,
  applyEnforcementMode,
  hashCanonicalAction,
  GUARD_DECISIONS,
  GUARD_ACTION_TYPES,
  ENFORCEMENT_MODES,
} from '../lib/guard-policies.js';

// ─── evaluateGuardPolicy ──────────────────────────────────────────────────

describe('evaluateGuardPolicy: hard-deny risk flags', () => {
  it('denies on impossible_travel regardless of action_type', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
      targetChangedFields: [],
      riskFlags: ['impossible_travel'],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.DENY);
    expect(r.signoffRequired).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/impossible travel/i);
  });

  it('denies on known_compromised_device', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [],
      riskFlags: ['known_compromised_device'],
      authStrength: 'mfa',
      amount: 500,
    });
    expect(r.decision).toBe(GUARD_DECISIONS.DENY);
    expect(r.signoffRequired).toBe(false);
  });

  it('hard-deny short-circuits before money-destination check', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
      targetChangedFields: ['bank_account'],
      riskFlags: ['impossible_travel'],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.DENY);
  });
});

describe('evaluateGuardPolicy: money-destination changes', () => {
  it('requires signoff on bank_account change', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.BENEFIT_BANK_ACCOUNT_CHANGE,
      targetChangedFields: ['bank_account'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r.signoffRequired).toBe(true);
  });

  it('requires signoff on routing_number change', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
      targetChangedFields: ['routing_number'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
  });

  it('requires signoff on iban change', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.BENEFICIARY_CREATION,
      targetChangedFields: ['iban'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.signoffRequired).toBe(true);
  });

  it('requires signoff on swift_bic change', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.BENEFICIARY_CREATION,
      targetChangedFields: ['swift_bic'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.signoffRequired).toBe(true);
  });

  it('requires signoff on beneficiary_name change', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
      targetChangedFields: ['beneficiary_name'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.signoffRequired).toBe(true);
  });

  it('does NOT require signoff on non-money-destination fields', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE,
      targetChangedFields: ['display_name'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW);
    expect(r.signoffRequired).toBe(false);
  });
});

describe('evaluateGuardPolicy: large-payment threshold', () => {
  it('requires signoff on payment >= $50,000', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [],
      amount: 50_000,
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
  });

  it('requires signoff on payment > $50,000', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [],
      amount: 250_000,
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
  });

  it('does NOT require signoff on payment < $50,000', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [],
      amount: 49_999,
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW);
  });

  it('skips threshold when amount is undefined', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW);
  });
});

describe('evaluateGuardPolicy: action-type-specific gates', () => {
  it('requires signoff on AI-agent payment action regardless of amount', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'agent_1',
      actorRole: 'agent',
      actionType: GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION,
      targetChangedFields: [],
      amount: 100,
      riskFlags: [],
      authStrength: 'service_account',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r.reasons.join(' ')).toMatch(/ai-agent/i);
  });

  it('requires signoff on caseworker_override', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE,
      targetChangedFields: [],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
  });
});

describe('evaluateGuardPolicy: default-allow', () => {
  it('allows benign action_type with no risk flags and no money-destination', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1',
      actorId: 'user_1',
      actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.BENEFIT_ADDRESS_CHANGE,
      targetChangedFields: ['display_name'],
      riskFlags: [],
      authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW);
    expect(r.signoffRequired).toBe(false);
  });
});

// ─── applyEnforcementMode ─────────────────────────────────────────────────

describe('applyEnforcementMode: observe mode', () => {
  it('downgrades DENY to OBSERVE in observe mode', () => {
    const base = { decision: GUARD_DECISIONS.DENY, reasons: ['x'], signoffRequired: false };
    const r = applyEnforcementMode(base, ENFORCEMENT_MODES.OBSERVE);
    expect(r.decision).toBe(GUARD_DECISIONS.OBSERVE);
    expect(r.observed_decision).toBe(GUARD_DECISIONS.DENY);
  });

  it('downgrades ALLOW_WITH_SIGNOFF to OBSERVE in observe mode', () => {
    const base = { decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF, reasons: ['x'], signoffRequired: true };
    const r = applyEnforcementMode(base, ENFORCEMENT_MODES.OBSERVE);
    expect(r.decision).toBe(GUARD_DECISIONS.OBSERVE);
    expect(r.observed_decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
  });

  it('passes ALLOW unchanged in observe mode', () => {
    const base = { decision: GUARD_DECISIONS.ALLOW, reasons: ['x'], signoffRequired: false };
    const r = applyEnforcementMode(base, ENFORCEMENT_MODES.OBSERVE);
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW);
  });
});

describe('applyEnforcementMode: warn + enforce', () => {
  it('passes decisions through unchanged in warn mode', () => {
    const base = { decision: GUARD_DECISIONS.DENY, reasons: ['x'], signoffRequired: false };
    expect(applyEnforcementMode(base, ENFORCEMENT_MODES.WARN)).toEqual(base);
  });

  it('passes decisions through unchanged in enforce mode', () => {
    const base = { decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF, reasons: ['x'], signoffRequired: true };
    expect(applyEnforcementMode(base, ENFORCEMENT_MODES.ENFORCE)).toEqual(base);
  });
});

// ─── hashCanonicalAction ──────────────────────────────────────────────────

describe('hashCanonicalAction', () => {
  it('produces a 64-char hex string (sha256)', () => {
    const h = hashCanonicalAction({ a: 1 });
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic — same input gives same hash', () => {
    const a = { foo: 'bar', n: 1 };
    expect(hashCanonicalAction(a)).toBe(hashCanonicalAction(a));
  });

  it('is order-insensitive — keys reordered produce same hash', () => {
    const h1 = hashCanonicalAction({ a: 1, b: 2, c: 3 });
    const h2 = hashCanonicalAction({ c: 3, a: 1, b: 2 });
    expect(h1).toBe(h2);
  });

  it('detects tampering — changing a field changes the hash', () => {
    const h1 = hashCanonicalAction({ amount: 100 });
    const h2 = hashCanonicalAction({ amount: 101 });
    expect(h1).not.toBe(h2);
  });

  it('handles nested objects with sorted keys', () => {
    const h1 = hashCanonicalAction({ outer: { a: 1, b: 2 } });
    const h2 = hashCanonicalAction({ outer: { b: 2, a: 1 } });
    expect(h1).toBe(h2);
  });

  it('handles arrays preserving order', () => {
    const h1 = hashCanonicalAction({ list: [1, 2, 3] });
    const h2 = hashCanonicalAction({ list: [3, 2, 1] });
    expect(h1).not.toBe(h2);
  });

  it('handles null and undefined consistently', () => {
    expect(() => hashCanonicalAction({ a: null })).not.toThrow();
    expect(() => hashCanonicalAction({ a: undefined })).not.toThrow();
  });
});
