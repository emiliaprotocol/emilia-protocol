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
  buildInitiatorAttestation,
  hashCanonicalAction,
  ATTESTATION_STATEMENT_MAX,
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

  it('tiers $50K–$1M as a single accountable signoff', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1', actorId: 'user_1', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [], amount: 250_000, riskFlags: [], authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r.signoffTier).toBe('single');
  });

  it('escalates >= $1,000,000 to dual authorization', () => {
    const r = evaluateGuardPolicy({
      organizationId: 'org_1', actorId: 'user_1', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [], amount: 1_400_000, riskFlags: [], authStrength: 'mfa',
    });
    expect(r.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(r.signoffTier).toBe('dual');
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

// ─── buildInitiatorAttestation (PIP-007) ──────────────────────────────────

describe('buildInitiatorAttestation: trigger mapping (PIP-007 §1 + deployment table)', () => {
  const POLICY = 'ep:policy:fin@v1';

  it('returns undefined for a non-escalating decision (ALLOW)', () => {
    const dec = { decision: GUARD_DECISIONS.ALLOW, signoffRequired: false, reasons: ['Policy satisfied.'] };
    expect(buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, policyId: POLICY })).toBeUndefined();
  });

  it('returns undefined for a DENY decision (no context, no attestation)', () => {
    const dec = { decision: GUARD_DECISIONS.DENY, signoffRequired: false, reasons: ['Impossible travel detected.'] };
    expect(buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, policyId: POLICY })).toBeUndefined();
  });

  it('maps a money-destination field change → policy_rule + destination rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'u', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE,
      targetChangedFields: ['bank_account'], riskFlags: [], authStrength: 'mfa',
    });
    const att = buildInitiatorAttestation(dec, {
      actionType: GUARD_ACTION_TYPES.VENDOR_BANK_ACCOUNT_CHANGE, policyId: POLICY, targetChangedFields: ['bank_account'],
    });
    expect(att.escalation_trigger).toBe('policy_rule');
    expect(att.policy_basis).toBe(`${POLICY}/rule:money-destination-change`);
    expect(att.statement).toMatch(/Money destination change/);
  });

  it('maps a LARGE_PAYMENT_RELEASE single tier → magnitude + threshold rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'u', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [], amount: 250_000, riskFlags: [], authStrength: 'mfa',
    });
    const att = buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, policyId: POLICY });
    expect(att.escalation_trigger).toBe('magnitude');
    expect(att.policy_basis).toBe(`${POLICY}/rule:payment-threshold-single`);
  });

  it('maps a LARGE_PAYMENT_RELEASE dual tier → magnitude + dual threshold rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'u', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [], amount: 1_400_000, riskFlags: [], authStrength: 'mfa',
    });
    const att = buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, policyId: POLICY });
    expect(att.escalation_trigger).toBe('magnitude');
    expect(att.policy_basis).toBe(`${POLICY}/rule:payment-threshold-dual`);
  });

  it('maps an AI_AGENT_PAYMENT_ACTION gate → authority_gap + agent-action rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'agent', actorRole: 'agent',
      actionType: GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION,
      targetChangedFields: [], amount: 100, riskFlags: [], authStrength: 'service_account',
    });
    const att = buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION, policyId: POLICY });
    expect(att.escalation_trigger).toBe('authority_gap');
    expect(att.policy_basis).toBe(`${POLICY}/rule:ai-agent-action`);
  });

  it('maps an AML structuring escalation → uncertainty + AML rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'u', actorRole: 'ap',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE,
      targetChangedFields: [], amount: 2000, riskFlags: [], authStrength: 'mfa',
      aml: { counterpartyName: 'Smurf Co', amount: 9500, recentAmounts: [9400, 9600] },
    });
    const att = buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, policyId: POLICY });
    expect(att.escalation_trigger).toBe('uncertainty');
    expect(att.policy_basis).toBe(`${POLICY}/rule:aml-screening`);
  });

  it('maps a caseworker_override → policy_rule + override rule id', () => {
    const dec = evaluateGuardPolicy({
      organizationId: 'o', actorId: 'u', actorRole: 'caseworker',
      actionType: GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE,
      targetChangedFields: [], riskFlags: [], authStrength: 'mfa',
    });
    const att = buildInitiatorAttestation(dec, { actionType: GUARD_ACTION_TYPES.CASEWORKER_OVERRIDE, policyId: POLICY });
    expect(att.escalation_trigger).toBe('policy_rule');
    expect(att.policy_basis).toBe(`${POLICY}/rule:caseworker-override`);
  });

  it('falls back to policy_rule for any other signoff-required escalation', () => {
    // A hand-built signoff decision that matches no actionType branch.
    const dec = { decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF, signoffRequired: true, reasons: ['Some rule fired.'] };
    const att = buildInitiatorAttestation(dec, { actionType: 'some_other_type', policyId: POLICY, targetChangedFields: [] });
    expect(att.escalation_trigger).toBe('policy_rule');
    expect(att.policy_basis).toBe(`${POLICY}/rule:signoff-required`);
  });

  it('uses a default policy id when none is supplied', () => {
    const dec = { decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF, signoffRequired: true, reasons: ['x'] };
    const att = buildInitiatorAttestation(dec, { actionType: 'x', targetChangedFields: [] });
    expect(att.policy_basis).toBe('ep:policy:guard/rule:signoff-required');
  });

  it('caps the statement at 280 characters (PIP-007 §1)', () => {
    const long = 'word '.repeat(100); // ~500 chars
    const dec = { decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF, signoffRequired: true, reasons: [long] };
    const att = buildInitiatorAttestation(dec, { actionType: 'x', policyId: POLICY, targetChangedFields: [] });
    expect(att.statement.length).toBeLessThanOrEqual(ATTESTATION_STATEMENT_MAX);
    expect(att.statement.endsWith('…')).toBe(true);
  });

  it('returns undefined when the decision object is missing', () => {
    expect(buildInitiatorAttestation(undefined, { actionType: 'x' })).toBeUndefined();
  });
});

describe('Class A by default — requiredAssurance on high-risk signoff decisions', () => {
  it('stamps requiredAssurance:A on a money-destination change', () => {
    const d = evaluateGuardPolicy({ actionType: 'vendor_bank_account_change', targetChangedFields: ['bank_account'] });
    expect(d.signoffRequired).toBe(true);
    expect(d.requiredAssurance).toBe('A');
  });

  it('stamps requiredAssurance:A on a large payment release', () => {
    const d = evaluateGuardPolicy({ actionType: 'large_payment_release', amount: 60_000, targetChangedFields: [] });
    expect(d.requiredAssurance).toBe('A');
  });

  it('stamps requiredAssurance:A on AI-agent payment and caseworker override', () => {
    expect(evaluateGuardPolicy({ actionType: 'ai_agent_payment_action', targetChangedFields: [] }).requiredAssurance).toBe('A');
    expect(evaluateGuardPolicy({ actionType: 'caseworker_override', targetChangedFields: [] }).requiredAssurance).toBe('A');
  });

  it('does NOT require Class A for a low-risk, default-allow action', () => {
    const d = evaluateGuardPolicy({ actionType: 'benefit_address_change', targetChangedFields: ['mailing_address'] });
    expect(d.signoffRequired).toBe(false);
    expect(d.requiredAssurance).toBeUndefined();
  });
});
