/**
 * AML screening — sanctions matching, structuring/velocity, and the guard-policy
 * integration. Synthetic watchlist; the logic is what must be correct.
 */

import { describe, it, expect } from 'vitest';
import {
  normalizeName, screenSanctions, detectStructuring, detectVelocity, screenAml,
} from '../lib/aml/screening.js';
import { evaluateGuardPolicy, GUARD_ACTION_TYPES, GUARD_DECISIONS } from '../lib/guard-policies.js';

describe('name normalization', () => {
  it('lowercases, strips punctuation, collapses whitespace', () => {
    expect(normalizeName('  Blocked-Person,  ALPHA! ')).toBe('blocked person alpha');
  });
  it('strips diacritics', () => {
    expect(normalizeName('Émbargöed')).toBe('embargoed');
  });
});

describe('sanctions screening', () => {
  it('matches an exact watchlist name', () => {
    const r = screenSanctions('Blocked Person Alpha');
    expect(r.hit).toBe(true);
    expect(r.topScore).toBe(1);
    expect(r.matches[0].name).toBe('BLOCKED PERSON ALPHA');
    expect(r.matches[0].program).toBe('SDGT');
  });
  it('matches an alias', () => {
    const r = screenSanctions('STC LLC');
    expect(r.hit).toBe(true);
    expect(r.matches[0].name).toBe('SANCTIONED TRADING COMPANY LLC');
  });
  it('matches token-reordered names above threshold', () => {
    const r = screenSanctions('Alpha Blocked Person');
    expect(r.hit).toBe(true);
  });
  it('does not match an unrelated name', () => {
    const r = screenSanctions('Acme Widgets Inc');
    expect(r.hit).toBe(false);
    expect(r.matches).toHaveLength(0);
  });
  it('flags an embargoed jurisdiction even without a name hit', () => {
    const r = screenSanctions('Some Neutral Party', { country: 'IR' });
    expect(r.country_blocked).toBe(true);
    expect(r.hit).toBe(true);
  });
  it('does not flag a non-embargoed country', () => {
    const r = screenSanctions('Some Neutral Party', { country: 'CA' });
    expect(r.country_blocked).toBe(false);
    expect(r.hit).toBe(false);
  });
});

describe('structuring detection', () => {
  it('flags repeated just-under-threshold transfers', () => {
    const r = detectStructuring(9500, [9200, 9800]);
    expect(r.structuring).toBe(true);
    expect(r.reason).toMatch(/just under/);
  });
  it('treats a single near-threshold transfer as a soft signal, not a block', () => {
    const r = detectStructuring(9500, []);
    expect(r.structuring).toBe(false);
    expect(r.score).toBeGreaterThanOrEqual(0.4);
  });
  it('does not flag a clearly-above-threshold transfer', () => {
    const r = detectStructuring(50000, [50000]);
    expect(r.structuring).toBe(false);
    expect(r.score).toBe(0);
  });
  it('flags aggregation of several sub-threshold transfers over the window', () => {
    const r = detectStructuring(2000, [9500, 9500, 9500]);
    expect(r.structuring).toBe(true);
  });
});

describe('velocity detection', () => {
  it('flags an unusual number of transfers', () => {
    expect(detectVelocity(new Array(12).fill(100)).high_velocity).toBe(true);
  });
  it('does not flag a normal count', () => {
    expect(detectVelocity([100, 200]).high_velocity).toBe(false);
  });
});

describe('aggregate screenAml', () => {
  it('returns allow with no context', () => {
    expect(screenAml().recommendation).toBe('allow');
    expect(screenAml({}).recommendation).toBe('allow');
  });
  it('DENIES a sanctions match (fail closed, no signoff path)', () => {
    const r = screenAml({ counterpartyName: 'Blocked Person Alpha', amount: 500 });
    expect(r.recommendation).toBe('deny');
    expect(r.risk).toBe('blocked');
    expect(r.signals.some((s) => s.startsWith('sanctions_match'))).toBe(true);
  });
  it('DENIES an embargoed jurisdiction', () => {
    const r = screenAml({ counterpartyName: 'Neutral Co', counterpartyCountry: 'KP', amount: 100 });
    expect(r.recommendation).toBe('deny');
  });
  it('escalates structuring to signoff', () => {
    const r = screenAml({ counterpartyName: 'Neutral Co', amount: 9500, recentAmounts: [9400, 9600] });
    expect(r.recommendation).toBe('signoff');
    expect(r.risk).toBe('elevated');
  });
  it('escalates high velocity to signoff', () => {
    const r = screenAml({ amount: 100, recentAmounts: new Array(15).fill(100) });
    expect(r.recommendation).toBe('signoff');
  });
  it('allows a clean transaction', () => {
    const r = screenAml({ counterpartyName: 'Acme Widgets', amount: 2500, recentAmounts: [1000] });
    expect(r.recommendation).toBe('allow');
  });
});

describe('guard-policy AML integration', () => {
  const fin = (aml, extra = {}) => evaluateGuardPolicy({
    organizationId: 'org', actorId: 'a', actorRole: 'system',
    actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, targetChangedFields: [],
    amount: 2000, riskFlags: [], authStrength: 'mfa', aml, ...extra,
  });

  it('a sanctions hit DENIES even an otherwise-allowed action', () => {
    const d = fin({ counterpartyName: 'Blocked Person Alpha' });
    expect(d.decision).toBe(GUARD_DECISIONS.DENY);
    expect(d.aml_signals.some((s) => s.startsWith('sanctions_match'))).toBe(true);
  });

  it('structuring escalates an allow to allow_with_signoff', () => {
    const d = fin({ amount: 9500, recentAmounts: [9400, 9600] });
    expect(d.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(d.signoffRequired).toBe(true);
    expect(d.aml_signals.some((s) => s.startsWith('structuring'))).toBe(true);
  });

  it('a clean action with AML context contributes no AML signals (base decision unchanged by AML)', () => {
    // AML intent: a clean counterparty produces NO aml_signals and does NOT
    // escalate. The base decision here is allow_with_signoff purely because of
    // the mint-time key-class floor on large_payment_release (independent of
    // AML). Compare it against the same call WITHOUT AML context to prove AML
    // contributed nothing: identical decision, and no aml_signals field.
    const withAml = fin({ counterpartyName: 'Acme Widgets', amount: 2000 });
    const withoutAml = evaluateGuardPolicy({
      organizationId: 'org', actorId: 'a', actorRole: 'system',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, targetChangedFields: [],
      amount: 2000, riskFlags: [], authStrength: 'mfa',
    });
    expect(withAml.aml_signals).toBeUndefined();
    expect(withAml.decision).toBe(withoutAml.decision);
    expect(withAml.signoffRequired).toBe(withoutAml.signoffRequired);
  });

  it('AML never weakens an existing signoff requirement (large payment stays signoff)', () => {
    const d = evaluateGuardPolicy({
      organizationId: 'org', actorId: 'a', actorRole: 'system',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, targetChangedFields: [],
      amount: 250000, riskFlags: [], authStrength: 'mfa',
      aml: { counterpartyName: 'Acme Widgets', amount: 250000 },
    });
    expect(d.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect(d.signoffTier).toBe('single');
  });

  it('omitting AML context preserves the exact non-AML decision shape (no aml_signals field)', () => {
    // AML intent: with no AML context, the result carries no aml_signals field
    // at all — the AML layer is a pure no-op. The decision itself is
    // allow_with_signoff because of the key-class floor on large_payment_release
    // (a base-policy property, not an AML one).
    const d = evaluateGuardPolicy({
      organizationId: 'org', actorId: 'a', actorRole: 'system',
      actionType: GUARD_ACTION_TYPES.LARGE_PAYMENT_RELEASE, targetChangedFields: [],
      amount: 2000, riskFlags: [], authStrength: 'mfa',
    });
    expect(d.decision).toBe(GUARD_DECISIONS.ALLOW_WITH_SIGNOFF);
    expect('aml_signals' in d).toBe(false);
  });
});
