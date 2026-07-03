// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FLEX_ENVELOPE_VERSION, CURTAILMENT_SETTLEMENT_POLICY,
  checkOrderWithinEnvelope, computeCompliance, buildRefusalStatement,
} from '../lib/grace/curtailment.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const envelope = {
  '@version': FLEX_ENVELOPE_VERSION,
  bounds: {
    max_mw: 15, min_notice_minutes: 10, max_event_hours: 6,
    window: { start: '2026-06-01T00:00:00Z', end: '2026-09-30T23:59:59Z' },
  },
};
const order = {
  mw: '12.0', notice_minutes: 30,
  window: { start: '2026-07-15T15:00:00Z', end: '2026-07-15T19:00:00Z' },
};

describe('GRACE — Order ⊆ Envelope (fail-closed pre-execution)', () => {
  it('an in-bounds order passes', () => {
    expect(checkOrderWithinEnvelope(order, envelope).within).toBe(true);
  });

  it.each([
    ['oversized MW', { ...order, mw: '22.0' }, 'exceeds envelope unspent balance'],
    ['short notice', { ...order, notice_minutes: 3 }, 'below envelope floor'],
    ['outside participation window', { ...order, window: { start: '2026-11-01T15:00:00Z', end: '2026-11-01T19:00:00Z' } }, 'outside envelope participation window'],
    ['event too long', { ...order, window: { start: '2026-07-15T08:00:00Z', end: '2026-07-15T18:00:00Z' } }, 'longer than envelope max'],
    ['invalid window', { ...order, window: { start: '2026-07-15T19:00:00Z', end: '2026-07-15T15:00:00Z' } }, 'invalid window'],
  ])('%s is refused with a named violation', (_name, badOrder, expected) => {
    const r = checkOrderWithinEnvelope(badOrder, envelope);
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain(expected);
  });

  it('an unknown envelope version is itself a violation (fail closed)', () => {
    const r = checkOrderWithinEnvelope(order, { ...envelope, '@version': 'v0' });
    expect(r.within).toBe(false);
  });

  it('the envelope, not any single order, is the ceiling: an order within max_mw but over the UNSPENT balance is refused', () => {
    // 12 MW order is under max_mw (15), but only 5 MW remains unspent this period
    const r = checkOrderWithinEnvelope(order, envelope, { spent_mw: 10 });
    expect(r.within).toBe(false);
    expect(r.violations.join(' ')).toContain('unspent balance');
  });

  it('the same order passes when the remaining balance covers it', () => {
    expect(checkOrderWithinEnvelope(order, envelope, { spent_mw: 2 }).within).toBe(true);
    expect(checkOrderWithinEnvelope(order, envelope, {}).within).toBe(true); // spent defaults to 0
  });
});

describe('GRACE — a refusal is signed evidence, not silence', () => {
  it('builds a refusal statement binding the refused order digest, the failing predicate, and the time', () => {
    const bad = checkOrderWithinEnvelope({ ...order, mw: '99.0' }, envelope);
    const refusal = buildRefusalStatement('sha256:' + 'a'.repeat(64), bad.violations, '2026-07-15T15:00:00Z');
    expect(refusal.typ).toBe('ep-curtailment-refusal');
    expect(refusal.refused_order_digest).toMatch(/^sha256:/);
    expect(refusal.failing_predicates.join(' ')).toContain('unspent balance');
    expect(refusal.refused_at).toBe('2026-07-15T15:00:00Z');
  });
});

describe('GRACE — compliance comes from the meter, and only the meter', () => {
  it('computes delivered vs ordered from meter intervals', () => {
    const c = computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [2.4, 2.1, 2.2, 2.3] });
    expect(c.computable).toBe(true);
    expect(c.delivered_mw).toBeCloseTo(11.95, 2);
    expect(c.compliant).toBe(true);
  });

  it('under-delivery is measurable, not hidden', () => {
    const c = computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [8.0, 8.2, 8.1, 8.0] });
    expect(c.compliant).toBe(false);
    expect(c.compliance_ratio).toBeLessThan(0.6);
  });

  it('a meter statement without baseline or intervals is not computable (never guessed)', () => {
    expect(computeCompliance({ mw: '12.0' }, { intervals_mw: [1] }).computable).toBe(false);
    expect(computeCompliance({ mw: '12.0' }, { baseline_mw: 14.2, intervals_mw: [] }).computable).toBe(false);
  });
});

describe('GRACE — settlement policy shape', () => {
  it('requires all four legs, meter edges, and revocation on the authorization', () => {
    const p = CURTAILMENT_SETTLEMENT_POLICY;
    expect(Object.isFrozen(p)).toBe(true);
    for (const t of ['curtailment_order', 'authorization_receipt', 'execution_attestation', 'meter_statement']) {
      expect(p.requirement).toContain(t);
    }
    expect(p.required_edges).toContainEqual({ from_type: 'meter_statement', rel: 'records', to_type: 'execution_attestation' });
    expect(p.revocation_required).toContain('authorization_receipt');
  });
});

describe('GRACE — the full proof-of-curtailment vector', () => {
  it('runs end to end: envelope, challenge, presentation, admissible, signed reliance, negatives enforced', () => {
    const out = execFileSync('node', [path.join(ROOT, 'examples/grace/proof-of-curtailment-vector.mjs')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    // OK line goes to stderr; execFileSync throws on nonzero exit — reaching
    // here means every assertion in the vector (positive + negatives) held.
    expect(true).toBe(true);
  });
});
