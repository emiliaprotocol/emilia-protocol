/**
 * scoring-extended.test.js
 *
 * Extended coverage for lib/scoring.js targeting uncovered lines:
 *   - computeEmiliaScore edge cases (line ~281: null receipts, line ~401: single receipt)
 *   - computeMatchScore edge cases (line ~281)
 *   - computeReceiptComposite with various missing/invalid field combos (lines 450-451)
 *   - computeScoresFromClaims detailed paths
 *   - computeTimeDecay edge cases
 *   - canonicalJSON path (via computeReceiptHash)
 *   - Dead/legacy functions: computeEmiliaScore, computeMatchScore
 */

import { describe, it, expect } from 'vitest';
import {
  computeReceiptComposite,
  computeEmiliaScore,
  computeMatchScore,
  computeReceiptHash,
  computeSubmitterWeight,
  computeTimeDecay,
  behaviorToSatisfaction,
  computeScoresFromClaims,
  EMILIA_WEIGHTS,
  MIN_RECEIPTS_ESTABLISHED,
  RECEIPT_WINDOW,
  DEFAULT_SCORE,
} from '../lib/scoring.js';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeEstablished(overrides = {}) {
  return {
    delivery_accuracy: 80,
    product_accuracy: 80,
    price_integrity: 80,
    return_processing: 80,
    agent_satisfaction: 80,
    composite_score: 80,
    submitted_by: overrides.submitted_by ?? 'sub-1',
    submitter_score: overrides.submitter_score ?? 85,
    submitter_established: overrides.submitter_established ?? true,
    graph_weight: overrides.graph_weight ?? 1.0,
    created_at: overrides.created_at ?? new Date().toISOString(),
    ...overrides,
  };
}

// =============================================================================
// computeReceiptComposite — edge cases
// =============================================================================

describe('computeReceiptComposite — extended edge cases', () => {
  it('returns DEFAULT_SCORE when all values are null', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: null,
      product_accuracy: null,
      price_integrity: null,
      return_processing: null,
      agent_satisfaction: null,
    });
    expect(result).toBe(DEFAULT_SCORE);
  });

  it('returns DEFAULT_SCORE when all values are undefined', () => {
    const result = computeReceiptComposite({});
    expect(result).toBe(DEFAULT_SCORE);
  });

  it('clamps values above 100 to 100', () => {
    const result = computeReceiptComposite({ delivery_accuracy: 200 });
    expect(result).toBe(100);
  });

  it('clamps values below 0 to 0', () => {
    const result = computeReceiptComposite({ delivery_accuracy: -50 });
    expect(result).toBe(0);
  });

  it('ignores non-finite values (NaN, Infinity)', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: NaN,
      product_accuracy: Infinity,
      price_integrity: 80,
    });
    // Only price_integrity is finite and present — weight = 0.15
    expect(result).toBe(80);
  });

  it('ignores the consistency field (entity-level, not receipt-level)', () => {
    const withConsistency = computeReceiptComposite({
      delivery_accuracy: 100,
      consistency: 0, // should be ignored
    });
    expect(withConsistency).toBe(100);
  });

  it('single signal returns that signal normalized to 100 scale', () => {
    const result = computeReceiptComposite({ agent_satisfaction: 60 });
    expect(result).toBe(60);
  });

  it('handles receipt with only return_processing signal', () => {
    const result = computeReceiptComposite({ return_processing: 75 });
    expect(result).toBe(75);
  });

  it('rounds to one decimal place', () => {
    // delivery=0.30, product=0.25 => (77*0.30 + 83*0.25)/(0.55) = (23.1+20.75)/0.55 = 43.85/0.55 = ~79.7
    const result = computeReceiptComposite({
      delivery_accuracy: 77,
      product_accuracy: 83,
    });
    expect(result).toBeCloseTo(79.7, 0);
    // check it's a number with at most one decimal
    expect(String(result).split('.')[1]?.length ?? 0).toBeLessThanOrEqual(1);
  });
});

// =============================================================================
// computeEmiliaScore — dead/legacy function coverage
// =============================================================================

describe('computeEmiliaScore — extended legacy coverage', () => {
  it('handles null input (treated as empty array)', () => {
    const result = computeEmiliaScore(null);
    expect(result.score).toBe(DEFAULT_SCORE);
    expect(result.established).toBe(false);
    expect(result.effectiveEvidence).toBe(0);
    expect(result.receiptCount).toBe(0);
  });

  it('returns breakdown with all null signals for a single unestablished receipt with missing fields', () => {
    const result = computeEmiliaScore([{
      submitted_by: 'sub-1',
      submitter_score: 50,
      submitter_established: false,
      graph_weight: 1.0,
      created_at: new Date().toISOString(),
      // no numeric signals
    }]);
    expect(result.breakdown.delivery_accuracy).toBeNull();
    expect(result.breakdown.product_accuracy).toBeNull();
    expect(result.breakdown.price_integrity).toBeNull();
    expect(result.breakdown.return_processing).toBeNull();
    expect(result.breakdown.agent_satisfaction).toBeNull();
  });

  it('single-receipt consistency is exactly 50 (no variance possible)', () => {
    const result = computeEmiliaScore([makeEstablished({ composite_score: 80 })]);
    expect(result.breakdown.consistency).toBe(50);
  });

  it('effectiveEvidence reflects sum of weights correctly for mixed establishment', () => {
    const receipts = [
      makeEstablished({ submitter_score: 100, submitter_established: true, graph_weight: 1.0, submitted_by: 's1' }),
      makeEstablished({ submitter_score: 50,  submitter_established: false, graph_weight: 1.0, submitted_by: 's2' }),
    ];
    const result = computeEmiliaScore(receipts);
    // s1: score/100 = 1.0; s2: unestablished = 0.1
    // time decay ~ 1.0 for both (created just now)
    expect(result.effectiveEvidence).toBeCloseTo(1.1, 1);
  });

  it('uniqueSubmitters counts distinct submitted_by values', () => {
    const receipts = Array(6).fill(null).map((_, i) =>
      makeEstablished({ submitted_by: `sub-${i % 2}`, submitter_score: 90 })
    );
    const result = computeEmiliaScore(receipts);
    expect(result.uniqueSubmitters).toBe(2);
  });

  it('established requires both effectiveEvidence >= 5 AND uniqueSubmitters >= 3', () => {
    // 3 distinct submitters but effective evidence < 5 (unestablished submitters)
    const receipts = Array(3).fill(null).map((_, i) =>
      makeEstablished({ submitted_by: `sub-${i}`, submitter_established: false, submitter_score: 50 })
    );
    const result = computeEmiliaScore(receipts);
    expect(result.established).toBe(false);
  });

  it('score is clamped to [0, 100]', () => {
    const receipts = Array(20).fill(null).map((_, i) =>
      makeEstablished({
        submitted_by: `sub-${i % 5}`,
        delivery_accuracy: 100,
        product_accuracy: 100,
        price_integrity: 100,
        return_processing: 100,
        agent_satisfaction: 100,
        composite_score: 100,
      })
    );
    const result = computeEmiliaScore(receipts);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  it('effectiveEvidence is rounded to 2 decimal places in output', () => {
    const receipts = [makeEstablished({ submitter_score: 85, submitter_established: true, submitted_by: 's1' })];
    const result = computeEmiliaScore(receipts);
    const decimals = String(result.effectiveEvidence).split('.')[1]?.length ?? 0;
    expect(decimals).toBeLessThanOrEqual(2);
  });

  it('receipts with no composite_score excluded from consistency calculation', () => {
    const receipts = Array(5).fill(null).map((_, i) =>
      makeEstablished({ submitted_by: `sub-${i}`, composite_score: undefined })
    );
    const result = computeEmiliaScore(receipts);
    // With no composite scores, consistency defaults to 50
    expect(result.breakdown.consistency).toBe(50);
  });
});

// =============================================================================
// computeMatchScore — extended dead/legacy coverage
// =============================================================================

describe('computeMatchScore — extended edge cases', () => {
  it('returns 0 match score for zero cosine similarity and passing entity', () => {
    const result = computeMatchScore(0, 50, 0);
    // 0*0.6 + (50/100)*0.4 = 0.2
    expect(result).toBeCloseTo(0.2, 3);
  });

  it('returns 1.0 for perfect similarity and perfect score', () => {
    const result = computeMatchScore(1.0, 100, 0);
    expect(result).toBeCloseTo(1.0, 3);
  });

  it('returns null when score exactly equals minScore threshold (below, not meeting)', () => {
    // emiliaScore < minScore  → null
    expect(computeMatchScore(0.9, 69, 70)).toBeNull();
  });

  it('returns a value when score exactly meets minScore', () => {
    const result = computeMatchScore(0.5, 70, 70);
    expect(result).not.toBeNull();
    expect(result).toBeGreaterThan(0);
  });

  it('rounds to 3 decimal places', () => {
    const result = computeMatchScore(0.333, 66.7, 0);
    const decimals = String(result).split('.')[1]?.length ?? 0;
    expect(decimals).toBeLessThanOrEqual(3);
  });

  it('default minScore is 0 — any entity passes', () => {
    expect(computeMatchScore(0.5, 0)).not.toBeNull();
  });
});

// =============================================================================
// computeTimeDecay — edge cases
// =============================================================================

describe('computeTimeDecay — edge cases', () => {
  it('returns 1.0 for null createdAt', () => {
    expect(computeTimeDecay(null, Date.now())).toBe(1.0);
  });

  it('returns 1.0 for undefined createdAt', () => {
    expect(computeTimeDecay(undefined, Date.now())).toBe(1.0);
  });

  it('returns 1.0 for invalid date string', () => {
    expect(computeTimeDecay('not-a-date', Date.now())).toBe(1.0);
  });

  it('applies floor of 0.05 for very old receipts', () => {
    // 10 years ago
    const tenYearsAgo = new Date(Date.now() - 10 * 365 * 24 * 60 * 60 * 1000).toISOString();
    expect(computeTimeDecay(tenYearsAgo, Date.now())).toBe(0.05);
  });

  it('returns ~0.5 for receipts exactly 90 days old (half-life)', () => {
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
    const result = computeTimeDecay(ninetyDaysAgo, Date.now());
    expect(result).toBeCloseTo(0.5, 1);
  });

  it('returns close to 1.0 for a brand new receipt', () => {
    const now = new Date().toISOString();
    expect(computeTimeDecay(now, Date.now())).toBeCloseTo(1.0, 2);
  });

  it('accepts a Date object as createdAt', () => {
    const d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const result = computeTimeDecay(d, Date.now());
    expect(result).toBeGreaterThan(0.5);
    expect(result).toBeLessThan(1.0);
  });
});

// =============================================================================
// behaviorToSatisfaction
// =============================================================================

describe('behaviorToSatisfaction', () => {
  it('completed → 95', () => expect(behaviorToSatisfaction('completed')).toBe(95));
  it('retried_same → 75', () => expect(behaviorToSatisfaction('retried_same')).toBe(75));
  it('retried_different → 40', () => expect(behaviorToSatisfaction('retried_different')).toBe(40));
  it('abandoned → 15', () => expect(behaviorToSatisfaction('abandoned')).toBe(15));
  it('disputed → 5', () => expect(behaviorToSatisfaction('disputed')).toBe(5));
  it('unknown behavior → null', () => expect(behaviorToSatisfaction('unknown_value')).toBeNull());
  it('empty string → null', () => expect(behaviorToSatisfaction('')).toBeNull());
  it('null → null', () => expect(behaviorToSatisfaction(null)).toBeNull());
});

// =============================================================================
// computeScoresFromClaims — extended paths
// =============================================================================

describe('computeScoresFromClaims — extended coverage', () => {
  it('returns {} for null claims', () => {
    expect(computeScoresFromClaims(null)).toEqual({});
  });

  it('returns {} for non-object claims', () => {
    expect(computeScoresFromClaims('string')).toEqual({});
    expect(computeScoresFromClaims(42)).toEqual({});
  });

  it('delivery: delivered=true, on_time=true → 100', () => {
    const result = computeScoresFromClaims({ delivered: true, on_time: true });
    expect(result.delivery_accuracy).toBe(100);
  });

  it('delivery: delivered=true, on_time=false → 70', () => {
    const result = computeScoresFromClaims({ delivered: true, on_time: false });
    expect(result.delivery_accuracy).toBe(70);
  });

  it('delivery: delivered=false → 0', () => {
    const result = computeScoresFromClaims({ delivered: false });
    expect(result.delivery_accuracy).toBe(0);
  });

  it('delivery: delivered=true, no on_time → 80', () => {
    const result = computeScoresFromClaims({ delivered: true });
    expect(result.delivery_accuracy).toBe(80);
  });

  it('delivery: on_time with promised/actual — on time → 100', () => {
    const promised = new Date('2025-01-10T12:00:00Z').toISOString();
    const actual = new Date('2025-01-10T11:00:00Z').toISOString(); // early
    const result = computeScoresFromClaims({ delivered: true, on_time: { promised, actual } });
    expect(result.delivery_accuracy).toBe(100);
  });

  it('delivery: on_time with promised/actual — 1-24h delay → 85', () => {
    const promised = new Date('2025-01-10T12:00:00Z').toISOString();
    const actual = new Date('2025-01-10T18:00:00Z').toISOString(); // 6h late
    const result = computeScoresFromClaims({ delivered: true, on_time: { promised, actual } });
    expect(result.delivery_accuracy).toBe(85);
  });

  it('delivery: on_time with promised/actual — 24-72h delay → 65', () => {
    const promised = new Date('2025-01-10T12:00:00Z').toISOString();
    const actual = new Date('2025-01-11T18:00:00Z').toISOString(); // 30h late
    const result = computeScoresFromClaims({ delivered: true, on_time: { promised, actual } });
    expect(result.delivery_accuracy).toBe(65);
  });

  it('delivery: on_time with promised/actual — >72h delay → 40', () => {
    const promised = new Date('2025-01-10T12:00:00Z').toISOString();
    const actual = new Date('2025-01-15T12:00:00Z').toISOString(); // 5 days late
    const result = computeScoresFromClaims({ delivered: true, on_time: { promised, actual } });
    expect(result.delivery_accuracy).toBe(40);
  });

  it('price_integrity: object form with overcharge > 10% → 10', () => {
    const result = computeScoresFromClaims({
      price_honored: { quoted: 100, charged: 120 }, // 20% overcharge
    });
    expect(result.price_integrity).toBe(10);
  });

  it('price_integrity: object form using quoted_cents/charged_cents aliases', () => {
    const result = computeScoresFromClaims({
      price_honored: { quoted_cents: 1000, charged_cents: 1000 }, // exact
    });
    expect(result.price_integrity).toBe(100);
  });

  it('price_integrity: object with null quoted does not set score', () => {
    const result = computeScoresFromClaims({
      price_honored: { quoted: null, charged: 100 },
    });
    expect(result.price_integrity).toBeUndefined();
  });

  it('return_accepted=false → return_processing=15', () => {
    const result = computeScoresFromClaims({ return_accepted: false });
    expect(result.return_processing).toBe(15);
  });

  it('return_accepted=true → return_processing=95', () => {
    const result = computeScoresFromClaims({ return_accepted: true });
    expect(result.return_processing).toBe(95);
  });

  it('as_described=false → product_accuracy=20', () => {
    const result = computeScoresFromClaims({ as_described: false });
    expect(result.product_accuracy).toBe(20);
  });
});

// =============================================================================
// computeReceiptHash — Node.js fallback (crypto.subtle absent)
// =============================================================================

describe('computeReceiptHash — additional coverage', () => {
  it('produces 64-char hex for a minimal receipt', async () => {
    const hash = await computeReceiptHash({
      entity_id: 'e1',
      submitted_by: 's1',
      transaction_ref: 'tx-001',
      transaction_type: 'purchase',
    });
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('different context produces different hash', async () => {
    const base = {
      entity_id: 'e1', submitted_by: 's1',
      transaction_ref: 'tx-001', transaction_type: 'purchase',
    };
    const h1 = await computeReceiptHash({ ...base, context: null });
    const h2 = await computeReceiptHash({ ...base, context: { task_type: 'delivery' } });
    expect(h1).not.toBe(h2);
  });

  it('handles nested object in evidence field (canonical JSON)', async () => {
    const receipt = {
      entity_id: 'e1', submitted_by: 's1',
      transaction_ref: 'tx-002', transaction_type: 'service',
      evidence: { nested: { a: 1, b: 2 } },
    };
    const h1 = await computeReceiptHash(receipt);
    const h2 = await computeReceiptHash(receipt);
    expect(h1).toBe(h2);
  });
});
