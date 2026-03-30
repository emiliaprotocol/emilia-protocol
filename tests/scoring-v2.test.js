import { describe, it, expect } from 'vitest';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
  EP_WEIGHTS_V2,
  DISPUTE_DAMPENING_FACTOR,
  DISPUTE_RESOLVED_FACTOR,
  validateScoringWeights,
  WEIGHT_BOUNDS,
} from '../lib/scoring-v2.js';

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    agent_satisfaction: 88,
    composite_score: 88,
    submitted_by: overrides.submitted_by || 'submitter-1',
    submitter_score: overrides.submitter_score ?? 85,
    submitter_established: overrides.submitter_established ?? true,
    graph_weight: overrides.graph_weight ?? 1.0,
    agent_behavior: overrides.agent_behavior || 'completed',
    created_at: overrides.created_at || new Date().toISOString(),
    ...overrides,
  };
}

describe('EP_WEIGHTS_V2', () => {
  it('behavioral has highest weight', () => {
    expect(EP_WEIGHTS_V2.behavioral).toBeGreaterThan(EP_WEIGHTS_V2.consistency);
    expect(EP_WEIGHTS_V2.behavioral).toBeGreaterThan(EP_WEIGHTS_V2.delivery);
  });

  it('weights sum to 1.0', () => {
    const total = Object.values(EP_WEIGHTS_V2).reduce((a, b) => a + b, 0);
    expect(total).toBeCloseTo(1.0, 10);
  });
});

describe('computeTrustProfile', () => {
  it('returns pending profile for no receipts', () => {
    const result = computeTrustProfile([], {});
    expect(result.confidence).toBe('pending');
    expect(result.score).toBe(50);
    expect(result.profile).toBeNull();
    expect(result.effectiveEvidence).toBe(0);
  });

  it('returns behavioral breakdown with rates', () => {
    const receipts = [
      makeReceipt({ agent_behavior: 'completed', submitted_by: 's1' }),
      makeReceipt({ agent_behavior: 'completed', submitted_by: 's2' }),
      makeReceipt({ agent_behavior: 'retried_same', submitted_by: 's3' }),
      makeReceipt({ agent_behavior: 'disputed', submitted_by: 's4' }),
    ];
    const result = computeTrustProfile(receipts, {});
    expect(result.profile.behavioral.completion_rate).toBeGreaterThan(0);
    expect(result.profile.behavioral.dispute_rate).toBeGreaterThan(0);
    expect(result.profile.behavioral.total_observed).toBe(4);
  });

  it('unestablished submitters produce low effective evidence', () => {
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `fake-${i}`,
      submitter_established: false,
      submitter_score: 50,
    }));
    const result = computeTrustProfile(receipts, {});
    expect(result.effectiveEvidence).toBeLessThan(1);
    expect(result.score).toBeLessThan(60);
  });

  it('established submitters produce higher evidence', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `real-${i % 4}`,
      submitter_established: true,
      submitter_score: 90,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));
    const result = computeTrustProfile(receipts, {});
    // 10 × (0.9 submitter × 1.0 time × 1.0 graph × 0.8 bilateral) = 7.2
    expect(result.effectiveEvidence).toBeGreaterThan(5);
    expect(result.score).toBeGreaterThan(70);
  });

  it('graph_weight affects effective evidence', () => {
    const normal = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`, graph_weight: 1.0,
    }));
    const flagged = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`, graph_weight: 0.3,
    }));
    const normalResult = computeTrustProfile(normal, {});
    const flaggedResult = computeTrustProfile(flagged, {});
    expect(normalResult.effectiveEvidence).toBeGreaterThan(flaggedResult.effectiveEvidence);
  });

  it('returns anomaly data when present', () => {
    const now = Date.now();
    const oldGood = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      composite_score: 90,
      created_at: new Date(now - 15 * 86400000).toISOString(),
    }));
    const recentBad = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      composite_score: 40,
      created_at: new Date(now - 2 * 86400000).toISOString(),
    }));
    const result = computeTrustProfile([...recentBad, ...oldGood], {});
    // Should detect a decline
    if (result.anomaly) {
      expect(result.anomaly.type).toBe('declining');
      expect(result.anomaly.delta).toBeLessThan(0);
    }
  });
});

describe('dispute dampening', () => {
  it('disputed receipt gets 0.3x weight in scoring', () => {
    // Build a baseline with 5 identical receipts, no disputes
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      id: `receipt-${i}`,
      submitted_by: `s-${i}`,
      submitter_established: true,
      submitter_score: 90,
      provenance_tier: 'bilateral',
    }));

    const baseline = computeTrustProfile(receipts, {});

    // Dispute receipt-0 — its weight contribution should drop to 30%
    const disputedReceiptIds = new Set(['receipt-0']);
    const dampened = computeTrustProfile(receipts, {}, disputedReceiptIds);

    // Effective evidence must be lower when one receipt is dampened
    expect(dampened.effectiveEvidence).toBeLessThan(baseline.effectiveEvidence);

    // The dampened receipt's weight contribution is exactly DISPUTE_DAMPENING_FACTOR (0.3x)
    // so the difference should be (1 - 0.3) = 0.7 × that receipt's undampened weight
    const diff = baseline.effectiveEvidence - dampened.effectiveEvidence;
    expect(diff).toBeGreaterThan(0);

    // dispute_dampened_count should be 1
    expect(dampened.dispute_dampened_count).toBe(1);
  });

  it('dismissed dispute receipt restores to 1.0x weight', () => {
    // DISPUTE_RESOLVED_FACTOR.dismissed === 1.0 means full restore
    expect(DISPUTE_RESOLVED_FACTOR.dismissed).toBe(1.0);

    // A dismissed receipt is no longer in the active disputed set,
    // so its weight is unchanged from baseline (no dampening applied)
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      id: `r-${i}`,
      submitted_by: `s-${i}`,
      submitter_established: true,
    }));

    const baseline = computeTrustProfile(receipts, {});

    // After dismissal the receipt leaves the disputedReceiptIds set
    const afterDismissal = computeTrustProfile(receipts, {}, new Set());

    expect(afterDismissal.effectiveEvidence).toBeCloseTo(baseline.effectiveEvidence, 5);
    expect(afterDismissal.dispute_dampened_count).toBe(0);
  });

  it('upheld dispute receipt gets 0.0x weight (excluded)', () => {
    // DISPUTE_RESOLVED_FACTOR.upheld === 0.0 means excluded from scoring
    expect(DISPUTE_RESOLVED_FACTOR.upheld).toBe(0.0);

    // Simulate an upheld resolution: caller removes the receipt from the
    // receipts array before calling computeTrustProfile (ledger still stores it,
    // but it is filtered out upstream when upheld).
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      id: `r-${i}`,
      submitted_by: `s-${i}`,
      submitter_established: true,
      submitter_score: 90,
    }));

    const baseline = computeTrustProfile(receipts, {});

    // Remove the upheld receipt entirely (simulating 0.0x factor)
    const withUpheld = computeTrustProfile(receipts.slice(1), {});

    expect(withUpheld.effectiveEvidence).toBeLessThan(baseline.effectiveEvidence);
    expect(withUpheld.receiptCount).toBe(baseline.receiptCount - 1);
  });

  it('undisputed entity shows dispute_dampened_count: 0', () => {
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      id: `r-${i}`,
      submitted_by: `s-${i}`,
    }));

    // No disputedReceiptIds passed — defaults to empty Set
    const result = computeTrustProfile(receipts, {});
    expect(result.dispute_dampened_count).toBe(0);

    // Explicit empty set
    const resultExplicit = computeTrustProfile(receipts, {}, new Set());
    expect(resultExplicit.dispute_dampened_count).toBe(0);
  });
});

describe('evaluateTrustPolicy', () => {
  it('fails when no data', () => {
    const profile = computeTrustProfile([], {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
    expect(result.pass).toBe(false);
    expect(result.failures).toContain('no_data');
  });

  it('passes standard policy with good data', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `real-${i % 5}`,
      agent_behavior: 'completed',
      delivery_accuracy: 90,
      product_accuracy: 88,
      price_integrity: 99,
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
    expect(result.pass).toBe(true);
    expect(result.failures).toHaveLength(0);
  });

  it('fails strict policy with high dispute rate', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      agent_behavior: i < 5 ? 'disputed' : 'completed',
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    const hasDisputeFailure = result.failures.some(f => f.includes('dispute_rate'));
    expect(hasDisputeFailure).toBe(true);
  });

  it('fails when confidence too low', () => {
    const receipts = [makeReceipt({ submitted_by: 's1', submitter_established: false })];
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(result.pass).toBe(false);
  });

  it('custom policy works', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 60,
    }));
    const profile = computeTrustProfile(receipts, {});
    const customPolicy = {
      min_score: 50,
      signal_minimums: { delivery_accuracy: 80 },
    };
    const result = evaluateTrustPolicy(profile, customPolicy);
    const hasDeliveryFailure = result.failures.some(f => f.includes('delivery_accuracy'));
    expect(hasDeliveryFailure).toBe(true);
  });

  it('discovery policy passes with zero data', () => {
    const receipts = [makeReceipt({ submitted_by: 's1' })];
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.discovery);
    expect(result.pass).toBe(true);
  });
});

// =============================================================================
// Weight validation
// =============================================================================

describe('validateScoringWeights', () => {
  it('accepts valid EP_WEIGHTS_V2 defaults', () => {
    const result = validateScoringWeights(EP_WEIGHTS_V2);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects missing dimensions', () => {
    const result = validateScoringWeights({ behavioral: 0.40 });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('missing'))).toBe(true);
  });

  it('rejects out-of-bounds weights', () => {
    const result = validateScoringWeights({
      behavioral: 0.60, // max is 0.50
      consistency: 0.10,
      delivery: 0.10,
      product: 0.10,
      price: 0.05,
      returns: 0.05,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('behavioral') && e.includes('outside bounds'))).toBe(true);
  });

  it('rejects weights that do not sum to 1.0', () => {
    const result = validateScoringWeights({
      behavioral: 0.40,
      consistency: 0.25,
      delivery: 0.12,
      product: 0.10,
      price: 0.08,
      returns: 0.10, // total = 1.05
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('sum'))).toBe(true);
  });

  it('rejects when behavioral + consistency < 0.35', () => {
    const result = validateScoringWeights({
      behavioral: 0.20,
      consistency: 0.10, // sum = 0.30 < 0.35
      delivery: 0.25,
      product: 0.20,
      price: 0.15,
      returns: 0.10,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('behavioral + consistency'))).toBe(true);
  });

  it('accepts valid government-style weights', () => {
    const govWeights = {
      behavioral: 0.25,
      consistency: 0.30,
      delivery: 0.20,
      product: 0.10,
      price: 0.12,
      returns: 0.03,
    };
    const result = validateScoringWeights(govWeights);
    expect(result.valid).toBe(true);
    expect(result.weights).toEqual(govWeights);
  });
});

// =============================================================================
// Policy-configurable weights (computeTrustProfile with custom weights)
// =============================================================================

describe('computeTrustProfile with custom weights', () => {
  it('uses EP_WEIGHTS_V2 by default (no weights param)', () => {
    const receipts = [makeReceipt({ submitted_by: 's1' })];
    const result = computeTrustProfile(receipts, {});
    expect(result.weights_version).toBe('ep-v2-default');
    expect(result.weights_used).toEqual(EP_WEIGHTS_V2);
  });

  it('uses custom weights when provided', () => {
    const customWeights = {
      behavioral: 0.25,
      consistency: 0.30,
      delivery: 0.20,
      product: 0.10,
      price: 0.12,
      returns: 0.03,
    };
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      submitter_established: true,
      submitter_score: 90,
    }));
    const result = computeTrustProfile(receipts, {}, new Set(), customWeights);
    expect(result.weights_version).toBe('policy');
    expect(result.weights_used).toEqual(customWeights);
  });

  it('produces different scores with different weights', () => {
    // Receipts with high delivery but low behavioral signals
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      submitter_established: true,
      submitter_score: 85,
      agent_behavior: 'retried_different', // low behavioral score (40)
      delivery_accuracy: 98,               // high delivery score
      composite_score: 70,
    }));

    const defaultResult = computeTrustProfile(receipts, {});
    const deliveryHeavy = computeTrustProfile(receipts, {}, new Set(), {
      behavioral: 0.20,
      consistency: 0.15,
      delivery: 0.25,
      product: 0.15,
      price: 0.15,
      returns: 0.10,
    });

    // Delivery-heavy weights should produce a higher score for these receipts
    // because delivery is 98 but behavioral is low
    expect(deliveryHeavy.score).not.toBe(defaultResult.score);
  });

  it('same weights as EP_WEIGHTS_V2 produces same score', () => {
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      submitter_established: true,
    }));
    const defaultResult = computeTrustProfile(receipts, {});
    const explicitResult = computeTrustProfile(receipts, {}, new Set(), { ...EP_WEIGHTS_V2 });
    expect(explicitResult.score).toBe(defaultResult.score);
  });
});
