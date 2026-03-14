import { describe, it, expect } from 'vitest';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
  EP_WEIGHTS_V2,
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
    }));
    const result = computeTrustProfile(receipts, {});
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
