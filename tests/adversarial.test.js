import { describe, it, expect } from 'vitest';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
} from '../lib/scoring-v2.js';

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90, product_accuracy: 85, price_integrity: 95,
    return_processing: 80, agent_satisfaction: 88, composite_score: 88,
    submitted_by: overrides.submitted_by || 'attacker-1',
    submitter_score: overrides.submitter_score ?? 50,
    submitter_established: overrides.submitter_established ?? false,
    graph_weight: overrides.graph_weight ?? 1.0,
    agent_behavior: overrides.agent_behavior || 'completed',
    created_at: overrides.created_at || new Date().toISOString(),
    context: overrides.context || null,
    provenance_tier: overrides.provenance_tier || 'self_attested',
    bilateral_status: overrides.bilateral_status || null,
    ...overrides,
  };
}

// ============================================================================
// ADVERSARIAL: Sybil attacks
// ============================================================================

describe('ADVERSARIAL: Sybil farm — many fake entities', () => {
  it('100 receipts from 100 unestablished entities = low trust', () => {
    const receipts = Array(100).fill(null).map((_, i) => makeReceipt({
      submitted_by: `sybil-${i}`,
      submitter_established: false,
      submitter_score: 50,
      composite_score: 100,
      delivery_accuracy: 100,
      product_accuracy: 100,
      price_integrity: 100,
    }));
    const profile = computeTrustProfile(receipts, {});
    // Quality gate: unestablished evidence capped at 2.0 → cannot establish
    expect(profile.score).toBeLessThan(70);
    expect(profile.established).toBe(false);
    expect(profile.confidence).not.toBe('confident');
    expect(profile.confidence).not.toBe('emerging');
    expect(profile.qualityGatedEvidence).toBeLessThan(5);
  });

  it('50 perfect receipts from 5 fake submitters = still low', () => {
    const receipts = Array(50).fill(null).map((_, i) => makeReceipt({
      submitted_by: `fake-${i % 5}`,
      submitter_established: false,
      composite_score: 100,
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeLessThan(70);
    expect(profile.uniqueSubmitters).toBe(5);
  });
});

// ============================================================================
// ADVERSARIAL: Reciprocal loops
// ============================================================================

describe('ADVERSARIAL: Reciprocal loops (A scores B, B scores A)', () => {
  it('closed-loop receipts (graph_weight 0.4) produce limited evidence', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `loop-partner-${i % 2}`,
      submitter_established: true,
      submitter_score: 90,
      graph_weight: 0.4, // Closed-loop penalty
      composite_score: 98,
    }));
    const profile = computeTrustProfile(receipts, {});
    // Even with established submitters, 0.4x graph weight limits evidence
    expect(profile.effectiveEvidence).toBeLessThan(10);
  });
});

// ============================================================================
// ADVERSARIAL: Cluster collusion
// ============================================================================

describe('ADVERSARIAL: Cluster collusion (ring of entities)', () => {
  it('cluster-flagged receipts (0.1x) produce near-zero trust', () => {
    const receipts = Array(30).fill(null).map((_, i) => makeReceipt({
      submitted_by: `cluster-node-${i % 6}`,
      submitter_established: true,
      submitter_score: 95,
      graph_weight: 0.1, // Cluster penalty
      composite_score: 100,
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.effectiveEvidence).toBeLessThan(2);
    expect(profile.score).toBeLessThan(66);
  });
});

// ============================================================================
// ADVERSARIAL: Trust farming over time
// ============================================================================

describe('ADVERSARIAL: Trust farming (slow buildup of fake receipts)', () => {
  it('old fake receipts decay away', () => {
    const now = Date.now();
    const receipts = Array(50).fill(null).map((_, i) => makeReceipt({
      submitted_by: `farmer-${i % 10}`,
      submitter_established: false,
      composite_score: 100,
      created_at: new Date(now - (180 + i) * 86400000).toISOString(), // 6+ months old
    }));
    const profile = computeTrustProfile(receipts, {});
    // Old + unestablished + self_attested = very low weight
    expect(profile.effectiveEvidence).toBeLessThan(1);
    expect(profile.score).toBeLessThan(56);
  });
});

// ============================================================================
// ADVERSARIAL: Context poisoning
// ============================================================================

describe('ADVERSARIAL: Context poisoning (good in one context, bad in another)', () => {
  it('entity with split behavior shows different profiles per context', () => {
    const good = Array(15).fill(null).map((_, i) => makeReceipt({
      submitted_by: `legit-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      delivery_accuracy: 95,
      composite_score: 95,
      context: { category: 'electronics' },
    }));
    const bad = Array(15).fill(null).map((_, i) => makeReceipt({
      submitted_by: `legit-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      delivery_accuracy: 30,
      composite_score: 35,
      agent_behavior: 'disputed',
      context: { category: 'furniture' },
    }));

    const elecProfile = computeTrustProfile(good, {});
    const furnProfile = computeTrustProfile(bad, {});
    const globalProfile = computeTrustProfile([...good, ...bad], {});

    // Electronics: good
    expect(elecProfile.score).toBeGreaterThan(75);
    // Furniture: bad
    expect(furnProfile.score).toBeLessThan(55);
    // Global: mixed
    expect(globalProfile.score).toBeGreaterThan(furnProfile.score);
    expect(globalProfile.score).toBeLessThan(elecProfile.score);
  });
});

// ============================================================================
// ADVERSARIAL: Reversed receipts
// ============================================================================

describe('ADVERSARIAL: Reversed receipts (graph_weight = 0)', () => {
  it('reversed receipts have zero contribution', () => {
    const receipts = [
      makeReceipt({ submitted_by: 's1', submitter_established: true, submitter_score: 90, composite_score: 95, graph_weight: 1.0 }),
      makeReceipt({ submitted_by: 's2', submitter_established: true, submitter_score: 90, composite_score: 10, graph_weight: 0.0 }), // REVERSED
      makeReceipt({ submitted_by: 's3', submitter_established: true, submitter_score: 90, composite_score: 90, graph_weight: 1.0 }),
    ];
    const profile = computeTrustProfile(receipts, {});
    // The reversed bad receipt (graph_weight=0) should not drag down the score
    // Score stays above baseline (50) — the two good receipts dominate
    expect(profile.score).toBeGreaterThan(50);
  });

  it('all reversed = empty profile', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      graph_weight: 0.0,
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.effectiveEvidence).toBe(0);
    expect(profile.score).toBe(50);
  });
});

// ============================================================================
// ADVERSARIAL: Low-quality volume attack
// ============================================================================

describe('ADVERSARIAL: Volume of low-quality self-attested receipts', () => {
  it('200 self-attested receipts from unestablished submitters = limited trust', () => {
    const receipts = Array(200).fill(null).map((_, i) => makeReceipt({
      submitted_by: `spammer-${i}`,
      submitter_established: false,
      submitter_score: 50,
      provenance_tier: 'self_attested',
      composite_score: 90,
    }));
    const profile = computeTrustProfile(receipts, {});
    // 200 × 0.1 submitter × 0.3 provenance = ~6 raw effective evidence
    // But qualityGatedEvidence caps unestablished at 2.0 → cannot establish
    expect(profile.score).toBeLessThan(70);
    expect(profile.established).toBe(false);
    expect(profile.confidence).toBe('provisional');
    expect(profile.qualityGatedEvidence).toBeLessThan(5);
  });

  it('same count with bilateral + established = much higher trust', () => {
    const receipts = Array(200).fill(null).map((_, i) => makeReceipt({
      submitted_by: `real-${i % 20}`,
      submitter_established: true,
      submitter_score: 90,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
      composite_score: 90,
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeGreaterThan(80);
    expect(profile.effectiveEvidence).toBeGreaterThan(50);
  });
});

// ============================================================================
// ADVERSARIAL: Policy bypass attempts
// ============================================================================

describe('ADVERSARIAL: Policy bypass', () => {
  it('strict policy rejects entity with high score but high dispute rate', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      provenance_tier: 'bilateral',
      composite_score: 92,
      agent_behavior: i < 4 ? 'disputed' : 'completed', // 20% dispute rate
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    // High score but high dispute rate — strict should reject
    expect(result.pass).toBe(false);
    expect(result.failures.some(f => f.includes('dispute_rate'))).toBe(true);
  });

  it('discovery policy allows even with bad data', () => {
    const receipts = [makeReceipt({ submitted_by: 's1', submitter_established: false })];
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.discovery);
    expect(result.pass).toBe(true);
  });
});

// ============================================================================
// ADVERSARIAL: Provenance gaming
// ============================================================================

describe('ADVERSARIAL: Claiming high provenance without proof', () => {
  it('self_attested has lowest weight regardless of signal scores', () => {
    const selfAttested = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      submitter_established: true,
      submitter_score: 95,
      provenance_tier: 'self_attested',
      composite_score: 100,
    }));
    const bilateral = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      submitter_established: true,
      submitter_score: 95,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
      composite_score: 100,
    }));
    const selfProfile = computeTrustProfile(selfAttested, {});
    const biProfile = computeTrustProfile(bilateral, {});
    // Same signals, same submitters — only provenance differs
    expect(biProfile.effectiveEvidence).toBeGreaterThan(selfProfile.effectiveEvidence * 2);
  });
});

// ============================================================================
// ADVERSARIAL: Damage ceiling verification
// ============================================================================

describe('ADVERSARIAL: Damage ceiling — worst case attack outcomes', () => {
  it('maximum possible score from pure Sybil attack is bounded', () => {
    // Best case for attacker: 200 perfect receipts, all unique, all unestablished
    const receipts = Array(200).fill(null).map((_, i) => makeReceipt({
      submitted_by: `sybil-${i}`,
      submitter_established: false,
      submitter_score: 100,
      provenance_tier: 'self_attested',
      composite_score: 100,
      delivery_accuracy: 100,
      product_accuracy: 100,
      price_integrity: 100,
      return_processing: 100,
      agent_satisfaction: 100,
      agent_behavior: 'completed',
    }));
    const profile = computeTrustProfile(receipts, {});
    // Even with 200 perfect receipts, unestablished + self_attested should cap damage
    expect(profile.score).toBeLessThan(75);
    expect(profile.established).toBe(false);
    expect(profile.confidence).not.toBe('confident');
    expect(profile.confidence).not.toBe('emerging');
    // Raw effective evidence is high, but quality-gated is capped
    expect(profile.effectiveEvidence).toBeGreaterThan(5);
    expect(profile.qualityGatedEvidence).toBeLessThan(5);
  });
});
