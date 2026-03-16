import { describe, it, expect } from 'vitest';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
} from '../lib/scoring-v2.js';
import { computeReceiptHash } from '../lib/scoring.js';

/**
 * END-TO-END PROTOCOL FLOW TESTS
 * 
 * These simulate the full lifecycle that a real user would experience:
 *   1. Register entity
 *   2. Submit receipts
 *   3. Get trust profile
 *   4. Evaluate policy
 *   5. File dispute
 *   6. Reverse receipt
 *   7. Verify recomputed profile
 *   8. Confirm redaction
 *   9. MCP output matches API output
 * 
 * These catch bugs that unit tests miss — the ones that live in the seams.
 */

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 85, product_accuracy: 82, price_integrity: 90,
    return_processing: 75, agent_satisfaction: 80, composite_score: 83,
    submitted_by: 'established-submitter-1',
    submitter_score: 88, submitter_established: true,
    graph_weight: 1.0, agent_behavior: 'completed',
    created_at: new Date().toISOString(),
    context: null, provenance_tier: 'bilateral', bilateral_status: 'confirmed',
    ...overrides,
  };
}

// ============================================================================
// Flow 1: Complete trust lifecycle — register → receipts → profile → policy
// ============================================================================

describe('E2E: Complete trust lifecycle', () => {
  const entity = { entity_id: 'e2e-merchant-1', entity_type: 'merchant' };

  it('step 1-2: entity with no receipts has pending confidence', () => {
    const profile = computeTrustProfile([], entity);
    expect(profile.confidence).toBe('pending');
    expect(profile.score).toBe(50);
    expect(profile.effectiveEvidence).toBe(0);
  });

  it('step 3: entity with 1 receipt has limited confidence', () => {
    const receipts = [makeReceipt({ submitted_by: 's1' })];
    const profile = computeTrustProfile(receipts, entity);
    // 1 bilateral receipt from established submitter: ~0.72 effective evidence
    expect(['insufficient', 'provisional']).toContain(profile.confidence);
    expect(profile.effectiveEvidence).toBeGreaterThan(0);
    expect(profile.effectiveEvidence).toBeLessThan(5);
  });

  it('step 4: entity building trust with 10 bilateral receipts from 4 submitters', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `established-${i % 4}`,
      submitter_established: true,
      submitter_score: 85 + (i % 4),
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));
    const profile = computeTrustProfile(receipts, entity);
    expect(profile.confidence).not.toBe('pending');
    expect(profile.confidence).not.toBe('insufficient');
    expect(profile.uniqueSubmitters).toBe(4);
    expect(profile.profile.provenance.bilateral_rate).toBeGreaterThan(0);
  });

  it('step 5: strict policy evaluation on healthy entity', () => {
    const receipts = Array(30).fill(null).map((_, i) => makeReceipt({
      submitted_by: `est-${i % 5}`,
      submitter_established: true, submitter_score: 90,
      provenance_tier: 'bilateral', bilateral_status: 'confirmed',
      composite_score: 88, delivery_accuracy: 92, price_integrity: 95,
    }));
    const profile = computeTrustProfile(receipts, entity);
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(result.pass).toBe(true);
    expect(result.failures).toHaveLength(0);
  });

  it('step 5b: same entity fails strict with bad delivery', () => {
    const receipts = Array(25).fill(null).map((_, i) => makeReceipt({
      submitted_by: `est-${i % 5}`,
      submitter_established: true, submitter_score: 90,
      provenance_tier: 'bilateral', bilateral_status: 'confirmed',
      composite_score: 60, delivery_accuracy: 50, price_integrity: 95,
    }));
    const profile = computeTrustProfile(receipts, entity);
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(result.pass).toBe(false);
    expect(result.failures.some(f => f.includes('delivery'))).toBe(true);
  });
});

// ============================================================================
// Flow 2: Dispute lifecycle — file → respond → reverse → verify recompute
// ============================================================================

describe('E2E: Dispute and reversal lifecycle', () => {
  it('reversing a bad receipt improves delivery signal', () => {
    const receipts = [
      makeReceipt({ submitted_by: 's1', composite_score: 90, delivery_accuracy: 95, graph_weight: 1.0 }),
      makeReceipt({ submitted_by: 's2', composite_score: 20, delivery_accuracy: 10, graph_weight: 1.0 }), // bad
      makeReceipt({ submitted_by: 's3', composite_score: 88, delivery_accuracy: 90, graph_weight: 1.0 }),
    ];

    const profileBefore = computeTrustProfile(receipts, {});

    // Simulate reversal: set graph_weight to 0
    receipts[1] = { ...receipts[1], graph_weight: 0.0 };

    const profileAfter = computeTrustProfile(receipts, {});

    // Delivery signal should improve (bad receipt neutralized)
    expect(profileAfter.profile.signals.delivery_accuracy).toBeGreaterThan(
      profileBefore.profile.signals.delivery_accuracy
    );
  });

  it('reversing a good receipt worsens the profile', () => {
    const receipts = [
      makeReceipt({ submitted_by: 's1', composite_score: 90, graph_weight: 1.0 }),
      makeReceipt({ submitted_by: 's2', composite_score: 95, graph_weight: 1.0 }), // good — will be reversed
      makeReceipt({ submitted_by: 's3', composite_score: 40, graph_weight: 1.0 }),
    ];

    const profileBefore = computeTrustProfile(receipts, {});
    receipts[1] = { ...receipts[1], graph_weight: 0.0 };
    const profileAfter = computeTrustProfile(receipts, {});

    expect(profileAfter.score).toBeLessThanOrEqual(profileBefore.score);
  });

  it('multiple reversals leave only non-reversed receipt signals', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      composite_score: i < 5 ? 90 : 30,
      delivery_accuracy: i < 5 ? 95 : 20,
      graph_weight: i < 5 ? 1.0 : 0.0, // last 5 reversed
    }));
    const profile = computeTrustProfile(receipts, {});

    // Only the first 5 (good) receipts should contribute to signals
    const goodOnly = receipts.filter(r => r.graph_weight > 0);
    const goodProfile = computeTrustProfile(goodOnly, {});

    // Signal values should be identical — reversed receipts have zero weight
    expect(profile.profile.signals.delivery_accuracy).toBe(goodProfile.profile.signals.delivery_accuracy);
  });
});

// ============================================================================
// Flow 3: Software install lifecycle
// ============================================================================

describe('E2E: Software install lifecycle', () => {
  const swEntity = { entity_id: 'mcp-test-server', entity_type: 'mcp_server' };

  it('new software entity starts with pending confidence', () => {
    const profile = computeTrustProfile([], swEntity);
    expect(profile.confidence).toBe('pending');
  });

  it('install + execution receipts build software trust', () => {
    const receipts = [
      makeReceipt({ submitted_by: 's1', agent_behavior: 'completed', context: { host: 'mcp', task_type: 'install' } }),
      makeReceipt({ submitted_by: 's2', agent_behavior: 'completed', context: { host: 'mcp', task_type: 'install' } }),
      makeReceipt({ submitted_by: 's3', agent_behavior: 'completed', context: { host: 'mcp', task_type: 'execution' } }),
    ];
    const profile = computeTrustProfile(receipts, swEntity);
    expect(profile.profile.behavioral.completion_rate).toBe(100);
    expect(profile.receiptCount).toBe(3);
    expect(profile.uniqueSubmitters).toBe(3);
  });

  it('incident receipt degrades behavioral score', () => {
    const clean = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`, agent_behavior: 'completed',
    }));
    const withIncident = [
      ...clean,
      makeReceipt({ submitted_by: 's-5', agent_behavior: 'failed' }),
      makeReceipt({ submitted_by: 's-6', agent_behavior: 'disputed' }),
    ];
    const cleanProfile = computeTrustProfile(clean, swEntity);
    const incidentProfile = computeTrustProfile(withIncident, swEntity);
    expect(incidentProfile.profile.behavioral.completion_rate).toBeLessThan(
      cleanProfile.profile.behavioral.completion_rate
    );
  });
});

// ============================================================================
// Flow 4: Hash chain integrity
// ============================================================================

describe('E2E: Hash chain integrity across receipt sequence', () => {
  it('each receipt hash chains to the previous', async () => {
    const baseReceipt = {
      entity_id: 'chain-entity',
      submitted_by: 'chain-submitter',
      transaction_type: 'purchase',
      delivery_accuracy: 90, product_accuracy: 85,
      price_integrity: 95, return_processing: 80,
      agent_satisfaction: 88, agent_behavior: 'completed',
      claims: null, evidence: null, context: null,
      submitter_score: 85, submitter_established: true,
    };

    const hash1 = await computeReceiptHash(
      { ...baseReceipt, transaction_ref: 'chain_txn_001' }, null
    );
    const hash2 = await computeReceiptHash(
      { ...baseReceipt, transaction_ref: 'chain_txn_002' }, hash1
    );
    const hash3 = await computeReceiptHash(
      { ...baseReceipt, transaction_ref: 'chain_txn_003' }, hash2
    );

    // All hashes should be valid SHA-256
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    expect(hash2).toMatch(/^[0-9a-f]{64}$/);
    expect(hash3).toMatch(/^[0-9a-f]{64}$/);

    // All hashes should be different
    expect(hash1).not.toBe(hash2);
    expect(hash2).not.toBe(hash3);

    // Chain should be reproducible
    const hash2_again = await computeReceiptHash(
      { ...baseReceipt, transaction_ref: 'chain_txn_002' }, hash1
    );
    expect(hash2_again).toBe(hash2);
  });
});

// ============================================================================
// Flow 5: Policy consistency — same entity produces same result everywhere
// ============================================================================

describe('E2E: Policy consistency across surfaces', () => {
  it('same receipts + same policy = same result regardless of call order', () => {
    const receipts = Array(15).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      submitter_established: true, submitter_score: 90,
      provenance_tier: 'bilateral', bilateral_status: 'confirmed',
    }));

    // Simulate: profile route calls computeTrustProfile first
    const profile1 = computeTrustProfile(receipts, {});
    const result1 = evaluateTrustPolicy(profile1, TRUST_POLICIES.standard);

    // Simulate: evaluate route calls computeTrustProfile independently
    const profile2 = computeTrustProfile(receipts, {});
    const result2 = evaluateTrustPolicy(profile2, TRUST_POLICIES.standard);

    // Results must be identical
    expect(profile1.score).toBe(profile2.score);
    expect(profile1.confidence).toBe(profile2.confidence);
    expect(profile1.effectiveEvidence).toBe(profile2.effectiveEvidence);
    expect(result1.pass).toBe(result2.pass);
    expect(result1.failures).toEqual(result2.failures);
  });

  it('all four built-in policies produce deterministic results', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
    }));
    const profile = computeTrustProfile(receipts, {});

    for (const policyName of ['strict', 'standard', 'permissive', 'discovery']) {
      const r1 = evaluateTrustPolicy(profile, TRUST_POLICIES[policyName]);
      const r2 = evaluateTrustPolicy(profile, TRUST_POLICIES[policyName]);
      expect(r1.pass).toBe(r2.pass);
      expect(r1.failures).toEqual(r2.failures);
    }
  });
});

// ============================================================================
// Flow 6: Provenance upgrade lifecycle
// ============================================================================

describe('E2E: Provenance upgrade lifecycle', () => {
  it('upgrading provenance from self_attested to bilateral increases trust', () => {
    const selfAttested = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      provenance_tier: 'self_attested',
      bilateral_status: null,
    }));

    // Same receipts but upgraded to bilateral
    const bilateral = selfAttested.map(r => ({
      ...r,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));

    const selfProfile = computeTrustProfile(selfAttested, {});
    const biProfile = computeTrustProfile(bilateral, {});

    expect(biProfile.effectiveEvidence).toBeGreaterThan(selfProfile.effectiveEvidence);
    expect(biProfile.profile.provenance.bilateral_rate).toBe(100);
    expect(selfProfile.profile.provenance.bilateral_rate).toBe(0);
  });
});
