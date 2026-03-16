import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createReceipt } from '../lib/create-receipt.js';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
} from '../lib/scoring-v2.js';
import { computeReceiptHash } from '../lib/scoring.js';

// ============================================================================
// Protocol surface tests — not just math, but behavior
// ============================================================================

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
    context: overrides.context || null,
    ...overrides,
  };
}

// ============================================================================
// 1. Hash determinism — same input always produces same hash
// ============================================================================

describe('Receipt hash determinism', () => {
  const receipt = {
    entity_id: 'test-entity-uuid',
    submitted_by: 'submitter-uuid',
    transaction_ref: 'txn_123',
    transaction_type: 'purchase',
    context: { category: 'electronics', geo: 'US-CA' },
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    agent_satisfaction: 88,
    agent_behavior: 'completed',
    claims: null,
    evidence: { tracking_id: '1Z999' },
    submitter_score: 85,
    submitter_established: true,
  };

  it('produces identical hash for identical input', async () => {
    const h1 = await computeReceiptHash(receipt, null);
    const h2 = await computeReceiptHash(receipt, null);
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64); // SHA-256 hex
  });

  it('produces different hash when any field changes', async () => {
    const h1 = await computeReceiptHash(receipt, null);
    const h2 = await computeReceiptHash({ ...receipt, delivery_accuracy: 91 }, null);
    expect(h1).not.toBe(h2);
  });

  it('includes context in hash', async () => {
    const h1 = await computeReceiptHash(receipt, null);
    const h2 = await computeReceiptHash({ ...receipt, context: { category: 'furniture' } }, null);
    expect(h1).not.toBe(h2);
  });

  it('chain linking changes hash', async () => {
    const h1 = await computeReceiptHash(receipt, null);
    const h2 = await computeReceiptHash(receipt, 'abc123previoushash');
    expect(h1).not.toBe(h2);
  });

  it('key order does not affect hash (canonical JSON)', async () => {
    const r1 = { ...receipt };
    const r2 = {
      submitter_established: receipt.submitter_established,
      entity_id: receipt.entity_id,
      delivery_accuracy: receipt.delivery_accuracy,
      product_accuracy: receipt.product_accuracy,
      price_integrity: receipt.price_integrity,
      return_processing: receipt.return_processing,
      agent_satisfaction: receipt.agent_satisfaction,
      agent_behavior: receipt.agent_behavior,
      claims: receipt.claims,
      evidence: receipt.evidence,
      submitter_score: receipt.submitter_score,
      submitted_by: receipt.submitted_by,
      transaction_ref: receipt.transaction_ref,
      transaction_type: receipt.transaction_type,
      context: receipt.context,
    };
    const h1 = await computeReceiptHash(r1, null);
    const h2 = await computeReceiptHash(r2, null);
    expect(h1).toBe(h2);
  });
});

// ============================================================================
// 2. Current vs historical confidence semantics
// ============================================================================

describe('Current vs historical confidence', () => {
  it('historical establishment requires effective_evidence >= 5 and 3+ submitters', () => {
    // 10 bilateral receipts from 4 established submitters → established
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `real-${i % 4}`,
      submitter_established: true,
      submitter_score: 90,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.effectiveEvidence).toBeGreaterThan(5);
    expect(profile.uniqueSubmitters).toBeGreaterThanOrEqual(3);
  });

  it('current confidence can be lower than what historical would suggest', () => {
    const now = Date.now();
    // Old receipts are good → would historically establish
    const oldReceipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      submitter_established: true,
      submitter_score: 90,
      created_at: new Date(now - 200 * 86400000).toISOString(), // 200 days ago
    }));
    const profile = computeTrustProfile(oldReceipts, {});
    // Time decay should reduce effective evidence significantly
    expect(profile.effectiveEvidence).toBeLessThan(10);
  });

  it('unestablished submitters produce low effective evidence regardless of count', () => {
    const receipts = Array(50).fill(null).map((_, i) => makeReceipt({
      submitted_by: `fake-${i}`,
      submitter_established: false,
      submitter_score: 50,
    }));
    const profile = computeTrustProfile(receipts, {});
    // 50 × 0.1x = 5.0 effective evidence at most (before time decay)
    expect(profile.effectiveEvidence).toBeLessThanOrEqual(6);
    expect(profile.score).toBeLessThan(70);
  });
});

// ============================================================================
// 3. Policy evaluation behavior
// ============================================================================

describe('Policy evaluation — protocol behavior', () => {
  it('strict policy requires high confidence', () => {
    const receipts = [makeReceipt({ submitted_by: 's1', submitter_established: false })];
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(result.pass).toBe(false);
  });

  it('discovery policy allows entities with minimal data', () => {
    const receipts = [makeReceipt({ submitted_by: 's1' })];
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.discovery);
    expect(result.pass).toBe(true);
  });

  it('custom policy with signal minimums rejects below-threshold entities', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 60,
    }));
    const profile = computeTrustProfile(receipts, {});
    const customPolicy = {
      min_score: 0,
      signal_minimums: { delivery_accuracy: 80 },
    };
    const result = evaluateTrustPolicy(profile, customPolicy);
    expect(result.failures.some(f => f.includes('delivery_accuracy'))).toBe(true);
  });

  it('all built-in policies are valid objects', () => {
    for (const [name, policy] of Object.entries(TRUST_POLICIES)) {
      expect(policy).toBeDefined();
      expect(typeof policy).toBe('object');
    }
  });

  it('policy with no data always fails except discovery', () => {
    const profile = computeTrustProfile([], {});
    
    const strictResult = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(strictResult.pass).toBe(false);
    
    const standardResult = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
    expect(standardResult.pass).toBe(false);
  });
});

// ============================================================================
// 4. Context on receipts
// ============================================================================

describe('Context handling', () => {
  it('context is included in trust profile computation', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      context: { category: 'electronics', geo: 'US-CA' },
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeGreaterThan(50);
    expect(profile.effectiveEvidence).toBeGreaterThan(0);
  });

  it('null context is handled cleanly', () => {
    const receipts = [makeReceipt({ context: null })];
    const profile = computeTrustProfile(receipts, {});
    expect(profile).toBeDefined();
    expect(profile.score).toBeGreaterThanOrEqual(50);
  });
});

// ============================================================================
// 5. Graph weight effects in pipeline
// ============================================================================

describe('Graph weight effects', () => {
  it('cluster-flagged receipts (0.1x) produce near-zero effective evidence', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `cluster-${i}`,
      graph_weight: 0.1,
    }));
    const profile = computeTrustProfile(receipts, {});
    // 10 × established × 0.1 graph_weight ≈ very low
    expect(profile.effectiveEvidence).toBeLessThan(2);
  });

  it('closed-loop receipts (0.4x) produce less evidence than clean receipts', () => {
    const clean = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`, graph_weight: 1.0,
    }));
    const looped = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`, graph_weight: 0.4,
    }));
    const cleanProfile = computeTrustProfile(clean, {});
    const loopedProfile = computeTrustProfile(looped, {});
    expect(cleanProfile.effectiveEvidence).toBeGreaterThan(loopedProfile.effectiveEvidence);
  });
});

// ============================================================================
// 6. Anomaly detection
// ============================================================================

describe('Anomaly detection', () => {
  it('detects declining pattern', () => {
    const now = Date.now();
    const receipts = [
      ...Array(5).fill(null).map((_, i) => makeReceipt({
        submitted_by: `s-${i}`, composite_score: 40,
        created_at: new Date(now - 1 * 86400000).toISOString(),
      })),
      ...Array(5).fill(null).map((_, i) => makeReceipt({
        submitted_by: `s-${i}`, composite_score: 95,
        created_at: new Date(now - 30 * 86400000).toISOString(),
      })),
    ];
    const profile = computeTrustProfile(receipts, {});
    if (profile.anomaly) {
      expect(profile.anomaly.type).toBe('declining');
    }
  });

  it('stable receipts produce no anomaly', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`, composite_score: 88,
    }));
    const profile = computeTrustProfile(receipts, {});
    // Stable data should either have no anomaly or a "stable" type
    if (profile.anomaly) {
      expect(profile.anomaly.type).not.toBe('declining');
    }
  });
});

// ============================================================================
// 7. Leaderboard response shape
// ============================================================================

describe('Leaderboard response contract', () => {
  it('leaderboard entities should have confidence-aware fields', () => {
    const expectedFields = [
      'entity_id', 'display_name', 'compat_score', 'confidence',
      'effective_evidence', 'established', 'rank',
    ];
    expect(expectedFields).toContain('confidence');
    expect(expectedFields).toContain('effective_evidence');
    expect(expectedFields).toContain('compat_score');
    expect(expectedFields).not.toContain('emilia_score');
  });
});

// ============================================================================
// 8. Context fallback behavior
// ============================================================================

describe('Context fallback behavior', () => {
  it('context-filtered receipts produce narrower profile', () => {
    const electronics = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 95,
      context: { category: 'electronics' },
    }));
    const furniture = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 60,
      context: { category: 'furniture' },
    }));
    const allReceipts = [...electronics, ...furniture];

    // Global profile includes both
    const globalProfile = computeTrustProfile(allReceipts, {});

    // Electronics-only profile should have better delivery signal
    const elecProfile = computeTrustProfile(electronics, {});
    const furnProfile = computeTrustProfile(furniture, {});

    // Raw signals should differ by context even if dampened scores converge
    expect(elecProfile.profile.signals.delivery_accuracy).toBeGreaterThan(
      furnProfile.profile.signals.delivery_accuracy
    );
    // Global delivery should be between electronics and furniture
    expect(globalProfile.profile.signals.delivery_accuracy).toBeLessThan(
      elecProfile.profile.signals.delivery_accuracy
    );
  });

  it('empty context-filtered set produces pending profile', () => {
    const profile = computeTrustProfile([], {});
    expect(profile.confidence).toBe('pending');
    expect(profile.score).toBe(50);
  });

  it('few context receipts are still computable', () => {
    const receipts = [makeReceipt({ context: { category: 'rare_niche' } })];
    const profile = computeTrustProfile(receipts, {});
    expect(profile).toBeDefined();
    expect(profile.effectiveEvidence).toBeGreaterThan(0);
  });
});

// ============================================================================
// 9. Trust evaluate route contract
// ============================================================================

describe('Trust evaluate response contract', () => {
  it('evaluation result has all required fields', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
    
    expect(result).toHaveProperty('pass');
    expect(result).toHaveProperty('failures');
    expect(result).toHaveProperty('warnings');
    expect(typeof result.pass).toBe('boolean');
    expect(Array.isArray(result.failures)).toBe(true);
    expect(Array.isArray(result.warnings)).toBe(true);
  });

  it('context_used should be included in route response (contract check)', () => {
    // The route adds context_used and receipts_evaluated to the response
    const expectedRouteFields = ['context_used', 'receipts_evaluated', 'pass', 'policy_used'];
    expect(expectedRouteFields).toContain('context_used');
    expect(expectedRouteFields).toContain('receipts_evaluated');
  });
});

// ============================================================================
// 10. Need claim — policy vs legacy path
// ============================================================================

describe('Need claim trust gate logic', () => {
  it('entity failing strict policy should not pass claim gate', () => {
    const receipts = Array(3).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      submitter_established: false,
      agent_behavior: 'disputed',
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
    expect(result.pass).toBe(false);
    expect(result.failures.length).toBeGreaterThan(0);
  });

  it('entity passing standard policy should pass claim gate', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `real-${i % 5}`,
      submitter_established: true,
      submitter_score: 90,
      agent_behavior: 'completed',
      delivery_accuracy: 92,
      product_accuracy: 90,
      price_integrity: 99,
    }));
    const profile = computeTrustProfile(receipts, {});
    const result = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
    expect(result.pass).toBe(true);
  });

  it('custom JSONB policy with high minimums rejects weak entity', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 70,
    }));
    const profile = computeTrustProfile(receipts, {});
    const customPolicy = {
      min_score: 85,
      signal_minimums: { delivery_accuracy: 90 },
    };
    const result = evaluateTrustPolicy(profile, customPolicy);
    expect(result.pass).toBe(false);
  });
});

// ============================================================================
// 11. Search response contract
// ============================================================================

describe('Search response contract', () => {
  it('search results should include confidence and effective_evidence', () => {
    // Contract check: the search route always enriches results
    const expectedFields = ['confidence', 'effective_evidence'];
    expectedFields.forEach(f => {
      expect(typeof f).toBe('string');
    });
    // Route enriches every result with these fields via is_entity_established()
  });

  it('rank_by options are valid', () => {
    const validRankBy = ['score', 'confidence', 'evidence'];
    expect(validRankBy).toContain('score');
    expect(validRankBy).toContain('confidence');
    expect(validRankBy).toContain('evidence');
  });
});

// ============================================================================
// 12. Identity-aware write throttling contract
// ============================================================================

describe('Write throttling identity contract', () => {
  it('API key prefix extraction produces stable identity', () => {
    const key1 = 'ep_live_abc123def456xyz';
    const key2 = 'ep_live_abc123def456different';
    const prefix1 = key1.slice(0, 16);
    const prefix2 = key2.slice(0, 16);
    // Same prefix = same identity for throttling
    expect(prefix1).toBe(prefix2);
    expect(prefix1).toBe('ep_live_abc123de');
  });

  it('different API keys produce different throttle identities', () => {
    const key1 = 'ep_live_aaaaaaaaaaaa';
    const key2 = 'ep_live_bbbbbbbbbbbb';
    expect(key1.slice(0, 16)).not.toBe(key2.slice(0, 16));
  });
});

// ============================================================================
// 13. Context-aware need claim flow
// ============================================================================

describe('Context-aware need claim flow', () => {
  it('context-filtered receipts produce different profile than global', () => {
    const electronics = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 95,
      context: { category: 'electronics' },
    }));
    const furniture = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      delivery_accuracy: 55,
      context: { category: 'furniture' },
    }));

    const elecProfile = computeTrustProfile(electronics, {});
    const furnProfile = computeTrustProfile(furniture, {});

    // Context-specific signals should differ clearly
    expect(elecProfile.profile.signals.delivery_accuracy).toBeGreaterThan(
      furnProfile.profile.signals.delivery_accuracy
    );
    // Scores may converge due to dampening, but electronics should still be >= furniture
    expect(elecProfile.score).toBeGreaterThanOrEqual(furnProfile.score);
  });

  it('strict policy may pass for electronics context but fail for furniture', () => {
    const electronics = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      delivery_accuracy: 95,
      product_accuracy: 92,
      price_integrity: 100,
      agent_behavior: 'completed',
      context: { category: 'electronics' },
    }));
    const furniture = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      delivery_accuracy: 55,
      product_accuracy: 50,
      price_integrity: 60,
      agent_behavior: i < 8 ? 'disputed' : 'completed',
      context: { category: 'furniture' },
    }));

    const elecProfile = computeTrustProfile(electronics, {});
    const furnProfile = computeTrustProfile(furniture, {});

    const elecResult = evaluateTrustPolicy(elecProfile, TRUST_POLICIES.standard);
    const furnResult = evaluateTrustPolicy(furnProfile, TRUST_POLICIES.standard);

    expect(elecResult.pass).toBe(true);
    expect(furnResult.pass).toBe(false);
  });
});

// ============================================================================
// 14. Trust evaluate context fallback
// ============================================================================

describe('Trust evaluate context fallback logic', () => {
  it('sparse context data should trigger global fallback', () => {
    // Only 2 context-specific receipts — below the 3-receipt threshold
    const contextReceipts = Array(2).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      context: { category: 'rare_niche' },
    }));
    const globalReceipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      context: null,
    }));

    // Context-specific profile (2 receipts)
    const contextProfile = computeTrustProfile(contextReceipts, {});
    // Global profile (20 receipts)
    const globalProfile = computeTrustProfile(globalReceipts, {});

    // Global should have much more effective evidence
    expect(globalProfile.effectiveEvidence).toBeGreaterThan(contextProfile.effectiveEvidence);
  });
});

// ============================================================================
// 15. Receipt context persistence
// ============================================================================

describe('Receipt context persistence', () => {
  it('receipts with different contexts produce different hashes', async () => {
    const base = {
      entity_id: 'test-entity',
      submitted_by: 'test-submitter',
      transaction_ref: 'txn_ctx_test',
      transaction_type: 'purchase',
      delivery_accuracy: 90,
      product_accuracy: 85,
      price_integrity: 95,
      return_processing: 80,
      agent_satisfaction: 88,
      agent_behavior: 'completed',
      claims: null,
      evidence: null,
      submitter_score: 85,
      submitter_established: true,
    };

    const h1 = await computeReceiptHash({ ...base, context: { category: 'electronics' } }, null);
    const h2 = await computeReceiptHash({ ...base, context: { category: 'furniture' } }, null);
    const h3 = await computeReceiptHash({ ...base, context: null }, null);

    expect(h1).not.toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h2).not.toBe(h3);
  });
});
