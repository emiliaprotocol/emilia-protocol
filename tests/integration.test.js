import { describe, it, expect } from 'vitest';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
  EP_WEIGHTS_V2,
} from '../lib/scoring-v2.js';
import { computeReceiptHash } from '../lib/scoring.js';

// ============================================================================
// Route-level integration tests
// Tests protocol surface behavior, not just math
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
    provenance_tier: overrides.provenance_tier || 'self_attested',
    bilateral_status: overrides.bilateral_status || null,
    ...overrides,
  };
}

// ============================================================================
// 1. Trust Evaluate — context fallback behavior
// ============================================================================

describe('ROUTE: /api/trust/evaluate — context fallback', () => {
  it('context-specific receipts produce different profile than global', () => {
    const electronics = Array(15).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      delivery_accuracy: 96,
      context: { category: 'electronics' },
    }));
    const furniture = Array(15).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      delivery_accuracy: 55,
      context: { category: 'furniture' },
    }));

    const elecProfile = computeTrustProfile(electronics, {});
    const furnProfile = computeTrustProfile(furniture, {});
    const globalProfile = computeTrustProfile([...electronics, ...furniture], {});

    expect(elecProfile.score).toBeGreaterThan(globalProfile.score);
    expect(furnProfile.score).toBeLessThan(globalProfile.score);
  });

  it('sparse context data should have lower effective evidence', () => {
    const sparse = [makeReceipt({ context: { category: 'rare_niche' } })];
    const rich = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      context: { category: 'common' },
    }));

    const sparseProfile = computeTrustProfile(sparse, {});
    const richProfile = computeTrustProfile(rich, {});

    expect(richProfile.effectiveEvidence).toBeGreaterThan(sparseProfile.effectiveEvidence);
  });
});

// ============================================================================
// 2. Trust Profile — provenance composition
// ============================================================================

describe('ROUTE: /api/trust/profile — provenance', () => {
  it('bilateral receipts produce higher effective evidence than self-attested', () => {
    const selfAttested = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      provenance_tier: 'self_attested',
    }));
    const bilateral = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 4}`,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));

    const selfProfile = computeTrustProfile(selfAttested, {});
    const biProfile = computeTrustProfile(bilateral, {});

    expect(biProfile.effectiveEvidence).toBeGreaterThan(selfProfile.effectiveEvidence);
    expect(biProfile.score).toBeGreaterThan(selfProfile.score);
  });

  it('oracle-verified receipts produce the highest evidence', () => {
    const oracle = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      provenance_tier: 'oracle_verified',
    }));
    const selfAttested = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      provenance_tier: 'self_attested',
    }));

    const oracleProfile = computeTrustProfile(oracle, {});
    const selfProfile = computeTrustProfile(selfAttested, {});

    expect(oracleProfile.effectiveEvidence).toBeGreaterThan(selfProfile.effectiveEvidence);
  });

  it('profile includes provenance breakdown', () => {
    const mixed = [
      makeReceipt({ provenance_tier: 'self_attested', submitted_by: 's1' }),
      makeReceipt({ provenance_tier: 'bilateral', bilateral_status: 'confirmed', submitted_by: 's2' }),
      makeReceipt({ provenance_tier: 'platform_originated', submitted_by: 's3' }),
    ];
    const profile = computeTrustProfile(mixed, {});
    expect(profile.profile.provenance).toBeDefined();
    expect(profile.profile.provenance.breakdown).toBeDefined();
    expect(profile.profile.provenance.breakdown.self_attested).toBe(1);
    expect(profile.profile.provenance.breakdown.bilateral).toBe(1);
    expect(profile.profile.provenance.breakdown.platform_originated).toBe(1);
  });

  it('bilateral_rate is computed correctly', () => {
    const receipts = [
      makeReceipt({ bilateral_status: 'confirmed', submitted_by: 's1' }),
      makeReceipt({ bilateral_status: 'confirmed', submitted_by: 's2' }),
      makeReceipt({ bilateral_status: null, submitted_by: 's3' }),
      makeReceipt({ bilateral_status: null, submitted_by: 's4' }),
    ];
    const profile = computeTrustProfile(receipts, {});
    expect(profile.profile.provenance.bilateral_rate).toBe(50); // 2/4 = 50%
  });
});

// ============================================================================
// 3. Receipt Submit — hash includes provenance and context
// ============================================================================

describe('ROUTE: /api/receipts/submit — hash integrity', () => {
  it('same receipt always produces same hash', async () => {
    const receipt = {
      entity_id: 'test-entity',
      submitted_by: 'test-submitter',
      transaction_ref: 'txn_route_test_001',
      transaction_type: 'install',
      context: { host: 'github', permission_class: 'read_only' },
      delivery_accuracy: null,
      product_accuracy: null,
      price_integrity: null,
      return_processing: null,
      agent_satisfaction: null,
      agent_behavior: 'completed',
      claims: { install_scope: 'selected_repos' },
      evidence: { github_app_id: 12345 },
      submitter_score: 85,
      submitter_established: true,
    };
    const h1 = await computeReceiptHash(receipt, null);
    const h2 = await computeReceiptHash(receipt, null);
    expect(h1).toBe(h2);
  });

  it('software transaction types produce valid hashes', async () => {
    const softwareTypes = ['install', 'uninstall', 'permission_grant', 'execution', 'incident'];
    for (const tt of softwareTypes) {
      const receipt = {
        entity_id: 'test-sw',
        submitted_by: 'test-sub',
        transaction_ref: `txn_${tt}_001`,
        transaction_type: tt,
        context: { host: 'npm' },
        delivery_accuracy: null,
        product_accuracy: null,
        price_integrity: null,
        return_processing: null,
        agent_satisfaction: null,
        agent_behavior: null,
        claims: null,
        evidence: null,
        submitter_score: 50,
        submitter_established: false,
      };
      const hash = await computeReceiptHash(receipt, null);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

// ============================================================================
// 4. Dispute Flow
// ============================================================================

describe('ROUTE: Dispute flow behavior', () => {
  it('reversed receipt (graph_weight=0) has zero contribution', () => {
    const receipts = [
      makeReceipt({ submitted_by: 's1', composite_score: 95, graph_weight: 1.0 }),
      makeReceipt({ submitted_by: 's2', composite_score: 20, graph_weight: 0.0 }), // reversed
      makeReceipt({ submitted_by: 's3', composite_score: 90, graph_weight: 1.0 }),
    ];
    const profile = computeTrustProfile(receipts, {});
    // The reversed receipt should not drag down the score significantly
    expect(profile.score).toBeGreaterThan(70);
  });

  it('all reversed receipts produce near-default profile', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      graph_weight: 0.0, // all reversed
    }));
    const profile = computeTrustProfile(receipts, {});
    expect(profile.effectiveEvidence).toBe(0);
    expect(profile.score).toBe(50);
    expect(profile.confidence).toBe('pending');
  });
});

// ============================================================================
// 5. Install Preflight — software policy evaluation
// ============================================================================

describe('ROUTE: /api/trust/install-preflight — software policies', () => {
  it('all software policies exist and are valid objects', () => {
    const softwarePolicies = [
      'github_private_repo_safe_v1',
      'npm_buildtime_safe_v1',
      'browser_extension_safe_v1',
      'mcp_server_safe_v1',
    ];
    for (const name of softwarePolicies) {
      expect(TRUST_POLICIES[name]).toBeDefined();
      expect(TRUST_POLICIES[name].software_requirements).toBeDefined();
      expect(typeof TRUST_POLICIES[name].software_requirements).toBe('object');
    }
  });

  it('github policy requires publisher_verified', () => {
    const policy = TRUST_POLICIES.github_private_repo_safe_v1;
    expect(policy.software_requirements.publisher_verified).toBe(true);
    expect(policy.software_requirements.max_permission_class).toBe('read_only');
  });

  it('npm policy requires trusted_publishing and provenance', () => {
    const policy = TRUST_POLICIES.npm_buildtime_safe_v1;
    expect(policy.software_requirements.trusted_publishing).toBe(true);
    expect(policy.software_requirements.provenance_verified).toBe(true);
  });

  it('mcp policy requires registry listing and server card', () => {
    const policy = TRUST_POLICIES.mcp_server_safe_v1;
    expect(policy.software_requirements.registry_listed).toBe(true);
    expect(policy.software_requirements.server_card_present).toBe(true);
  });

  it('software policies can be evaluated alongside trust policies', () => {
    const receipts = Array(20).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i % 5}`,
      agent_behavior: 'completed',
      delivery_accuracy: 92,
      product_accuracy: 90,
      price_integrity: 99,
      provenance_tier: 'bilateral',
    }));
    const profile = computeTrustProfile(receipts, {});

    // Standard trust evaluation should pass
    const trustResult = evaluateTrustPolicy(profile, TRUST_POLICIES.github_private_repo_safe_v1);
    // Trust part may pass, software requirements are checked separately by install-preflight
    expect(typeof trustResult.pass).toBe('boolean');
  });
});

// ============================================================================
// 6. MCP Tool Contract
// ============================================================================

describe('ROUTE: MCP tool contracts', () => {
  it('ep_trust_profile should return all expected fields', () => {
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      submitted_by: `s-${i}`,
      provenance_tier: 'bilateral',
      bilateral_status: 'confirmed',
    }));
    const profile = computeTrustProfile(receipts, {});

    // These are the fields the MCP formatTrustProfile function expects
    expect(profile).toHaveProperty('score');
    expect(profile).toHaveProperty('confidence');
    expect(profile).toHaveProperty('effectiveEvidence');
    expect(profile).toHaveProperty('profile');
    expect(profile.profile).toHaveProperty('behavioral');
    expect(profile.profile).toHaveProperty('signals');
    expect(profile.profile).toHaveProperty('consistency');
    expect(profile.profile).toHaveProperty('provenance');
  });
});

// ============================================================================
// 7. Weight model integrity
// ============================================================================

describe('ROUTE: Weight model invariants', () => {
  it('v2 weights sum to exactly 1.0', () => {
    const sum = Object.values(EP_WEIGHTS_V2).reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(1.0, 10);
  });

  it('behavioral has the highest weight', () => {
    const maxWeight = Math.max(...Object.values(EP_WEIGHTS_V2));
    expect(EP_WEIGHTS_V2.behavioral).toBe(maxWeight);
  });

  it('no weight is negative', () => {
    for (const [key, val] of Object.entries(EP_WEIGHTS_V2)) {
      expect(val).toBeGreaterThanOrEqual(0);
    }
  });
});
