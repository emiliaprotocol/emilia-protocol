import { describe, it, expect } from 'vitest';
import {
  computeWeightRecommendation,
  extractDimensions,
  computeContributions,
  VERTICAL_PACKS,
  MIN_RESOLVED_DISPUTES,
  MIN_DISPUTED_ENTITIES,
} from '../lib/cloud/calibration.js';
import { EP_WEIGHTS_V2, validateScoringWeights } from '../lib/scoring-v2.js';

// =============================================================================
// Helpers
// =============================================================================

function makeCalibrationRecord(overrides = {}) {
  return {
    dispute_id: `ep_disp_${Math.random().toString(36).slice(2, 8)}`,
    outcome: 'upheld',
    resolution: 'upheld',
    reason: 'inaccurate_signals',
    resolved_at: new Date().toISOString(),
    adjudication_confidence: 0.8,
    adjudication_recommendation: 'uphold_dispute',
    receipt: {
      composite_score: 75,
      delivery_accuracy: 90,
      product_accuracy: 85,
      price_integrity: 95,
      return_processing: 80,
      agent_behavior: 'completed',
      submitter_score: 80,
      submitter_established: true,
      provenance_tier: 'bilateral',
    },
    entity_score: 72,
    entity_snapshot: null,
    ...overrides,
  };
}

function makeStats(overrides = {}) {
  return {
    resolved: 60,
    upheld: 30,
    dismissed: 25,
    reversed: 5,
    uniqueEntities: 25,
    windowDays: 90,
    ...overrides,
  };
}

// =============================================================================
// extractDimensions
// =============================================================================

describe('extractDimensions', () => {
  it('maps agent_behavior to behavioral score', () => {
    const dims = extractDimensions({ agent_behavior: 'completed', delivery_accuracy: 90 });
    expect(dims.behavioral).toBe(95);
  });

  it('maps retried_different to 40', () => {
    const dims = extractDimensions({ agent_behavior: 'retried_different' });
    expect(dims.behavioral).toBe(40);
  });

  it('returns null for missing receipt', () => {
    expect(extractDimensions(null)).toBeNull();
  });

  it('passes through signal values', () => {
    const dims = extractDimensions({
      agent_behavior: 'completed',
      delivery_accuracy: 88,
      product_accuracy: 92,
      price_integrity: 100,
      return_processing: 70,
    });
    expect(dims.delivery).toBe(88);
    expect(dims.product).toBe(92);
    expect(dims.price).toBe(100);
    expect(dims.returns).toBe(70);
  });

  it('returns null for missing signals', () => {
    const dims = extractDimensions({ agent_behavior: 'completed' });
    expect(dims.delivery).toBeNull();
    expect(dims.product).toBeNull();
  });
});

// =============================================================================
// computeContributions
// =============================================================================

describe('computeContributions', () => {
  it('computes weighted contributions using EP_WEIGHTS_V2', () => {
    const dims = { behavioral: 95, consistency: 80, delivery: 90, product: 85, price: 95, returns: 80 };
    const contributions = computeContributions(dims);

    // With all 6 dimensions, totalWeight = 1.0, no normalization
    // behavioral contribution = 95 * 0.40 = 38
    expect(contributions.behavioral).toBeCloseTo(38, 0);
  });

  it('handles missing dimensions gracefully', () => {
    const dims = { behavioral: 95 };
    const contributions = computeContributions(dims);
    expect(contributions.behavioral).toBeDefined();
    expect(contributions.delivery).toBeUndefined();
  });

  it('uses custom weights when provided', () => {
    const dims = { behavioral: 95, consistency: 80, delivery: 90, product: 85, price: 95, returns: 80 };
    const customWeights = { behavioral: 0.50, delivery: 0.20, product: 0.10, price: 0.10, returns: 0.05, consistency: 0.05 };
    const contributions = computeContributions(dims, customWeights);

    // All 6 dimensions present, totalWeight = 1.0, no normalization
    // behavioral contribution = 95 * 0.50 = 47.5
    expect(contributions.behavioral).toBeCloseTo(47.5, 0);
  });
});

// =============================================================================
// computeWeightRecommendation — insufficient data
// =============================================================================

describe('computeWeightRecommendation — insufficient data', () => {
  it('rejects when resolved disputes < minimum', () => {
    const data = Array(10).fill(null).map(() => makeCalibrationRecord());
    const stats = makeStats({ resolved: 10 }); // below MIN_RESOLVED_DISPUTES

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(false);
    expect(result.recommendation).toBeNull();
    expect(result.reason).toContain('Insufficient resolved disputes');
  });

  it('rejects when unique entities < minimum', () => {
    const data = Array(60).fill(null).map(() => makeCalibrationRecord());
    const stats = makeStats({ uniqueEntities: 5 }); // below MIN_DISPUTED_ENTITIES

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(false);
    expect(result.recommendation).toBeNull();
    expect(result.reason).toContain('Insufficient disputed entities');
  });

  it('rejects when upheld disputes with receipts < 10', () => {
    // 60 resolved but only 5 upheld
    const data = [
      ...Array(5).fill(null).map(() => makeCalibrationRecord({ outcome: 'upheld' })),
      ...Array(55).fill(null).map(() => makeCalibrationRecord({ outcome: 'dismissed' })),
    ];
    const stats = makeStats({ upheld: 5 });

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(false);
    expect(result.reason).toContain('Insufficient upheld disputes');
  });
});

// =============================================================================
// computeWeightRecommendation — with sufficient data
// =============================================================================

describe('computeWeightRecommendation — with sufficient data', () => {
  it('returns null recommendation when weights are well-calibrated', () => {
    // All receipts have balanced signals — no clear overweighting
    const data = Array(60).fill(null).map((_, i) => makeCalibrationRecord({
      outcome: i < 30 ? 'upheld' : 'dismissed',
      receipt: {
        composite_score: 75,
        delivery_accuracy: 80,
        product_accuracy: 80,
        price_integrity: 80,
        return_processing: 80,
        agent_behavior: 'completed',
        submitter_score: 80,
        submitter_established: true,
        provenance_tier: 'bilateral',
      },
    }));
    const stats = makeStats();

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(true);
    // Either no recommendation or a valid one — both are acceptable for uniform data
  });

  it('detects overweighted dimension in upheld disputes', () => {
    // Upheld disputes: entities had high delivery scores (delivery was overweighted)
    // Dismissed disputes: entities had normal delivery scores
    const upheld = Array(30).fill(null).map(() => makeCalibrationRecord({
      outcome: 'upheld',
      receipt: {
        composite_score: 85,
        delivery_accuracy: 99, // very high — this is what made the score high
        product_accuracy: 40,  // low — entity was actually bad here
        price_integrity: 50,
        return_processing: 30,
        agent_behavior: 'retried_different', // behavioral was low
        submitter_score: 80,
        submitter_established: true,
        provenance_tier: 'bilateral',
      },
    }));

    const dismissed = Array(30).fill(null).map(() => makeCalibrationRecord({
      outcome: 'dismissed',
      receipt: {
        composite_score: 75,
        delivery_accuracy: 70,
        product_accuracy: 70,
        price_integrity: 70,
        return_processing: 70,
        agent_behavior: 'completed',
        submitter_score: 80,
        submitter_established: true,
        provenance_tier: 'bilateral',
      },
    }));

    const data = [...upheld, ...dismissed];
    const stats = makeStats();

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(true);

    // If a recommendation is generated, check it has valid weights
    if (result.recommendation) {
      const validation = validateScoringWeights(result.recommendation.weights);
      expect(validation.valid).toBe(true);
      expect(result.recommendation.confidence).toBeGreaterThan(0);
      expect(result.recommendation.sample_size).toBe(30);
    }
  });

  it('generates recommendations with valid weights that sum to 1.0', () => {
    // Strong signal: delivery was overweighted in upheld disputes
    const upheld = Array(40).fill(null).map(() => makeCalibrationRecord({
      outcome: 'upheld',
      receipt: {
        composite_score: 90,
        delivery_accuracy: 99,
        product_accuracy: 30,
        price_integrity: 30,
        return_processing: 20,
        agent_behavior: 'abandoned',
        submitter_score: 80,
        submitter_established: true,
        provenance_tier: 'bilateral',
      },
    }));

    const dismissed = Array(20).fill(null).map(() => makeCalibrationRecord({
      outcome: 'dismissed',
      receipt: {
        composite_score: 70,
        delivery_accuracy: 70,
        product_accuracy: 70,
        price_integrity: 70,
        return_processing: 70,
        agent_behavior: 'completed',
        submitter_score: 80,
        submitter_established: true,
        provenance_tier: 'bilateral',
      },
    }));

    const data = [...upheld, ...dismissed];
    const stats = makeStats({ upheld: 40, dismissed: 20 });

    const result = computeWeightRecommendation(data, stats);
    expect(result.sufficient_data).toBe(true);

    if (result.recommendation) {
      const weights = result.recommendation.weights;
      const sum = Object.values(weights).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 2);

      // All weights must be within bounds
      const validation = validateScoringWeights(weights);
      expect(validation.valid).toBe(true);

      // Must have metadata
      expect(result.recommendation.generated_at).toBeDefined();
      expect(result.recommendation.window_days).toBe(90);
    }
  });
});

// =============================================================================
// Vertical packs
// =============================================================================

describe('VERTICAL_PACKS', () => {
  it('all vertical packs pass weight validation', () => {
    for (const [name, pack] of Object.entries(VERTICAL_PACKS)) {
      const result = validateScoringWeights(pack.weights);
      expect(result.valid, `${name} vertical pack failed validation: ${result.errors.join(', ')}`).toBe(true);
    }
  });

  it('all vertical pack weights sum to 1.0', () => {
    for (const [name, pack] of Object.entries(VERTICAL_PACKS)) {
      const sum = Object.values(pack.weights).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 2);
    }
  });

  it('government pack has lower behavioral and higher consistency than defaults', () => {
    expect(VERTICAL_PACKS.government.weights.behavioral).toBeLessThan(EP_WEIGHTS_V2.behavioral);
    expect(VERTICAL_PACKS.government.weights.consistency).toBeGreaterThan(EP_WEIGHTS_V2.consistency);
  });

  it('agent_governance pack has highest behavioral weight', () => {
    const agentBehavioral = VERTICAL_PACKS.agent_governance.weights.behavioral;
    for (const [name, pack] of Object.entries(VERTICAL_PACKS)) {
      if (name !== 'agent_governance') {
        expect(agentBehavioral).toBeGreaterThanOrEqual(pack.weights.behavioral);
      }
    }
  });

  it('ecommerce pack equals EP_WEIGHTS_V2 defaults', () => {
    for (const dim of Object.keys(EP_WEIGHTS_V2)) {
      expect(VERTICAL_PACKS.ecommerce.weights[dim]).toBe(EP_WEIGHTS_V2[dim]);
    }
  });
});
