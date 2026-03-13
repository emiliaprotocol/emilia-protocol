import { describe, it, expect } from 'vitest';
import {
  computeReceiptComposite,
  computeEmiliaScore,
  computeMatchScore,
  computeReceiptHash,
  EMILIA_WEIGHTS,
  DEFAULT_SCORE,
  MIN_RECEIPTS_ESTABLISHED,
} from '../lib/scoring.js';

describe('EMILIA_WEIGHTS', () => {
  it('weights sum to 1.0', () => {
    const total = Object.values(EMILIA_WEIGHTS).reduce((a, b) => a + b, 0);
    expect(total).toBeCloseTo(1.0, 10);
  });
});

describe('computeReceiptComposite', () => {
  it('computes weighted average with all signals', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: 100,
      product_accuracy: 100,
      price_integrity: 100,
      return_processing: 100,
      agent_satisfaction: 100,
    });
    expect(result).toBe(100);
  });

  it('returns DEFAULT_SCORE when no signals provided', () => {
    const result = computeReceiptComposite({});
    expect(result).toBe(DEFAULT_SCORE);
  });

  it('handles partial signals by normalizing weight', () => {
    // Only delivery_accuracy (30%) and product_accuracy (25%)
    const result = computeReceiptComposite({
      delivery_accuracy: 80,
      product_accuracy: 60,
    });
    // (80*0.30 + 60*0.25) / (0.30 + 0.25) = (24+15) / 0.55 = 70.9...
    expect(result).toBeCloseTo(70.9, 0);
  });

  it('ignores null and NaN values', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: 90,
      product_accuracy: null,
      price_integrity: NaN,
      agent_satisfaction: 80,
    });
    // Only delivery (0.30) and satisfaction (0.10) counted
    // (90*0.30 + 80*0.10) / (0.30 + 0.10) = (27+8) / 0.40 = 87.5
    expect(result).toBeCloseTo(87.5, 0);
  });

  it('handles zero scores correctly', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: 0,
      product_accuracy: 0,
      price_integrity: 0,
      return_processing: 0,
      agent_satisfaction: 0,
    });
    expect(result).toBe(0);
  });
});

describe('computeEmiliaScore', () => {
  it('returns DEFAULT_SCORE for no receipts', () => {
    const result = computeEmiliaScore([]);
    expect(result.score).toBe(DEFAULT_SCORE);
    expect(result.established).toBe(false);
    expect(result.receiptCount).toBe(0);
  });

  it('dampens score for < 5 receipts', () => {
    const receipts = [
      { delivery_accuracy: 100, product_accuracy: 100, price_integrity: 100, return_processing: 100, agent_satisfaction: 100, composite_score: 100 },
    ];
    const result = computeEmiliaScore(receipts);
    // With 1 receipt, dampened: 50 + (100-50) * (1/5) = 60
    expect(result.score).toBe(60);
    expect(result.established).toBe(false);
  });

  it('marks as established at 5+ receipts', () => {
    const receipts = Array(5).fill({
      delivery_accuracy: 90,
      product_accuracy: 85,
      price_integrity: 95,
      return_processing: 80,
      agent_satisfaction: 88,
      composite_score: 88,
    });
    const result = computeEmiliaScore(receipts);
    expect(result.established).toBe(true);
    expect(result.receiptCount).toBe(5);
    expect(result.score).toBeGreaterThan(80);
  });

  it('score is between 0 and 100', () => {
    const perfectReceipts = Array(10).fill({
      delivery_accuracy: 100,
      product_accuracy: 100,
      price_integrity: 100,
      return_processing: 100,
      agent_satisfaction: 100,
      composite_score: 100,
    });
    const terrible = Array(10).fill({
      delivery_accuracy: 0,
      product_accuracy: 0,
      price_integrity: 0,
      return_processing: 0,
      agent_satisfaction: 0,
      composite_score: 0,
    });

    expect(computeEmiliaScore(perfectReceipts).score).toBeLessThanOrEqual(100);
    expect(computeEmiliaScore(terrible).score).toBeGreaterThanOrEqual(0);
  });

  it('provides breakdown for established entities', () => {
    const receipts = Array(6).fill({
      delivery_accuracy: 95,
      product_accuracy: 88,
      price_integrity: 100,
      return_processing: 75,
      agent_satisfaction: 90,
      composite_score: 90,
    });
    const result = computeEmiliaScore(receipts);
    expect(result.breakdown).not.toBeNull();
    expect(result.breakdown.delivery_accuracy).toBe(95);
    expect(result.breakdown.product_accuracy).toBe(88);
  });

  it('consistency rewards low variance', () => {
    // Consistent: all 80
    const consistent = Array(10).fill({
      delivery_accuracy: 80, product_accuracy: 80, price_integrity: 80,
      return_processing: 80, agent_satisfaction: 80, composite_score: 80,
    });
    // Inconsistent: alternating 50 and 100
    const inconsistent = Array(10).fill(null).map((_, i) => {
      const v = i % 2 === 0 ? 50 : 100;
      return {
        delivery_accuracy: v, product_accuracy: v, price_integrity: v,
        return_processing: v, agent_satisfaction: v, composite_score: v,
      };
    });

    const consistentResult = computeEmiliaScore(consistent);
    const inconsistentResult = computeEmiliaScore(inconsistent);

    // Same average signals but consistent should score slightly higher
    expect(consistentResult.breakdown.consistency).toBeGreaterThan(
      inconsistentResult.breakdown.consistency
    );
  });

  it('uses rolling window of 200', () => {
    const receipts = Array(300).fill({
      delivery_accuracy: 90, product_accuracy: 90, price_integrity: 90,
      return_processing: 90, agent_satisfaction: 90, composite_score: 90,
    });
    const result = computeEmiliaScore(receipts);
    expect(result.receiptCount).toBe(200);
  });
});

describe('computeMatchScore', () => {
  it('returns null if below minimum score', () => {
    expect(computeMatchScore(0.9, 60, 70)).toBeNull();
  });

  it('returns match score above minimum', () => {
    const result = computeMatchScore(0.8, 85, 70);
    expect(result).not.toBeNull();
    // 0.8 * 0.6 + 0.85 * 0.4 = 0.48 + 0.34 = 0.82
    expect(result).toBeCloseTo(0.82, 2);
  });

  it('perfect relevance + perfect reputation = ~1.0', () => {
    const result = computeMatchScore(1.0, 100, 0);
    // 1.0 * 0.6 + 1.0 * 0.4 = 1.0
    expect(result).toBeCloseTo(1.0, 2);
  });
});

describe('computeReceiptHash', () => {
  it('produces deterministic hash', async () => {
    const receipt = {
      entity_id: 'test-entity',
      submitted_by: 'test-submitter',
      transaction_ref: 'tx-123',
      transaction_type: 'purchase',
      delivery_accuracy: 95,
      product_accuracy: 88,
      price_integrity: 100,
      return_processing: null,
      agent_satisfaction: 90,
      evidence: { foo: 'bar' },
    };

    const hash1 = await computeReceiptHash(receipt, null);
    const hash2 = await computeReceiptHash(receipt, null);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex
  });

  it('different previous_hash produces different hash', async () => {
    const receipt = {
      entity_id: 'test',
      submitted_by: 'sub',
      transaction_ref: 'tx',
      transaction_type: 'purchase',
      delivery_accuracy: 80,
      product_accuracy: 80,
      price_integrity: 80,
      return_processing: null,
      agent_satisfaction: 80,
      evidence: {},
    };

    const hash1 = await computeReceiptHash(receipt, null);
    const hash2 = await computeReceiptHash(receipt, 'abc123');

    expect(hash1).not.toBe(hash2);
  });
});
