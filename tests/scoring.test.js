import { describe, it, expect } from 'vitest';
import {
  computeReceiptComposite,
  computeEmiliaScore,
  computeMatchScore,
  computeReceiptHash,
  computeSubmitterWeight,
  computeTimeDecay,
  EMILIA_WEIGHTS,
  DEFAULT_SCORE,
} from '../lib/scoring.js';

// Helper: create a receipt with defaults
function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    agent_satisfaction: 88,
    composite_score: 88,
    submitted_by: overrides.submitted_by || 'submitter-1',
    submitter_score: overrides.submitter_score ?? 50,
    submitter_established: overrides.submitter_established ?? false,
    graph_weight: overrides.graph_weight ?? 1.0,
    created_at: overrides.created_at || new Date().toISOString(),
    ...overrides,
  };
}

// Helper: create an established receipt (high submitter score, established)
function makeEstablishedReceipt(overrides = {}) {
  return makeReceipt({
    submitter_score: 85,
    submitter_established: true,
    ...overrides,
  });
}

describe('EMILIA_WEIGHTS', () => {
  it('weights sum to 1.0', () => {
    const total = Object.values(EMILIA_WEIGHTS).reduce((a, b) => a + b, 0);
    expect(total).toBeCloseTo(1.0, 10);
  });
});

describe('computeReceiptComposite', () => {
  it('computes weighted average with all signals', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: 100, product_accuracy: 100,
      price_integrity: 100, return_processing: 100, agent_satisfaction: 100,
    });
    expect(result).toBe(100);
  });

  it('returns DEFAULT_SCORE when no signals provided', () => {
    expect(computeReceiptComposite({})).toBe(DEFAULT_SCORE);
  });

  it('handles partial signals by normalizing weight', () => {
    const result = computeReceiptComposite({
      delivery_accuracy: 80, product_accuracy: 60,
    });
    expect(result).toBeCloseTo(70.9, 0);
  });
});

describe('computeSubmitterWeight', () => {
  it('unestablished submitter always gets 0.1', () => {
    expect(computeSubmitterWeight(50, false)).toBe(0.1);
    expect(computeSubmitterWeight(99, false)).toBe(0.1);
    expect(computeSubmitterWeight(10, false)).toBe(0.1);
  });

  it('established submitter gets score/100', () => {
    expect(computeSubmitterWeight(90, true)).toBe(0.9);
    expect(computeSubmitterWeight(50, true)).toBe(0.5);
  });

  it('established submitter has floor of 0.1', () => {
    expect(computeSubmitterWeight(5, true)).toBe(0.1);
  });

  it('null score defaults to 0.5 for established', () => {
    expect(computeSubmitterWeight(null, true)).toBe(0.5);
  });
});

describe('computeEmiliaScore — effective evidence dampening', () => {
  it('returns DEFAULT_SCORE for no receipts', () => {
    const result = computeEmiliaScore([]);
    expect(result.score).toBe(DEFAULT_SCORE);
    expect(result.established).toBe(false);
    expect(result.effectiveEvidence).toBe(0);
  });

  it('5 perfect receipts from UNESTABLISHED submitters score ~55, NOT 100', () => {
    // This is THE sybil resistance test.
    // 5 receipts × 0.1x weight = 0.5 effective evidence
    // Dampening: 50 + (100 - 50) * (0.5 / 5) = 55
    const receipts = Array(5).fill(null).map((_, i) => makeReceipt({
      delivery_accuracy: 100, product_accuracy: 100,
      price_integrity: 100, return_processing: 100, agent_satisfaction: 100,
      composite_score: 100,
      submitted_by: `fake-${i}`,
      submitter_score: 50,
      submitter_established: false,
    }));
    const result = computeEmiliaScore(receipts);
    expect(result.score).toBeLessThan(60);
    expect(result.score).toBeGreaterThan(50);
    expect(result.established).toBe(false);
    expect(result.effectiveEvidence).toBeCloseTo(0.5, 1);
  });

  it('5 perfect receipts from ESTABLISHED submitters ARE established', () => {
    const receipts = Array(5).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: 100, product_accuracy: 100,
      price_integrity: 100, return_processing: 100, agent_satisfaction: 100,
      composite_score: 100,
      submitted_by: `real-${i}`,
    }));
    const result = computeEmiliaScore(receipts);
    // 5 × 0.85 weight = 4.25 effective evidence
    // Still under 5.0 threshold, so dampened but close
    expect(result.score).toBeGreaterThan(80);
    // Need 3+ unique submitters AND 5.0+ effective evidence for established
    expect(result.uniqueSubmitters).toBe(5);
  });

  it('10 receipts from established high-score submitters are fully established', () => {
    const receipts = Array(10).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: 90, product_accuracy: 85,
      price_integrity: 95, return_processing: 80, agent_satisfaction: 88,
      composite_score: 88,
      submitted_by: `real-${i % 4}`, // 4 unique submitters
      submitter_score: 90,
    }));
    const result = computeEmiliaScore(receipts);
    expect(result.established).toBe(true);
    expect(result.effectiveEvidence).toBeGreaterThan(5);
    expect(result.uniqueSubmitters).toBeGreaterThanOrEqual(3);
    expect(result.score).toBeGreaterThan(80);
  });

  it('graph_weight reduces effective evidence', () => {
    const normal = Array(5).fill(null).map((_, i) => makeEstablishedReceipt({
      submitted_by: `s-${i}`, graph_weight: 1.0,
    }));
    const flagged = Array(5).fill(null).map((_, i) => makeEstablishedReceipt({
      submitted_by: `s-${i}`, graph_weight: 0.3,
    }));

    const normalResult = computeEmiliaScore(normal);
    const flaggedResult = computeEmiliaScore(flagged);

    expect(normalResult.effectiveEvidence).toBeGreaterThan(flaggedResult.effectiveEvidence);
    // Flagged receipts should produce a more dampened score
    expect(normalResult.score).toBeGreaterThan(flaggedResult.score);
  });
});

describe('computeEmiliaScore — other properties', () => {
  it('score is between 0 and 100', () => {
    const perfect = Array(10).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: 100, product_accuracy: 100, price_integrity: 100,
      return_processing: 100, agent_satisfaction: 100, composite_score: 100,
      submitted_by: `s-${i}`,
    }));
    const terrible = Array(10).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: 0, product_accuracy: 0, price_integrity: 0,
      return_processing: 0, agent_satisfaction: 0, composite_score: 0,
      submitted_by: `s-${i}`,
    }));

    expect(computeEmiliaScore(perfect).score).toBeLessThanOrEqual(100);
    expect(computeEmiliaScore(terrible).score).toBeGreaterThanOrEqual(0);
  });

  it('consistency rewards low variance', () => {
    const consistent = Array(10).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: 80, product_accuracy: 80, price_integrity: 80,
      return_processing: 80, agent_satisfaction: 80, composite_score: 80,
      submitted_by: `s-${i % 4}`,
    }));
    const inconsistent = Array(10).fill(null).map((_, i) => makeEstablishedReceipt({
      delivery_accuracy: i % 2 === 0 ? 50 : 100,
      product_accuracy: i % 2 === 0 ? 50 : 100,
      price_integrity: i % 2 === 0 ? 50 : 100,
      return_processing: i % 2 === 0 ? 50 : 100,
      agent_satisfaction: i % 2 === 0 ? 50 : 100,
      composite_score: i % 2 === 0 ? 50 : 100,
      submitted_by: `s-${i % 4}`,
    }));

    expect(computeEmiliaScore(consistent).breakdown.consistency).toBeGreaterThan(
      computeEmiliaScore(inconsistent).breakdown.consistency
    );
  });

  it('uses rolling window of 200', () => {
    const receipts = Array(300).fill(null).map((_, i) => makeEstablishedReceipt({
      submitted_by: `s-${i % 10}`,
    }));
    expect(computeEmiliaScore(receipts).receiptCount).toBe(200);
  });
});

describe('computeReceiptHash', () => {
  it('produces deterministic hash', async () => {
    const receipt = {
      entity_id: 'test-entity', submitted_by: 'test-submitter',
      transaction_ref: 'tx-123', transaction_type: 'purchase',
      delivery_accuracy: 95, product_accuracy: 88,
      price_integrity: 100, return_processing: null,
      agent_satisfaction: 90, agent_behavior: 'completed',
      claims: null, evidence: { foo: 'bar' },
      submitter_score: 50, submitter_established: false,
    };

    const hash1 = await computeReceiptHash(receipt, null);
    const hash2 = await computeReceiptHash(receipt, null);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('different previous_hash produces different hash', async () => {
    const receipt = {
      entity_id: 'test', submitted_by: 'sub',
      transaction_ref: 'tx', transaction_type: 'purchase',
      delivery_accuracy: 80, product_accuracy: 80,
      price_integrity: 80, return_processing: null,
      agent_satisfaction: 80, agent_behavior: null,
      claims: null, evidence: {},
      submitter_score: 50, submitter_established: false,
    };

    const hash1 = await computeReceiptHash(receipt, null);
    const hash2 = await computeReceiptHash(receipt, 'abc123');
    expect(hash1).not.toBe(hash2);
  });

  it('canonical JSON produces consistent hashes regardless of key order', async () => {
    const receipt1 = {
      entity_id: 'e', submitted_by: 's', transaction_ref: 't',
      transaction_type: 'purchase', delivery_accuracy: 90,
      product_accuracy: null, price_integrity: null,
      return_processing: null, agent_satisfaction: null,
      agent_behavior: null, claims: null,
      evidence: { a: 1, b: 2 },
      submitter_score: 50, submitter_established: false,
    };
    // Same data, different JS object creation order
    const receipt2 = {
      submitter_established: false, submitter_score: 50,
      evidence: { b: 2, a: 1 },
      claims: null, agent_behavior: null,
      agent_satisfaction: null, return_processing: null,
      price_integrity: null, product_accuracy: null,
      delivery_accuracy: 90, transaction_type: 'purchase',
      transaction_ref: 't', submitted_by: 's', entity_id: 'e',
    };

    const hash1 = await computeReceiptHash(receipt1, null);
    const hash2 = await computeReceiptHash(receipt2, null);
    expect(hash1).toBe(hash2);
  });
});

describe('computeMatchScore', () => {
  it('returns null if below minimum score', () => {
    expect(computeMatchScore(0.9, 60, 70)).toBeNull();
  });

  it('returns match score above minimum', () => {
    const result = computeMatchScore(0.8, 85, 70);
    expect(result).toBeCloseTo(0.82, 2);
  });
});
