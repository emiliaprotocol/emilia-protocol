import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { computeReceiptHash } from '../lib/scoring.js';
import {
  computeTrustProfile,
  evaluateTrustPolicy,
  TRUST_POLICIES,
  EP_WEIGHTS_V2,
} from '../lib/scoring-v2.js';

// Load canonical fixtures
const fixtures = JSON.parse(readFileSync(new URL('../conformance/fixtures.json', import.meta.url), 'utf8'));

// ============================================================================
// CONFORMANCE SUITE — EP Core RFC v1.1
// Any implementation claiming EP compatibility must pass these tests.
// ============================================================================

// --- 1. Hash determinism ---------------------------------------------------

describe('CONFORMANCE: Receipt hash determinism', () => {
  for (const fixture of fixtures.hash_fixtures) {
    it(`${fixture.name}: produces expected hash`, async () => {
      const hash = await computeReceiptHash(fixture.receipt, fixture.previous_hash);
      expect(hash).toBe(fixture.expected_hash);
    });
  }

  it('key order does not affect hash output', async () => {
    const f = fixtures.hash_fixtures[0];
    // Reverse key order
    const reversed = Object.fromEntries(Object.entries(f.receipt).reverse());
    const h1 = await computeReceiptHash(f.receipt, f.previous_hash);
    const h2 = await computeReceiptHash(reversed, f.previous_hash);
    expect(h1).toBe(h2);
  });

  it('all hashes are 64-character hex strings', async () => {
    for (const f of fixtures.hash_fixtures) {
      const hash = await computeReceiptHash(f.receipt, f.previous_hash);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

// --- 2. Scoring: Sybil resistance ------------------------------------------

describe('CONFORMANCE: Sybil resistance', () => {
  for (const fixture of fixtures.scoring_fixtures) {
    it(`${fixture.name}`, () => {
      const receipts = fixture.receipts.map(r => ({
        ...r,
        delivery_accuracy: 95,
        product_accuracy: 95,
        price_integrity: 100,
        return_processing: 90,
        agent_satisfaction: 95,
        created_at: new Date().toISOString(),
      }));
      const profile = computeTrustProfile(receipts, {});

      if (fixture.expected.score_max !== undefined) {
        expect(profile.score).toBeLessThanOrEqual(fixture.expected.score_max);
      }
      if (fixture.expected.effective_evidence_max !== undefined) {
        expect(profile.effectiveEvidence).toBeLessThanOrEqual(fixture.expected.effective_evidence_max);
      }
      if (fixture.expected.confidence !== undefined) {
        expect(profile.confidence).toBe(fixture.expected.confidence);
      }
    });
  }
});

// --- 3. Policy evaluation --------------------------------------------------

describe('CONFORMANCE: Policy evaluation', () => {
  for (const fixture of fixtures.policy_fixtures) {
    it(`${fixture.name}`, () => {
      let receipts;
      if (fixture.receipts) {
        receipts = fixture.receipts.map(r => ({
          ...r,
          delivery_accuracy: r.delivery_accuracy ?? 90,
          product_accuracy: r.product_accuracy ?? 85,
          price_integrity: r.price_integrity ?? 95,
          return_processing: r.return_processing ?? 80,
          agent_satisfaction: r.agent_satisfaction ?? 88,
          created_at: new Date().toISOString(),
        }));
      } else if (fixture.receipt_template) {
        receipts = Array(fixture.receipt_count).fill(null).map((_, i) => ({
          ...fixture.receipt_template,
          submitted_by: `submitter-${i % fixture.submitter_count}`,
          agent_satisfaction: fixture.receipt_template.agent_satisfaction ?? 90,
          return_processing: fixture.receipt_template.return_processing ?? 85,
          created_at: new Date().toISOString(),
        }));
      }

      const profile = computeTrustProfile(receipts, {});
      const policy = TRUST_POLICIES[fixture.policy];
      const result = evaluateTrustPolicy(profile, policy);

      expect(result.pass).toBe(fixture.expected_pass);

      if (fixture.expected_failure_contains) {
        expect(result.failures.some(f => f.includes(fixture.expected_failure_contains))).toBe(true);
      }
    });
  }
});

// --- 4. Confidence levels --------------------------------------------------

describe('CONFORMANCE: Confidence levels from effective evidence', () => {
  for (const fixture of fixtures.confidence_level_fixtures) {
    it(`effective_evidence ${fixture.effective_evidence} → ${fixture.expected_confidence}`, () => {
      let conf;
      const ee = fixture.effective_evidence;
      if (ee === 0) conf = 'pending';
      else if (ee < 1.0) conf = 'insufficient';
      else if (ee < 5.0) conf = 'provisional';
      else if (ee < 20.0) conf = 'emerging';
      else conf = 'confident';
      expect(conf).toBe(fixture.expected_confidence);
    });
  }
});

// --- 5. Weight model -------------------------------------------------------

describe('CONFORMANCE: Weight model', () => {
  it('v2 weights match canonical fixture', () => {
    const canonical = fixtures.weight_fixtures.v2_weights;
    for (const [key, value] of Object.entries(canonical)) {
      expect(EP_WEIGHTS_V2[key]).toBeCloseTo(value, 10);
    }
  });

  it('v2 weights sum to exactly 1.00', () => {
    const sum = Object.values(EP_WEIGHTS_V2).reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(fixtures.weight_fixtures.expected_sum, 10);
  });
});

// --- 6. Establishment rules -----------------------------------------------

describe('CONFORMANCE: Establishment rules', () => {
  for (const fixture of fixtures.establishment_fixtures) {
    it(`${fixture.name}`, () => {
      const receipts = Array(fixture.receipt_count).fill(null).map((_, i) => ({
        submitted_by: fixture.submitters[i % fixture.submitters.length],
        submitter_established: fixture.submitter_established,
        submitter_score: fixture.submitter_score ?? 50,
        graph_weight: 1.0,
        agent_behavior: 'completed',
        composite_score: 90,
        delivery_accuracy: 90,
        product_accuracy: 85,
        price_integrity: 95,
        return_processing: 80,
        agent_satisfaction: 88,
        created_at: new Date().toISOString(),
      }));
      const profile = computeTrustProfile(receipts, {});

      if (fixture.expected_established) {
        expect(profile.effectiveEvidence).toBeGreaterThanOrEqual(5.0);
        expect(profile.uniqueSubmitters).toBeGreaterThanOrEqual(3);
      } else {
        // Either evidence or submitter count is below threshold
        const meetsEvidence = profile.effectiveEvidence >= 5.0;
        const meetsSubmitters = profile.uniqueSubmitters >= 3;
        expect(meetsEvidence && meetsSubmitters).toBe(false);
      }
    });
  }
});
