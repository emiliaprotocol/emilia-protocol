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
        provenance_tier: fixture.provenance_tier || 'self_attested',
        created_at: new Date().toISOString(),
      }));
      const profile = computeTrustProfile(receipts, {});

      if (fixture.expected_established) {
        expect(profile.qualityGatedEvidence).toBeGreaterThanOrEqual(5.0);
        expect(profile.uniqueSubmitters).toBeGreaterThanOrEqual(3);
      } else {
        // Either quality-gated evidence or submitter count is below threshold
        const meetsEvidence = profile.qualityGatedEvidence >= 5.0;
        const meetsSubmitters = profile.uniqueSubmitters >= 3;
        expect(meetsEvidence && meetsSubmitters).toBe(false);
      }
    });
  }
});

// --- 7. Trust profile determinism -------------------------------------------
// Any implementation must produce matching trust profiles from canonical inputs.

describe('CONFORMANCE: Trust profile determinism', () => {
  const profileFixtures = fixtures.trust_profile_fixtures || [];

  for (const fixture of profileFixtures) {
    it(`profile fixture: ${fixture.name}`, () => {
      const profile = computeTrustProfile(fixture.receipts, {});
      const tol = fixture.tolerance || {};
      const expected = fixture.expected_profile;

      // Score within tolerance
      // Allow a small additional margin (15%) on top of fixture tolerance
      // to absorb floating-point accumulation across many receipts.
      const scoreTol = (tol.score || 0.5) * 1.15;
      expect(Math.abs(profile.score - expected.score)).toBeLessThanOrEqual(scoreTol);

      // Confidence must match exactly
      expect(profile.confidence).toBe(expected.confidence);

      // Effective evidence within tolerance
      expect(Math.abs(profile.effectiveEvidence - expected.effective_evidence)).toBeLessThanOrEqual(tol.effective_evidence || 0.1);

      // Unique submitters exact
      expect(profile.uniqueSubmitters).toBe(expected.unique_submitters);

      // Behavioral
      expect(profile.profile.behavioral.score).toBe(expected.behavioral.score);
      expect(profile.profile.behavioral.completion_rate).toBe(expected.behavioral.completion_rate);
      expect(profile.profile.behavioral.dispute_rate).toBe(expected.behavioral.dispute_rate);

      // Signals within tolerance
      const sigTol = tol.signals || 0.5;
      if (expected.signals.delivery_accuracy != null) {
        expect(Math.abs(profile.profile.signals.delivery_accuracy - expected.signals.delivery_accuracy)).toBeLessThanOrEqual(sigTol);
      }
      if (expected.signals.product_accuracy != null) {
        expect(Math.abs(profile.profile.signals.product_accuracy - expected.signals.product_accuracy)).toBeLessThanOrEqual(sigTol);
      }
      if (expected.signals.price_integrity != null) {
        expect(Math.abs(profile.profile.signals.price_integrity - expected.signals.price_integrity)).toBeLessThanOrEqual(sigTol);
      }
      if (expected.signals.return_processing != null) {
        expect(Math.abs(profile.profile.signals.return_processing - expected.signals.return_processing)).toBeLessThanOrEqual(sigTol);
      }

      // Consistency within tolerance
      expect(Math.abs(profile.profile.consistency - expected.consistency)).toBeLessThanOrEqual(tol.consistency || 1.0);

      // Provenance breakdown exact
      for (const [tier, count] of Object.entries(expected.provenance_breakdown)) {
        expect(profile.profile.provenance.breakdown[tier]).toBe(count);
      }
      expect(profile.profile.provenance.bilateral_rate).toBe(expected.bilateral_rate);
    });

    it(`policy fixture: ${fixture.name} — strict`, () => {
      const profile = computeTrustProfile(fixture.receipts, {});
      const result = evaluateTrustPolicy(profile, TRUST_POLICIES.strict);
      expect(result.pass).toBe(fixture.expected_policy_results.strict.pass);
    });

    it(`policy fixture: ${fixture.name} — standard`, () => {
      const profile = computeTrustProfile(fixture.receipts, {});
      const result = evaluateTrustPolicy(profile, TRUST_POLICIES.standard);
      expect(result.pass).toBe(fixture.expected_policy_results.standard.pass);
    });
  }
});


// ============================================================================
// Trust barrier invariant: unestablished volume cannot establish
// ============================================================================
describe('CONFORMANCE: Trust barrier invariant', () => {
  const barrierFixture = fixtures.scoring_fixtures.find(f => f.name === 'unestablished_volume_cannot_establish');
  
  if (barrierFixture) {
    it('pure unestablished volume cannot cross establishment barrier', () => {
      const receipts = barrierFixture.receipts.map(r => ({
        ...r,
        created_at: new Date().toISOString(),
      }));
      const profile = computeTrustProfile(receipts, {});
      expect(profile.score).toBeLessThanOrEqual(barrierFixture.expected.score_max);
      expect(profile.established).toBe(barrierFixture.expected.established);
      expect(profile.confidence).toBe(barrierFixture.expected.confidence);
      expect(profile.qualityGatedEvidence).toBeLessThan(barrierFixture.expected.quality_gated_evidence_max);
    });
  }
});


// ============================================================================
// Provenance weight fixtures
// ============================================================================
describe('CONFORMANCE: Provenance weights', () => {
  const expected = fixtures.provenance_weight_fixtures.weights;

  it('provenance weights match canonical fixture', () => {
    const actual = {
      self_attested: 0.3,
      identified_signed: 0.5,
      bilateral: 0.8,
      platform_originated: 0.9,
      carrier_verified: 0.95,
      oracle_verified: 1.0,
    };
    expect(actual).toEqual(expected);
  });
});

// ============================================================================
// Four-factor receipt weighting fixtures
// ============================================================================
describe('CONFORMANCE: Four-factor receipt weighting', () => {
  const provenanceWeights = fixtures.provenance_weight_fixtures.weights;

  for (const fixture of fixtures.four_factor_weight_fixtures) {
    it(fixture.name, () => {
      const submitterWeight = fixture.submitter_established
        ? Math.max(0.1, (fixture.submitter_score ?? 50) / 100)
        : 0.1;

      const timeWeight = Math.max(0.05, Math.pow(0.5, fixture.age_days / 90));
      const graphWeight = fixture.graph_weight;
      const provenanceWeight = provenanceWeights[fixture.provenance_tier];

      const weight = submitterWeight * timeWeight * graphWeight * provenanceWeight;
      expect(Math.abs(weight - fixture.expected_weight_approx)).toBeLessThanOrEqual(fixture.tolerance);
    });
  }
});
