// SPDX-License-Identifier: Apache-2.0
// EP-OUTCOME-BINDING-v1 — predicted effects + observed-effects attestation +
// machine-detectable divergence. Runs the full conformance suite
// (conformance/vectors/outcome-binding.v1.json) plus direct unit coverage of
// the decimal-string comparator, the digest, and the fail-closed guards.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import {
  PREDICATE_OPS, DIVERGENCE_OUTCOMES, predictedEffectsDigest,
  validatePredictedEffects, isDecimalString, compareDecimalStrings,
  evaluatePredictedEffects,
} from '../lib/evidence/effect-predicates.js';
import {
  EVIDENCE_GRAPH_VERSION, REASON_CODES, artifactDigest, evaluateEvidenceGraph,
} from '../lib/evidence/evidence-graph.js';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const suite = JSON.parse(fs.readFileSync(
  path.join(here, '..', 'conformance', 'vectors', 'outcome-binding.v1.json'), 'utf8',
));

const ACTION = 'sha256:' + 'a'.repeat(64);
const AS_OF = '2026-07-08T00:02:00Z';

// Graph harness: a one-node EP-AEG-v1 graph whose effect_attestation verifier
// surfaces exactly the fields the vector's attestation carries — the same
// shape the real executor-attestation verifier reports.
function runGraphVector(v) {
  const att = {
    typ: 'effect_attestation', action: ACTION,
    receipt_id: 'tr_outcome_1', issued_at: '2026-07-08T00:00:00Z',
    ...v.attestation,
  };
  const id = artifactDigest(att);
  const doc = {
    '@version': EVIDENCE_GRAPH_VERSION, action_digest: ACTION,
    nodes: [{ id, type: 'effect_attestation', artifact: att }], edges: [],
  };
  const verifiers = {
    effect_attestation: (a) => ({
      valid: true, action_digest: a.action, issued_at: a.issued_at,
      receipt_id: a.receipt_id,
      observed_effect_digest: a.observed_effect_digest,
      committed_effect_digest: a.committed_effect_digest,
      observed_effects: a.observed_effects,
      predicted_effects: a.predicted_effects,
      predicted_effects_digest: a.predicted_effects_digest,
    }),
  };
  const policy = {
    policy_id: 'ep:test:outcome-binding', reliance_purpose: 'regulated_execution',
    requirement: 'effect_attestation', ...(v.policy || {}),
  };
  return evaluateEvidenceGraph(doc, policy, { verifiers, as_of: AS_OF });
}

describe(`conformance suite ${suite.suite} (${suite.vectors.length} vectors)`, () => {
  const predicateVectors = suite.vectors.filter((v) => v.kind === 'predicate');
  const graphVectors = suite.vectors.filter((v) => v.kind === 'graph');

  it('covers every predicate op passing AND failing, plus the graph wiring', () => {
    expect(suite.vectors.length).toBeGreaterThanOrEqual(10);
    const text = JSON.stringify(predicateVectors);
    for (const op of PREDICATE_OPS) expect(text).toContain(`"op":"${op}"`);
    expect(graphVectors.length).toBeGreaterThanOrEqual(4);
  });

  for (const v of predicateVectors) {
    it(`predicate: ${v.id}`, () => {
      const r = evaluatePredictedEffects(v.predicted_effects, v.observed_effects);
      expect(DIVERGENCE_OUTCOMES).toContain(r.outcome);
      expect(r.outcome).toBe(v.expect.outcome);
      if (v.expect.reason_contains) {
        expect(r.reasons.join(' ')).toContain(v.expect.reason_contains);
      }
      if (r.outcome !== 'in_bounds') {
        // A non-pass ALWAYS carries a reason (a refusal is explained, never silent).
        expect(r.reasons.length).toBeGreaterThan(0);
      }
    });
  }

  for (const v of graphVectors) {
    it(`graph: ${v.id}`, () => {
      const r = runGraphVector(v);
      expect(r.verdict).toBe(v.expect.verdict);
      if (v.expect.reason_contains) {
        expect(r.reasons.join(' ')).toContain(v.expect.reason_contains);
      }
    });
  }
});

describe('decimal-string comparison (exact, no floats)', () => {
  it('orders integers, fractions, negatives, and float-hostile magnitudes exactly', () => {
    expect(compareDecimalStrings('9007199254740993', '9007199254740992')).toBe(1); // beyond 2^53
    expect(compareDecimalStrings('0.1', '0.10')).toBe(0);   // trailing zeros normalize
    expect(compareDecimalStrings('-0', '0')).toBe(0);       // -0 == 0
    expect(compareDecimalStrings('-1.5', '-1.05')).toBe(-1);
    expect(compareDecimalStrings('10', '9.999999')).toBe(1);
    expect(compareDecimalStrings('25000.00', '25000.01')).toBe(-1);
  });

  it('fails closed on non-decimal input: null, never a false equality', () => {
    expect(compareDecimalStrings('1e5', '1')).toBe(null);   // exponent form rejected
    expect(compareDecimalStrings('01', '1')).toBe(null);    // leading zero rejected
    expect(compareDecimalStrings('1.', '1')).toBe(null);
    expect(compareDecimalStrings(1, '1')).toBe(null);       // number, not string
    expect(isDecimalString('12.50')).toBe(true);
    expect(isDecimalString('NaN')).toBe(false);
  });
});

describe('predicted_effects digest + validation', () => {
  const PREDICTED = [
    { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '25000.00' } },
  ];

  it('digest is deterministic and key-order-independent (JCS canonical bytes)', () => {
    const reordered = [{ target: 'acct:vendor-9', predicate: { value: '25000.00', op: 'lte' }, effect_type: 'payment' }];
    expect(predictedEffectsDigest(PREDICTED)).toBe(predictedEffectsDigest(reordered));
    expect(predictedEffectsDigest(PREDICTED)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('rejects unknown predicate members (a constraint the evaluator would silently ignore)', () => {
    const r = validatePredictedEffects([
      { effect_type: 'payment', target: 'a', predicate: { op: 'lte', value: '1', tolerance: '0.1' } },
    ]);
    expect(r.ok).toBe(false);
    expect(r.reasons.join(' ')).toContain('unknown member');
  });

  it('rejects an empty array, a range with min > max, and a non-integer count', () => {
    expect(validatePredictedEffects([]).ok).toBe(false);
    expect(validatePredictedEffects([
      { effect_type: 'x', target: 'y', predicate: { op: 'range', min: '5', max: '1' } },
    ]).reasons.join(' ')).toContain('min > max');
    expect(validatePredictedEffects([
      { effect_type: 'x', target: 'y', predicate: { op: 'count_lte', value: '1.5' } },
    ]).ok).toBe(false);
  });
});

describe('graph wiring — fail-closed guards beyond the suite', () => {
  const PREDICTED = [
    { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '25000.00' } },
  ];

  it('predicted effects that do not hash to the bound digest are refused (effect_incomparable)', () => {
    const r = runGraphVector({
      attestation: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: 'sha256:' + '1'.repeat(64), // wrong digest
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('do not hash to the bound predicted_effects_digest');
  });

  it('a correctly bound predicted_effects_digest passes through to predicate evaluation', () => {
    const r = runGraphVector({
      attestation: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: predictedEffectsDigest(PREDICTED),
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
      },
    });
    expect(r.verdict).toBe('admissible');
  });

  it('an in-bounds predicate result never masks a diverging exact digest (both paths run)', () => {
    const r = runGraphVector({
      attestation: {
        predicted_effects: PREDICTED,
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
        observed_effect_digest: 'sha256:' + 'f'.repeat(64),
        committed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('approved X, executed Y');
  });

  it('effect_incomparable is a registered reason code', () => {
    expect(REASON_CODES).toContain('effect_incomparable');
    expect(REASON_CODES).toContain('effect_divergence');
    expect(REASON_CODES).toContain('effect_commitment_missing');
  });
});
