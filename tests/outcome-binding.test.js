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

// Graph harness: the effect-attestation verifier surfaces ONLY executor-signed
// observations. Approved commitments come from a separate relying-party
// resolver keyed by receipt_id, so the presenter cannot choose both sides of
// the comparison.
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
      observed_effects: a.observed_effects,
      ...(a.receipt_digest === undefined ? {} : { receipt_digest: a.receipt_digest }),
      ...(a.consumption_nonce === undefined ? {} : { consumption_nonce: a.consumption_nonce }),
      ...(a.verifier_checks === undefined ? {} : { checks: a.verifier_checks }),
    }),
  };
  const policy = {
    policy_id: 'ep:test:outcome-binding', reliance_purpose: 'regulated_execution',
    requirement: 'effect_attestation', ...(v.policy || {}),
  };
  const resolveApprovedEffect = v.approved
    ? (receiptId) => ({
      valid: receiptId === att.receipt_id,
      receipt_id: att.receipt_id,
      action_digest: ACTION,
      ...v.approved,
    })
    : undefined;
  return evaluateEvidenceGraph(doc, policy, { verifiers, resolveApprovedEffect, as_of: AS_OF });
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
      approved: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: 'sha256:' + '1'.repeat(64), // wrong digest
      },
      attestation: {
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('do not hash to the bound predicted_effects_digest');
  });

  it('a correctly bound predicted_effects_digest passes through to predicate evaluation', () => {
    const r = runGraphVector({
      approved: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: predictedEffectsDigest(PREDICTED),
      },
      attestation: {
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
      },
    });
    expect(r.verdict).toBe('admissible');
  });

  it('an in-bounds predicate result never masks a diverging exact digest (both paths run)', () => {
    const r = runGraphVector({
      approved: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: predictedEffectsDigest(PREDICTED),
        committed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
      attestation: {
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
        observed_effect_digest: 'sha256:' + 'f'.repeat(64),
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('approved X, executed Y');
  });

  it('replay_digest binds exact commitments and the final verdict', () => {
    const attestation = {
      observed_effect_digest: 'sha256:' + 'e'.repeat(64),
    };
    const admitted = runGraphVector({
      approved: { committed_effect_digest: 'sha256:' + 'e'.repeat(64) },
      attestation,
    });
    const conflicted = runGraphVector({
      approved: { committed_effect_digest: 'sha256:' + 'f'.repeat(64) },
      attestation,
    });
    expect(admitted.verdict).toBe('admissible');
    expect(conflicted.verdict).toBe('conflicted');
    expect(admitted.replay_digest).not.toBe(conflicted.replay_digest);
    expect(admitted.outcome_binding.evaluations[0]).toMatchObject({
      source: 'exact_effect_digest',
      outcome: 'in_bounds',
    });
  });

  it('relying-party policy cannot loosen the signed receipt prediction', () => {
    const signed = [
      { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '10.00' } },
    ];
    const policy = [
      { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '1000.00' } },
    ];
    const r = runGraphVector({
      approved: {
        predicted_effects: signed,
        predicted_effects_digest: predictedEffectsDigest(signed),
      },
      attestation: {
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '500.00' }],
      },
      policy: { predicted_effects: policy },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.outcome_binding.evaluations.map((item) => [item.source, item.outcome])).toEqual([
      ['signed_receipt', 'divergent'],
      ['relying_party_policy', 'in_bounds'],
    ]);
  });

  it('matches the graph action across equivalent bare and sha256-prefixed forms', () => {
    const r = runGraphVector({
      approved: { committed_effect_digest: 'sha256:' + 'e'.repeat(64) },
      attestation: {
        action: 'a'.repeat(64),
        observed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
    });
    expect(r.verdict).toBe('admissible');
  });

  it('requires the approved source to bind the exact referenced receipt', () => {
    const r = runGraphVector({
      approved: {
        receipt_id: undefined,
        committed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
      attestation: { observed_effect_digest: 'sha256:' + 'e'.repeat(64) },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('receipt');
  });

  it('a matching policy-pinned effect cannot mask failed resolver linkage', () => {
    const effect = 'sha256:' + 'e'.repeat(64);
    const r = runGraphVector({
      approved: { receipt_id: undefined, committed_effect_digest: effect },
      attestation: { observed_effect_digest: effect },
      policy: { expected_effect_digest: effect },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.outcome_binding.evaluations).toContainEqual(expect.objectContaining({
      source: 'approved_effect_linkage', outcome: 'incomparable',
    }));
  });

  it('refuses receipt-digest and consumption-nonce substitutions when both APIs expose them', () => {
    const r = runGraphVector({
      approved: {
        receipt_digest: 'sha256:' + 'b'.repeat(64),
        consumption_nonce: 'nonce:approved',
        committed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
      attestation: {
        receipt_digest: 'sha256:' + 'c'.repeat(64),
        consumption_nonce: 'nonce:attested',
        observed_effect_digest: 'sha256:' + 'e'.repeat(64),
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toMatch(/receipt_digest|consumption_nonce/);
  });

  it('does not accept valid:true over explicit failed signature or executor-pin checks', () => {
    const r = runGraphVector({
      approved: { committed_effect_digest: 'sha256:' + 'e'.repeat(64) },
      attestation: {
        observed_effect_digest: 'sha256:' + 'e'.repeat(64),
        verifier_checks: { signature: false, executor_key_pinned: false },
      },
    });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reasons.join(' ')).toMatch(/signature|executor/);
  });

  it('fails closed on a structurally malformed relying-party prediction array', () => {
    const r = runGraphVector({
      approved: {
        predicted_effects: PREDICTED,
        predicted_effects_digest: predictedEffectsDigest(PREDICTED),
      },
      attestation: {
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '1.00' }],
      },
      policy: {
        predicted_effects: [{
          effect_type: 'payment', target: 'acct:vendor-9',
          predicate: { op: 'lte', value: '10.00', ignored_tolerance: '999.00' },
        }],
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.outcome_binding.evaluations.find((row) => row.source === 'relying_party_policy'))
      .toMatchObject({ outcome: 'incomparable' });
    expect(r.reasons.join(' ')).toContain('unknown member');
  });

  it('ignores presenter-supplied predictions and refuses without an approved source', () => {
    const r = runGraphVector({
      attestation: {
        predicted_effects: [
          { effect_type: 'payment', target: 'acct:vendor-9', predicate: { op: 'lte', value: '999999.00' } },
        ],
        predicted_effects_digest: predictedEffectsDigest(PREDICTED),
        observed_effects: [{ effect_type: 'payment', target: 'acct:vendor-9', value: '26000.00' }],
      },
    });
    expect(r.verdict).toBe('conflicted');
    expect(r.reasons.join(' ')).toContain('effect_commitment_missing');
  });

  it('effect_incomparable is a registered reason code', () => {
    expect(REASON_CODES).toContain('effect_incomparable');
    expect(REASON_CODES).toContain('effect_divergence');
    expect(REASON_CODES).toContain('effect_commitment_missing');
  });
});
