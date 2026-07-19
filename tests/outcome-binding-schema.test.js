// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { authorityInstantMs } from '../lib/authority/authority-doc.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schema = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'public/schemas/ep-outcome-binding.schema.json'),
  'utf8',
));
const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addFormat('date-time', (value) => Number.isFinite(authorityInstantMs(value)));
ajv.addSchema(schema);

const validateArtifact = ajv.getSchema(schema.$id);
const validatePredictedEffects = ajv.compile({
  $ref: `${schema.$id}#/$defs/predictedEffects`,
});
const validateObservedEffects = ajv.compile({
  $ref: `${schema.$id}#/$defs/observedEffects`,
});
const clone = (value) => JSON.parse(JSON.stringify(value));
const errors = (validate) => JSON.stringify(validate.errors, null, 2);

const DIGEST = `sha256:${'1'.repeat(64)}`;
const PREDICTED = [
  { effect_type: 'status', target: 'payment:1', predicate: { op: 'eq', value: 'settled' } },
  { effect_type: 'amount', target: 'payment:2', predicate: { op: 'lte', value: '10.00' } },
  { effect_type: 'balance', target: 'account:1', predicate: { op: 'gte', value: '-1.50' } },
  { effect_type: 'temperature', target: 'sensor:1', predicate: { op: 'range', min: '-5', max: '5.0' } },
  { effect_type: 'members', target: 'group:1', predicate: { op: 'set_eq', values: ['a', 'b'] } },
  { effect_type: 'writes', target: 'store:1', predicate: { op: 'count_lte', value: '2' } },
  { effect_type: 'deletion', target: 'record:1', predicate: { op: 'absent' } },
];
const OBSERVED = [
  { effect_type: 'status', target: 'payment:1', value: 'settled' },
  { effect_type: 'members', target: 'group:1', values: ['a', 'b'] },
];
const ATTESTATION = {
  '@version': 'EP-OUTCOME-ATTESTATION-v1',
  receipt_id: 'ep:receipt:outcome-1',
  receipt_digest: DIGEST,
  action_hash: DIGEST,
  consumption_nonce: 'nonce:1',
  execution_id: 'execution:1',
  executor_id: 'executor:1',
  executed_at: '2026-07-19T16:01:00.000Z',
  observed_effects: OBSERVED,
  observed_effects_digest: DIGEST,
  proof: {
    algorithm: 'Ed25519',
    key_id: `ep:executor-key:sha256:${'2'.repeat(64)}`,
    public_key: 'A',
    signature_b64u: 'A'.repeat(86),
  },
};
const RESULT = {
  '@version': 'EP-OUTCOME-BINDING-v1',
  outcome: 'in_bounds',
  evaluations: [{
    source: 'signed_receipt',
    outcome: 'in_bounds',
    results: [{
      effect_type: 'status',
      target: 'payment:1',
      op: 'eq',
      outcome: 'in_bounds',
      reason: null,
    }],
    reasons: [],
  }],
  reasons: [],
};

describe('public EP Outcome Binding schema', () => {
  it('validates the closed attestation, every predicted predicate shape, observed effects, and typed result', () => {
    expect(validateArtifact(ATTESTATION), errors(validateArtifact)).toBe(true);
    expect(validatePredictedEffects(PREDICTED), errors(validatePredictedEffects)).toBe(true);
    expect(validateObservedEffects(OBSERVED), errors(validateObservedEffects)).toBe(true);
    expect(validateArtifact(RESULT), errors(validateArtifact)).toBe(true);
  });

  it('refuses wildcard targets, non-string numeric operands, ambiguous observations, and unknown members', () => {
    const wildcardPrediction = clone(PREDICTED);
    wildcardPrediction[0].target = 'payment:*';
    expect(validatePredictedEffects(wildcardPrediction)).toBe(false);

    const numericPrediction = clone(PREDICTED);
    numericPrediction[1].predicate.value = 10;
    expect(validatePredictedEffects(numericPrediction)).toBe(false);

    const exponentPrediction = clone(PREDICTED);
    exponentPrediction[1].predicate.value = '1e3';
    expect(validatePredictedEffects(exponentPrediction)).toBe(false);

    const unknownPredicateMember = clone(PREDICTED);
    unknownPredicateMember[1].predicate.tolerance = '1.00';
    expect(validatePredictedEffects(unknownPredicateMember)).toBe(false);

    const ambiguousObservation = clone(OBSERVED);
    ambiguousObservation[0].values = ['settled'];
    expect(validateObservedEffects(ambiguousObservation)).toBe(false);

    const wildcardObservation = clone(OBSERVED);
    wildcardObservation[0].target = 'payment:*';
    expect(validateObservedEffects(wildcardObservation)).toBe(false);

    const unknownObservationMember = clone(OBSERVED);
    unknownObservationMember[0].metadata = {};
    expect(validateObservedEffects(unknownObservationMember)).toBe(false);
  });

  it('enforces the runtime resource ceilings exactly', () => {
    const tooManyPredictions = Array.from({ length: 65 }, (_, index) => ({
      effect_type: 'payment',
      target: `payment:${index}`,
      predicate: { op: 'absent' },
    }));
    expect(validatePredictedEffects(tooManyPredictions)).toBe(false);

    const tooManyObservations = Array.from({ length: 257 }, (_, index) => ({
      effect_type: 'payment',
      target: `payment:${index}`,
      value: '1.00',
    }));
    expect(validateObservedEffects(tooManyObservations)).toBe(false);

    const oversizedValue = clone(OBSERVED);
    oversizedValue[0].value = 'x'.repeat(513);
    expect(validateObservedEffects(oversizedValue)).toBe(false);

    const oversizedSet = clone(PREDICTED);
    oversizedSet[4].predicate.values = Array.from({ length: 257 }, () => 'x');
    expect(validatePredictedEffects(oversizedSet)).toBe(false);

    const tooManyEvaluations = clone(RESULT);
    tooManyEvaluations.evaluations = Array.from({ length: 3 }, () => RESULT.evaluations[0]);
    expect(validateArtifact(tooManyEvaluations)).toBe(false);
  });

  it('keeps attestation and result members exact and the result explicitly typed', () => {
    const hostileAttestation = clone(ATTESTATION);
    hostileAttestation.predicted_effects = PREDICTED;
    expect(validateArtifact(hostileAttestation)).toBe(false);

    const hostileResult = clone(RESULT);
    hostileResult.authorized = true;
    expect(validateArtifact(hostileResult)).toBe(false);

    const untypedResult = clone(RESULT);
    delete untypedResult['@version'];
    expect(validateArtifact(untypedResult)).toBe(false);

    const unknownEffectResultMember = clone(RESULT);
    unknownEffectResultMember.evaluations[0].results[0].evidence = 'unsigned';
    expect(validateArtifact(unknownEffectResultMember)).toBe(false);
  });
});
