// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifyGateAttemptPair } from './verify.mjs';

const VECTOR_PATH = fileURLToPath(new URL('./gate-attempt-pair.v1.json', import.meta.url));
const vector = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));
const clone = () => structuredClone(vector);

test('the EMILIA Gate attempt pair verifies', () => {
  assert.deepEqual(verifyGateAttemptPair(vector), {
    valid: true,
    exchange_id: 'urn:emilia:interop:aae-psea-gate:exchange:001',
    attempts: 2,
    second_admission: 'NONE',
    second_reason: 'already_consumed',
  });
});

test('a non-NONE outcome without a qualifying admission is refused', () => {
  const mutated = clone();
  mutated.attempts[0].rows.admission.value = 'RESERVED';
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /non-NONE outcome requires a qualifying same-or-prior admission/,
  );
});

test('an indeterminate outcome without a reason is refused', () => {
  const mutated = clone();
  delete mutated.attempts[0].rows.outcome.reason;
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /INDETERMINATE requires a reason/,
  );
});

test('already-consumed replay cannot rewrite the decision as REFUSED', () => {
  const mutated = clone();
  mutated.attempts[1].rows.decision.value = 'REFUSED';
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /already-consumed replay must preserve AUTHORIZED decision/,
  );
});

test('already-consumed replay cannot admit the action a second time', () => {
  const mutated = clone();
  mutated.attempts[1].rows.admission = { value: 'CONSUMED' };
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /already-consumed replay must withhold admission as NONE\/already_consumed/,
  );
});

test('already-consumed replay must name the prior consumed admission', () => {
  const mutated = clone();
  mutated.attempts[1].gate_custody.prior_admission = 'INVOKED';
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /must reference prior CONSUMED admission/,
  );
});

test('the pair cannot change evidence or linkage between attempts', () => {
  const mutated = clone();
  mutated.attempts[1].rows.evidence_satisfaction.value = 'UNSATISFIED';
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /attempt pair must preserve reservation, native result, linkage, evidence, and decision/,
  );
});

test('the fixture cannot promote the proposed WHO axis to confirmed', () => {
  const mutated = clone();
  mutated.source_fixture.who_axis_status = 'CONFIRMED';
  assert.throws(
    () => verifyGateAttemptPair(mutated),
    /WHO axis must remain PROPOSED/,
  );
});
