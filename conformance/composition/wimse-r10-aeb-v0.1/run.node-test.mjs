// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  PROFILE,
  evaluateMatrix,
  runSuite,
  verifySourceLock,
} from './run.mjs';

const report = runSuite();

function result(id) {
  const found = report.cases.find((entry) => entry.id === id);
  assert.ok(found, `missing result: ${id}`);
  return found.observed;
}

function matrixRow(id) {
  const found = report.matrix.rows.find((entry) => entry.id === id);
  assert.ok(found, `missing matrix row: ${id}`);
  return found;
}

test('source lock, five matrix rows, and all eleven cases pass', () => {
  assert.equal(report.profile, PROFILE);
  assert.deepEqual(report.summary, {
    matrix_rows: 5,
    matrix_rows_passed: 5,
    total: 11,
    passed: 11,
    failed: 0,
  });
  assert.equal(verifySourceLock().valid, true);
  assert.equal(evaluateMatrix().summary.failed, 0);
  assert.equal(report.implementation.independent_implementation, false);
  assert.equal(report.implementation.production_mediation, false);
});

test('native rows keep unsupported and external-profile results visible', () => {
  const asor = matrixRow('ASOR-ADC-00');
  assert.equal(
    asor.criteria.execution_time_required_evidence.actual,
    'NOT_MET',
  );
  assert.equal(
    asor.criteria.monotonic_non_droppable_carriage.actual,
    'EXTERNAL_PROFILE_REQUIRED',
  );
  assert.equal(
    asor.criteria.monotonic_non_droppable_carriage.signal,
    'registered_constraint_definition_required',
  );

  const hamr = matrixRow('HAMR-ADP-00');
  assert.equal(
    hamr.criteria.execution_time_required_evidence.actual,
    'NOT_SUPPORTED',
  );
  assert.equal(
    hamr.criteria.monotonic_non_droppable_carriage.actual,
    'NOT_SUPPORTED',
  );

  const envelope = matrixRow('AGENTENVELOPE-01');
  assert.equal(
    envelope.criteria.execution_time_required_evidence.actual,
    'PARTIAL',
  );
  assert.equal(
    envelope.criteria.at_most_once_local_admission.actual,
    'EXTERNAL_PROFILE_REQUIRED',
  );

  const currentAdapter = matrixRow('EMILIA-WIMSE-ADAPTER-CURRENT');
  assert.equal(
    currentAdapter.criteria.execution_time_required_evidence.actual,
    'NOT_MET',
  );
  assert.equal(
    currentAdapter.criteria.consume_only_on_admission.actual,
    'EXTERNAL_PROFILE_REQUIRED',
  );
});

test('only the candidate host carrier plus AEB reaches every criterion', () => {
  const candidate = matrixRow('EMILIA-AEB-HOST-CARRIER-CANDIDATE');
  assert.equal(candidate.summary.total, 10);
  assert.equal(candidate.summary.passed, 10);
  assert.equal(candidate.summary.failed, 0);
  for (const criterion of Object.values(candidate.criteria)) {
    assert.equal(criterion.actual, 'MET');
  }
});

test('positive carrier lifecycle admits once and records one modeled provider effect', () => {
  const positive = result('positive_host_carrier_lifecycle');
  assert.equal(positive.preflight, 'PASS');
  assert.equal(positive.admission_decision, 'ADMIT');
  assert.equal(positive.reservation, 'CONSUMED');
  assert.equal(positive.consumed_on_admission, true);
  assert.equal(positive.provider_entry, 'ENTERED_ONCE');
  assert.equal(positive.modeled_provider_entries_total, 1);
  assert.equal(positive.custody, 'TERMINAL');
  assert.equal(positive.provider_outcome, 'COMMITTED');
  assert.equal(positive.effect_relation, 'OBSERVED_AS_REQUESTED');
  assert.equal(positive.aeb_decision, 'RECORDED');
});

test('stripping, downgrade, and unknown profile all fail closed before admission', () => {
  const stripped = result('stripped_required_evidence_refused');
  assert.equal(stripped.preflight, 'REFUSE_REQUIRED_EVIDENCE_STRIPPED');
  assert.equal(stripped.reservation, 'NOT_ATTEMPTED');
  assert.equal(stripped.consumed_on_admission, false);

  const downgraded = result('downgraded_required_evidence_refused');
  assert.equal(downgraded.preflight, 'REFUSE_REQUIRED_EVIDENCE_DOWNGRADE');
  assert.equal(downgraded.modeled_provider_entries_total, 0);

  const unknown = result('unknown_required_evidence_profile_refused');
  assert.equal(unknown.preflight, 'REFUSE_UNKNOWN_REQUIRED_EVIDENCE_PROFILE');
  assert.equal(unknown.provider_entry, 'REFUSED_BEFORE_ENTRY');
});

test('target and acting-for substitutions fail before AEB admission', () => {
  const target = result('changed_target_refused');
  assert.equal(target.preflight, 'REFUSE_EXACT_ACTION_BINDING_MISMATCH');
  assert.deepEqual(target.reasons, ['exact_action_binding_mismatch']);
  assert.equal(target.modeled_provider_entries_total, 0);

  const principal = result('changed_acting_for_principal_refused');
  assert.equal(principal.preflight, 'REFUSE_ACTING_FOR_PRINCIPAL_MISMATCH');
  assert.deepEqual(principal.reasons, ['acting_for_principal_mismatch']);
  assert.equal(principal.modeled_provider_entries_total, 0);
});

test('replay and both refusal paths do not consume a new reliance unit', () => {
  const replay = result('native_evidence_replay_refused');
  assert.equal(replay.reservation, 'NATIVE_EVIDENCE_REPLAY');
  assert.equal(replay.consumed_on_admission, false);
  assert.equal(replay.modeled_provider_entries_total, 0);

  const verification = result('native_verification_refusal_does_not_consume');
  assert.equal(verification.reservation, 'NOT_ATTEMPTED');
  assert.equal(verification.consumed_on_admission, false);
  assert.deepEqual(verification.reasons, ['native_verification_failed']);

  const policy = result('local_policy_refusal_does_not_consume');
  assert.equal(policy.reservation, 'NOT_ATTEMPTED');
  assert.equal(policy.consumed_on_admission, false);
  assert.deepEqual(policy.reasons, ['local_policy_denied']);
});

test('timeout remains indeterminate and blind retry does not model a second provider entry', () => {
  const timeout = result('timeout_after_dispatch_is_indeterminate');
  assert.equal(timeout.admission_decision, 'ADMIT');
  assert.equal(timeout.provider_entry, 'ENTERED_ONCE_OUTCOME_UNKNOWN');
  assert.equal(timeout.modeled_provider_entries_total, 1);
  assert.equal(timeout.custody, 'INVOKING');
  assert.equal(timeout.provider_outcome, 'INDETERMINATE');
  assert.equal(timeout.effect_relation, 'INDETERMINATE');
  assert.equal(timeout.retry, 'REFUSED');
  assert.equal(timeout.reconciliation, 'REQUIRED');
  assert.equal(timeout.aeb_decision, 'INDETERMINATE');

  const retry = result('blind_retry_while_unresolved_refused');
  assert.equal(retry.admission_decision, 'ADMIT');
  assert.equal(retry.provider_entry, 'REENTRY_REFUSED');
  assert.equal(retry.modeled_provider_entries_total, 1);
  assert.equal(retry.reservation, 'OPERATION_REPLAY');
  assert.equal(retry.aeb_decision, 'REFUSE');
  assert.deepEqual(retry.reasons, ['blind_retry_refused']);
});

test('deterministic report matches reference and preserves all nonclaims', () => {
  const reference = JSON.parse(
    readFileSync(new URL('./report.reference.json', import.meta.url), 'utf8'),
  );
  assert.deepEqual(report, reference);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
  for (const exclusion of [
    'wimse_adoption',
    'reece_endorsement',
    'freedom_to_operate',
    'independent_implementation',
    'production_mediation',
  ]) {
    assert.ok(report.claim_scope.exclusions.includes(exclusion), exclusion);
  }
});
