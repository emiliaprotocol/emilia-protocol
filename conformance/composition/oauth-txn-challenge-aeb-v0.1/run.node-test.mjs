// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  EXACT_NONCLAIMS,
  NATIVE_FIXTURE,
  PROFILE,
  REPORT_VERSION,
  SOURCE_LOCK,
  buildCompilerFixture,
  runSuite,
  verifySourceLock,
} from './run.mjs';

function profileCase(report, id) {
  const entry = report.cases.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing profile case: ${id}`);
  return entry;
}

test('the offline source lock names the exact reviewed Internet-Draft bytes', () => {
  assert.deepEqual(SOURCE_LOCK.upstream, {
    id: 'draft-rosomakho-oauth-txn-challenge-00',
    url: 'https://www.ietf.org/archive/id/draft-rosomakho-oauth-txn-challenge-00.txt',
    bytes: 70435,
    sha256: 'a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead',
  });
  assert.equal(SOURCE_LOCK['@version'], 'OAUTH-TXN-CHALLENGE-AEB-SOURCE-LOCK-v0.2');
  assert.equal(Object.keys(SOURCE_LOCK.local_implementation).length, 10);
  assert.deepEqual(verifySourceLock(), { valid: true, failures: [] });
});

test('native JWT bytes and verifier keys are static checked-in fixtures', () => {
  for (const field of [
    'protected_resource_public_spki',
    'authorization_server_public_spki',
    'challenge_jwt',
    'access_token_jwt',
    'twin_access_token_jwt',
  ]) {
    const actual = crypto.createHash('sha256').update(NATIVE_FIXTURE[field], 'utf8').digest('hex');
    assert.equal(actual, NATIVE_FIXTURE.sha256[field], field);
  }
  assert.notEqual(NATIVE_FIXTURE.access_token_jwt, NATIVE_FIXTURE.twin_access_token_jwt);
});

test('the exact challenge and access token compile and admit through the consequence kernel', async () => {
  const exact = profileCase(await runSuite(), 'exact_transaction_admits');
  assert.deepEqual(exact.observed.compiler_axes, {
    verified: 'VERIFIED',
    accepted: 'ACCEPTED',
    match: 'MATCH',
    satisfied: 'SATISFIED',
    local_authorization: 'NOT_EVALUATED',
  });
  assert.equal(exact.observed.consequence.decision, 'ADMIT');
  assert.equal(exact.observed.consequence.reservation, 'RESERVED');
});

test('material changes, transaction substitution, and a bare challenge fail closed', async () => {
  const report = await runSuite();
  for (const id of [
    'material_details_change_refuses',
    'transaction_mismatch_refuses',
    'challenge_alone_refuses',
  ]) {
    const entry = profileCase(report, id);
    assert.notEqual(entry.observed.compiler_axes.satisfied, 'SATISFIED', id);
    assert.equal(entry.observed.provider_entry, 'REFUSED_BEFORE_ENTRY', id);
  }
});

test('two access tokens for one transaction race through one local store and exactly one reserves', async () => {
  const twin = profileCase(await runSuite(), 'twin_token_concurrent_admission_one_reservation');
  assert.equal(twin.observed.same_native_replay_unit, true);
  assert.deepEqual(twin.observed.promise_race, {
    arrivals: 2,
    admission_states: ['AUTHORIZED', 'REFUSED'],
    admission_reasons: ['consumption_conflict', 'reserved_for_execution'],
    reservation_states: ['AVAILABLE', 'RESERVED'],
  });
});

test('timeout remains indeterminate, blind retry stays closed, and mismatched reconciliation does not settle it', async () => {
  const report = await runSuite();
  const timeout = profileCase(report, 'timeout_after_dispatch_indeterminate').observed.consequence;
  assert.equal(timeout.decision, 'INDETERMINATE');
  assert.equal(timeout.provider_outcome, 'INDETERMINATE');
  assert.equal(timeout.effect_relation, 'INDETERMINATE');
  assert.equal(timeout.retry, 'REFUSED');
  assert.equal(timeout.reconciliation, 'REQUIRED');

  const retry = profileCase(report, 'blind_retry_refused').observed.consequence;
  assert.equal(retry.decision, 'REFUSE');
  assert.ok(retry.reasons.includes('blind_retry_refused'));

  const mismatch = profileCase(report, 'reconciliation_mismatch_refused').observed.consequence;
  assert.equal(mismatch.decision, 'REFUSE');
  assert.equal(mismatch.provider_outcome, 'INDETERMINATE');
  assert.equal(mismatch.reconciliation, 'REFUSED');
  assert.ok(mismatch.reasons.includes('reconciliation_binding_mismatch'));
});

test('native replay identity is stable across AEB wrapper references', () => {
  const first = buildCompilerFixture({ artifact_ref: 'urn:emilia:wrapper:first' }).compiler;
  const second = buildCompilerFixture({ artifact_ref: 'urn:emilia:wrapper:second' }).compiler;
  assert.equal(first.legs[0].replay_unit, second.legs[0].replay_unit);
  assert.equal(first.replay_unit, second.replay_unit);
});

test('the report is deterministic and carries the exact nonclaims', async () => {
  const first = await runSuite();
  const second = await runSuite();
  assert.deepEqual(first, second);
  assert.equal(first['@version'], REPORT_VERSION);
  assert.equal(first.profile, PROFILE);
  assert.deepEqual(EXACT_NONCLAIMS, [
    'challenge_is_not_authorization',
    'pending_transaction_authorization_id_is_not_authorization',
    'access_token_does_not_prove_named_human_identity',
    'profile_does_not_reperform_authorization_server_policy_or_consent_correctness',
    'sender_constrained_token_or_channel_binding_is_not_established',
    'nonreusable_transaction_rule_is_application_profile_not_oauth_requirement',
    'compiler_report_is_not_authorization_or_credential',
    'native_verification_does_not_prove_provider_entry_execution_or_outcome',
    'local_atomicity_does_not_prove_remote_or_downstream_exactly_once',
    'single_process_promise_race_does_not_establish_distributed_store_concurrency',
    'profile_is_signed_jwt_with_inline_exact_rar_not_the_full_base_draft',
    'indeterminate_does_not_prove_provider_success_or_failure',
    'test_harness_is_not_independent_implementation_or_production_mediation',
    'internet_draft_is_not_ietf_adoption_or_endorsement',
  ]);
  assert.deepEqual(first.claim_scope.exclusions, EXACT_NONCLAIMS);
  assert.deepEqual(first.summary, { total: 9, passed: 9, failed: 0 });
  assert.ok(first.cases.every((entry) => entry.passed));
});
