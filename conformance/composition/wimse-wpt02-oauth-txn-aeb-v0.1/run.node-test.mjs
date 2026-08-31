// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EXACT_NONCLAIMS,
  PROFILE,
  REPORT_VERSION,
  SOURCE_LOCK,
  runSuite,
  verifySourceLock,
} from './run.mjs';

function profileCase(report, id) {
  const entry = report.cases.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing profile case: ${id}`);
  return entry;
}

test('the offline lock pins every interpreted draft, the executed local closure, and compatibility surfaces', () => {
  assert.deepEqual(
    SOURCE_LOCK.upstream.map((entry) => entry.id),
    [
      'draft-ietf-wimse-wpt-02',
      'draft-ietf-wimse-http-signature-06',
      'draft-ietf-wimse-workload-creds-02',
      'draft-ietf-oauth-transaction-tokens-11',
      'draft-coetzee-oauth-spt-txn-tokens-03',
      'draft-rosomakho-oauth-txn-challenge-00',
    ],
  );
  assert.deepEqual(
    SOURCE_LOCK.local_runtime_closure,
    [
      'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.mjs',
      'packages/verify/aeb-wimse-oauth-adapter.js',
      'packages/verify/dist/aeb-wimse-oauth-adapter.js',
      'packages/verify/dist/strict-json.js',
      'packages/verify/vendor/caid.mjs',
    ],
  );
  assert.deepEqual(
    SOURCE_LOCK.local_compatibility_surfaces,
    [
      'packages/verify/aeb-adapter-contract.js',
      'packages/verify/dist/aeb-adapter-contract.js',
    ],
  );
  assert.deepEqual(
    SOURCE_LOCK.local_artifacts.map((entry) => entry.path),
    [
      'packages/verify/src/aeb-wimse-oauth-adapter.ts',
      'packages/verify/aeb-wimse-oauth-adapter.js',
      'packages/verify/dist/aeb-wimse-oauth-adapter.js',
      'packages/verify/aeb-adapter-contract.js',
      'packages/verify/dist/aeb-adapter-contract.js',
      'packages/verify/dist/strict-json.js',
      'packages/verify/vendor/caid.mjs',
      'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/run.mjs',
      'conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/vectors.json',
      'conformance/composition/oauth-txn-challenge-aeb-v0.1/native-fixture.json',
    ],
  );
  assert.deepEqual(verifySourceLock(), { valid: true, failures: [] });
});

test('the candidate wrapper binds exact Txn-Token, challenge, and access-token bytes without claiming native OAuth presentation', () => {
  const entry = profileCase(
    runSuite(),
    'candidate_wrapper_bytes_bound_not_native_oauth_presentation',
  );
  assert.equal(entry.observed.token_binding.verification, 'VERIFIED');
  assert.equal(entry.observed.token_binding.transaction_token, 'PRESENT');
  assert.deepEqual(entry.observed.token_binding.other_token_headers, [
    'oauth-transaction-access-token',
    'oauth-transaction-challenge',
  ]);
  assert.equal(entry.observed.native.verification, 'VERIFIED');
  assert.equal(entry.observed.native.evidence_role, 'delegated-workload');
  assert.equal(
    entry.observed.native_oauth_transaction_challenge_presentation,
    'NOT_COMPLIANT_CUSTOM_HEADER_CANDIDATE_ONLY',
  );
  assert.equal(entry.observed.wpt_authorization, 'NOT_EVALUATED');
});

test('the exact drafts refuse direct same-request composition because their Authorization schemes collide', () => {
  const entry = profileCase(runSuite(), 'direct_http_authorization_scheme_collision');
  assert.equal(entry.passed, true);
  assert.equal(entry.observed.one_authorization_field, true);
  assert.equal(
    entry.observed.direct_same_request_composition,
    'REFUSED_AUTHORIZATION_SCHEME_COLLISION',
  );
  assert.equal(
    entry.observed.candidate_other_header_status,
    'NONSTANDARD_AND_NOT_NATIVE_OAUTH_PRESENTATION',
  );
});

test('missing or mismatched tth fails whenever Txn-Token is present', () => {
  const report = runSuite();
  for (const id of ['missing_tth_with_txn_refused', 'mismatched_tth_refused']) {
    const entry = profileCase(report, id);
    assert.equal(entry.observed.token_binding.verification, 'FAILED', id);
    assert.equal(entry.observed.token_binding.reason, 'tth_missing_or_mismatch', id);
    assert.equal(entry.observed.native.verification, 'FAILED', id);
    assert.equal(entry.observed.native.acceptance, 'REJECTED', id);
  }
});

test('oth refuses missing, mismatched, substituted, and unknown token entries', () => {
  const report = runSuite();
  for (const id of [
    'missing_oth_entry_refused',
    'mismatched_oth_hash_refused',
    'oauth_access_token_substitution_refused',
    'unknown_oth_entry_refused',
  ]) {
    const entry = profileCase(report, id);
    assert.equal(entry.observed.token_binding.verification, 'FAILED', id);
    assert.equal(entry.observed.native.verification, 'FAILED', id);
    assert.equal(entry.observed.native.acceptance, 'REJECTED', id);
  }
});

test('oth member order is irrelevant, but the exact normalized set is not', () => {
  const entry = profileCase(runSuite(), 'oth_json_member_order_is_not_semantic');
  assert.equal(entry.observed.token_binding.verification, 'VERIFIED');
  assert.equal(entry.observed.native.verification, 'VERIFIED');
  assert.equal(entry.observed.mapping, 'MATCH');
});

test('fully re-signed target authority and path substitutions fail native audience binding', () => {
  const report = runSuite();
  for (const id of [
    'target_authority_substitution_refused',
    'target_path_substitution_refused',
  ]) {
    const entry = profileCase(report, id);
    assert.equal(entry.observed.token_binding.verification, 'VERIFIED', id);
    assert.equal(entry.observed.native.verification, 'FAILED', id);
    assert.equal(entry.observed.native.acceptance, 'REJECTED', id);
    assert.deepEqual(
      entry.observed.native.reasons,
      ['wimse-oauth-spt:request_target_audience_mismatch'],
      id,
    );
  }
});

test('a noncanonical absolute target is refused before origin-form projection', () => {
  const entry = profileCase(runSuite(), 'noncanonical_target_uri_refused');
  assert.equal(entry.observed.token_binding.verification, 'VERIFIED');
  assert.equal(entry.observed.native.verification, 'FAILED');
  assert.deepEqual(entry.observed.native.reasons, ['wimse-oauth-spt:request_malformed']);
});

test('the -06 request subset refuses response-signature negotiation it cannot enforce', () => {
  const entry = profileCase(runSuite(), 'response_signature_negotiation_refused');
  assert.equal(entry.observed.token_binding.verification, 'VERIFIED');
  assert.equal(entry.observed.native.verification, 'FAILED');
  assert.equal(entry.observed.native.acceptance, 'REJECTED');
  assert.deepEqual(
    entry.observed.native.reasons,
    ['wimse-oauth-spt:http_signature_invalid_or_incomplete'],
  );
});

test('a signed Txn-Token rctx twin is refused before the closed action mapping', () => {
  const entry = profileCase(runSuite(), 'txn_rctx_present_refused_before_mapping');
  assert.equal(entry.observed.token_binding.verification, 'VERIFIED');
  assert.equal(entry.observed.native.verification, 'FAILED');
  assert.equal(entry.observed.native.acceptance, 'REJECTED');
  assert.deepEqual(
    entry.observed.native.reasons,
    ['wimse-oauth-spt:oauth_txn_rctx_unsupported'],
  );
});

test('case-folded duplicate object headers fail without claiming raw-wire cardinality', () => {
  const entry = profileCase(runSuite(), 'case_variant_duplicate_header_refused');
  assert.equal(entry.observed.token_binding.verification, 'FAILED');
  assert.equal(entry.observed.token_binding.reason, 'binding_input_malformed');
  assert.equal(entry.observed.native.verification, 'FAILED');
  assert.deepEqual(entry.observed.native.reasons, ['wimse-oauth-spt:request_malformed']);
});

test('tth is absent when Txn-Token is absent, and an orphan tth fails closed', () => {
  const report = runSuite();
  const absent = profileCase(report, 'no_txn_token_requires_no_tth');
  assert.equal(absent.observed.token_binding.verification, 'VERIFIED');
  assert.equal(absent.observed.token_binding.transaction_token, 'ABSENT');
  const orphan = profileCase(report, 'orphan_tth_without_txn_refused');
  assert.equal(orphan.observed.token_binding.verification, 'FAILED');
  assert.equal(orphan.observed.token_binding.reason, 'unexpected_tth_without_txn_token');
});

test('a source revision migration cannot open a second spend for the same Trust-Domain txn', () => {
  const entry = profileCase(runSuite(), 'draft_revision_migration_does_not_rekey_spend');
  assert.equal(entry.observed.current.replay_unit, entry.observed.next_review.replay_unit);
  assert.deepEqual(entry.observed.identity_fields, ['aud_trust_domain', 'txn']);
  assert.deepEqual(entry.observed.excluded_identity_fields, ['draft_revision', 'iss']);
  assert.equal(entry.observed.first_reservation, true);
  assert.equal(entry.observed.second_reservation, false);
  assert.equal(entry.observed.second_decision, 'NATIVE_EVIDENCE_REPLAY');
});

test('the report refuses any claim of broad Txn-Tokens-11 or WIMSE-06 conformance', () => {
  const report = runSuite();
  assert.ok(report.claim_scope.exclusions.includes(
    'strict_application_subset_not_general_txn_tokens_11_or_wimse_06_conformance',
  ));
  assert.match(report.semantics.application_subset, /strict EMILIA request subset/);
  assert.match(report.semantics.rctx, /refused when present/);
  assert.match(report.semantics.header_observation, /not proof of raw-wire singleton cardinality/);
  assert.match(report.semantics.replay_enforcement, /emits a stable replay identity only/);
});

test('the report is deterministic and keeps every nonclaim visible', () => {
  const first = runSuite();
  const second = runSuite();
  assert.deepEqual(first, second);
  assert.equal(first['@version'], REPORT_VERSION);
  assert.equal(first.profile, PROFILE);
  assert.deepEqual(first.summary, { total: 18, passed: 18, failed: 0 });
  assert.ok(first.cases.every((entry) => entry.passed));
  assert.deepEqual(first.claim_scope.exclusions, [...EXACT_NONCLAIMS]);
  assert.match(first.report_digest, /^sha256:[0-9a-f]{64}$/);
});
