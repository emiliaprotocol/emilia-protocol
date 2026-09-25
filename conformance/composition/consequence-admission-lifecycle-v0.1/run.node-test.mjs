// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { runSuite } from './run.mjs';

function byId(report, id) {
  const entry = report.cases.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing case: ${id}`);
  return entry;
}

test('all four native profiles traverse one residual consequence lifecycle without a second authorization decision', async () => {
  const report = await runSuite();
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.cases.length, 23);
  assert.equal(report.authorization_decisions_by_aeb, 0);
  assert.deepEqual(
    report.profiles.map((profile) => profile.id),
    [
      'authzen-coaz-mcp',
      'ap2-payment-mandate',
      'oauth-transaction-token',
      'local-signed-mandate',
    ],
  );
  assert.equal(
    report.profiles.find((profile) => profile.id === 'local-signed-mandate')
      .native_fixture_integrity,
    'PINNED_ED25519_SIGNATURE',
  );
  for (const entry of report.cases) {
    assert.equal(entry.native_authorization_redecided_by_aeb, false, entry.id);
  }
  for (const id of [
    'AUTHZEN-EXACT-ACTION-ADMITTED-ONCE',
    'AP2-EXACT-ACTION-ADMITTED-ONCE',
    'OAUTH-EXACT-ACTION-ADMITTED-ONCE',
    'LOCAL-SIGNED-EXACT-ACTION-ADMITTED-ONCE',
  ]) {
    const entry = byId(report, id);
    assert.equal(entry.observed.first, 'EXECUTED', id);
    assert.equal(entry.observed.second, 'REFUSED', id);
    assert.equal(entry.observed.provider_calls, 1, id);
  }
});

test('material action comparison is exact, loss-aware, and normalization-profile bounded', async () => {
  const report = await runSuite();
  const material = byId(report, 'MATERIAL-MUTATION-REQUIRES-NATIVE-REEVALUATION');
  assert.equal(material.observed.state, 'REEVALUATION_REQUIRED');
  assert.equal(material.observed.provider_calls, 0);

  const declared = byId(report, 'DECLARED-CURRENCY-NORMALIZATION-PRESERVES-ACTION');
  assert.equal(declared.observed.state, 'EXECUTED');
  assert.equal(declared.observed.provider_calls, 1);

  const undeclared = byId(report, 'UNDECLARED-CURRENCY-NORMALIZATION-IS-NOT-INFERRED');
  assert.equal(undeclared.observed.state, 'REEVALUATION_REQUIRED');
  assert.equal(undeclared.observed.provider_calls, 0);

  const omitted = byId(report, 'OMITTED-MATERIAL-FIELD-IS-INDETERMINATE');
  assert.equal(omitted.observed.state, 'INDETERMINATE');
  assert.equal(omitted.observed.reason, 'omitted_material_field');
  assert.deepEqual(omitted.observed.fields, ['payee']);

  const unknown = byId(report, 'UNKNOWN-MATERIAL-FIELD-IS-INDETERMINATE');
  assert.equal(unknown.observed.state, 'INDETERMINATE');
  assert.equal(unknown.observed.reason, 'unknown_material_field_without_mapping_rule');
  assert.deepEqual(unknown.observed.fields, ['settlement_window']);
});

test('audience, tenant, executor, provider, freshness, and revocation remain fail-closed', async () => {
  const report = await runSuite();
  const expected = {
    'WRONG-AUDIENCE-REFUSED': 'audience_binding_mismatch',
    'WRONG-TENANT-REFUSED': 'tenant_binding_mismatch',
    'WRONG-EXECUTOR-REFUSED': 'executor_binding_mismatch',
    'WRONG-PROVIDER-REFUSED': 'provider_binding_mismatch',
    'STALE-NATIVE-AUTHORITY-REFUSED': 'native_authority_stale',
    'REVOKED-NATIVE-AUTHORITY-REFUSED': 'native_authority_revoked',
    'TAMPERED-LOCAL-MANDATE-SIGNATURE-REFUSED': 'native_verifier_result_invalid',
  };
  for (const [id, reason] of Object.entries(expected)) {
    const entry = byId(report, id);
    assert.equal(entry.observed.state, 'REFUSED', id);
    assert.equal(entry.observed.reason, reason, id);
    assert.equal(entry.observed.provider_calls, 0, id);
  }
});

test('stable replay identity and atomic reservation permit at most one dispatch owner', async () => {
  const report = await runSuite();
  const wrapper = byId(report, 'REFRESHED-WRAPPER-CANNOT-REKEY-REPLAY');
  assert.equal(wrapper.observed.first, 'EXECUTED');
  assert.equal(wrapper.observed.second, 'REFUSED');
  assert.equal(wrapper.observed.replay_unit_stable, true);
  assert.equal(wrapper.observed.wrapper_changed, true);
  assert.equal(wrapper.observed.provider_calls, 1);

  const concurrent = byId(report, 'CONCURRENT-RESERVATION-HAS-ONE-DISPATCH-OWNER');
  assert.deepEqual(concurrent.observed.states, ['EXECUTED', 'REFUSED']);
  assert.equal(concurrent.observed.provider_calls, 1);
  assert.equal(concurrent.observed.dispatch_owner_count, 1);
});

test('pre-entry recovery is retryable while post-entry uncertainty is sticky', async () => {
  const report = await runSuite();
  const preEntry = byId(report, 'PRE-ENTRY-CRASH-IS-SAFELY-RETRYABLE');
  assert.equal(preEntry.observed.first, 'PRE_ENTRY_CRASHED');
  assert.equal(preEntry.observed.recovered, true);
  assert.equal(preEntry.observed.retry, 'EXECUTED');
  assert.equal(preEntry.observed.provider_calls, 1);

  const postEntry = byId(report, 'POST-ENTRY-RESPONSE-LOSS-IS-STICKY-INDETERMINATE');
  assert.equal(postEntry.observed.first, 'INDETERMINATE');
  assert.equal(postEntry.observed.retry, 'REFUSED');
  assert.equal(postEntry.observed.retry_allowed, false);
  assert.equal(postEntry.observed.provider_calls, 1);
});

test('only authenticated same-provider, same-operation, same-action evidence reconciles without redispatch', async () => {
  const report = await runSuite();
  const accepted = byId(report, 'AUTHENTICATED-RECONCILIATION-CLOSES-SAME-EFFECT');
  assert.equal(accepted.observed.first, 'INDETERMINATE');
  assert.equal(accepted.observed.final, 'EXECUTED');
  assert.equal(accepted.observed.authenticated, true);
  assert.equal(accepted.observed.provider_calls, 1);

  const mismatched = byId(report, 'MISMATCHED-RECONCILIATION-STAYS-INDETERMINATE');
  assert.deepEqual(mismatched.observed.states, [
    'INDETERMINATE',
    'INDETERMINATE',
    'INDETERMINATE',
  ]);
  assert.deepEqual(mismatched.observed.reasons, [
    'provider_binding_mismatch',
    'operation_binding_mismatch',
    'action_binding_mismatch',
  ]);
  assert.equal(mismatched.observed.final_state, 'INDETERMINATE');
  assert.equal(mismatched.observed.provider_calls, 1);
});

test('known bypass paths are disclosed rather than promoted into a complete-mediation claim', async () => {
  const report = await runSuite();
  const bypass = byId(report, 'BYPASS-PATH-IS-DISCLOSED-NOT-MEDIATED');
  assert.equal(bypass.observed.coverage, 'CONFIGURED_PATHS_ONLY');
  assert.deepEqual(bypass.observed.covered_paths, ['mcp:payments-gateway']);
  assert.deepEqual(bypass.observed.known_uncovered_paths, ['direct:provider-api-credential']);
  assert.equal(bypass.observed.complete_mediation_claimed, false);
});
