// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { runCarrierActionPilot } from './scenario.mjs';

const run = runCarrierActionPilot();

test('the exact payment packet is technically complete under the named test adapters', async () => {
  const result = await run;
  assert.equal(result.positive.packet_result, 'TECHNICALLY_COMPLETE');
  assert.equal(result.positive.schedule_evaluation, 'ELIGIBLE');
  assert.equal(result.native_verifier_mode, 'synthetic_test_adapters');
  assert.equal(result.positive.authorizes_action, false);
  assert.equal(result.positive.establishes_coverage, false);
});

test('changing the payee changes the exact action and the packet is refused for it', async () => {
  const result = await run;
  assert.equal(result.payee_substitution.packet_result, 'CONFLICTED');
  assert.ok(result.payee_substitution.reasons.includes('expected_context_mismatch'));
  assert.equal(result.payee_substitution.packet_accepted_for_substituted_action, false);
});

test('a suspended qualification and an older status behind its durable head are refused', async () => {
  const result = await run;
  assert.deepEqual(result.qualification_suspended, {
    schedule_evaluation: 'NOT_ELIGIBLE',
    reason: 'qualification_status_not_eligible',
    provider_entry_permitted: false,
  });
  assert.deepEqual(result.qualification_rollback, {
    schedule_evaluation: 'NOT_ELIGIBLE',
    reason: 'qualification_status_rollback_detected',
    provider_entry_permitted: false,
  });
});

test('a digest-only provider source is not treated as a signed observation', async () => {
  const result = await run;
  assert.equal(result.digest_only_provider_source.packet_result, 'INCOMPLETE');
  assert.ok(result.digest_only_provider_source.reasons.includes(
    'provider_outcome_complete_signed_observation_required',
  ));
  assert.ok(result.digest_only_provider_source.reasons.includes('provider_outcome_quorum_not_met'));
  assert.equal(result.digest_only_provider_source.source_treated_as_verified, false);
});

test('an unclear provider result stays indeterminate, holds exposure open, and cannot be retried', async () => {
  const result = await run;
  assert.equal(result.lost_or_unclear_provider_result.packet_result, 'INDETERMINATE');
  assert.ok(result.lost_or_unclear_provider_result.reasons.includes('provider_outcome_indeterminate'));
  assert.equal(result.lost_or_unclear_provider_result.open_exposure, 'PRESERVED');
  assert.equal(result.lost_or_unclear_provider_result.retry_allowed, false);
  assert.equal(
    result.lost_or_unclear_provider_result.required_handling,
    'REFUSE_RETRY_PRESERVE_OPEN_EXPOSURE_REQUIRE_RECONCILIATION',
  );
});

test('leaving the provider console outside the mediated surface set fails the packet', async () => {
  const result = await run;
  assert.equal(result.omitted_provider_surface.packet_result, 'INCOMPLETE');
  assert.ok(result.omitted_provider_surface.reasons.includes('coverage_surface_not_verified'));
  assert.equal(result.omitted_provider_surface.complete_mediation_established, false);
});

test('a reported loss remains evidence, not an insurance or claim decision', async () => {
  const result = await run;
  assert.equal(result.loss_reported.packet_result, 'TECHNICALLY_COMPLETE');
  assert.equal(result.loss_reported.loss_artifact_verified, true);
  assert.equal(result.loss_reported.establishes_coverage, false);
  assert.equal(result.loss_reported.coverage_decision, null);
  assert.equal(result.loss_reported.claim_payment_decision, null);
  assert.match(result.claim_boundary, /No carrier or provider has adopted/);
  assert.match(result.claim_boundary, /does not establish.*coverage/i);
});
