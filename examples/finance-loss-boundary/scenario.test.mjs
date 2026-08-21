// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { runFinanceLossBoundaryScenario } from './scenario.mjs';

test('finance boundary refuses substitution and preserves post-entry truth', async () => {
  const report = await runFinanceLossBoundaryScenario();

  assert.equal(report['@version'], 'EP-FINANCE-LOSS-BOUNDARY-v1');
  assert.equal(report.network_requests, 0);
  assert.equal(report.money_moved, false);
  assert.equal(report.protection_plan.activation, 'not_active');

  assert.deepEqual(report.vendor_change.injected_email, {
    admitted: false,
    reason: 'field_origin_control_untrusted:/new_account_digest',
    effects: 0,
  });
  assert.deepEqual(report.vendor_change.bounded_memo, {
    admitted: true,
    reason: null,
    effects: 1,
  });

  assert.equal(report.payout.allowed.admitted, true);
  assert.equal(report.payout.allowed.provider_calls, 1);
  assert.equal(report.payout.replay.admitted, false);
  assert.equal(report.payout.replay.reason, 'operation_already_committed');
  assert.equal(report.payout.replay.provider_calls, 1);
  assert.equal(report.payout.frozen.admitted, false);
  assert.equal(report.payout.frozen.reason, 'capability_control_domain_frozen');
  assert.equal(report.payout.frozen.provider_calls, 1);

  assert.equal(report.outcomes.diverged.provider_outcome.value, 'COMMITTED');
  assert.equal(report.outcomes.diverged.effect_relation.value, 'DIVERGED');
  assert.notEqual(
    report.outcomes.diverged.provider_outcome.evidence_digest,
    report.outcomes.diverged.effect_relation.evidence_digest,
  );
  assert.equal(report.outcomes.unknown.state, 'INDETERMINATE');
  assert.equal(report.outcomes.unknown.execution_right, 'CONSUMED');
  assert.equal(report.outcomes.unknown.blind_retry, 'state_conflict');

  const reference = JSON.parse(await readFile(
    new URL('./report.reference.json', import.meta.url),
    'utf8',
  ));
  assert.deepEqual(report, reference);
});
