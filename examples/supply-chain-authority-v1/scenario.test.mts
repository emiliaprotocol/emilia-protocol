// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import { runSupplyChainAuthorityDemo } from './scenario.mjs';

test('an exact machine action is admitted once, then the same operation cannot re-enter', async () => {
  const result = await runSupplyChainAuthorityDemo();

  assert.equal(result.exact_action.provider_entered, true);
  assert.equal(result.exact_action.outcome, 'executed');
  assert.equal(result.retry.provider_entered, false);
  assert.equal(result.retry.reason, 'operation_already_committed');
  assert.equal(result.provider_entry_count, 1);
});

test('material command substitution is refused before provider entry', async () => {
  const result = await runSupplyChainAuthorityDemo();

  assert.equal(result.substitution.refused, true);
  assert.equal(result.substitution.provider_entered, false);
  assert.notEqual(result.substitution.presented_action_digest, result.substitution.authorized_action_digest);
});

test('an emergency freeze releases a reserved action as not entered and restore cannot revive it', async () => {
  const result = await runSupplyChainAuthorityDemo();

  assert.equal(result.freeze.status, 'frozen');
  assert.equal(result.freeze.pending_action_outcome, 'not_entered');
  assert.equal(result.freeze.reservation, 'released');
  assert.equal(result.freeze.restored_epoch, 3);
  assert.equal(result.freeze.old_reservation_reentered, false);
  assert.equal(result.provider_entry_count, 1);
});

test('the report keeps the demonstration boundary explicit', async () => {
  const result = await runSupplyChainAuthorityDemo();

  assert.match(result.claim_boundary, /synthetic/i);
  assert.match(result.claim_boundary, /in-memory/i);
  assert.match(result.claim_boundary, /not.*live robot/i);
  assert.match(result.claim_boundary, /not.*production/i);
});
