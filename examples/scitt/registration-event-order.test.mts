// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import { assessRegistrationEventOrder } from './registration-event-order.mjs';

function entry(log_id: string, index: number, operation_id: string, record_digest: string) {
  return {
    log_id,
    index,
    operation_id,
    record_digest,
    phase: 'PENDING_BEFORE_EFFECT',
    native_verification: 'VERIFIED',
  };
}

function terminal(
  log_id: string,
  index: number,
  operation_id: string,
  record_digest: string,
  outcome = 'EFFECT_CONFIRMED',
) {
  return {
    log_id,
    index,
    operation_id,
    record_digest,
    phase: 'TERMINAL',
    outcome,
    native_verification: 'VERIFIED',
    effect_evidence_verification: 'VERIFIED',
  };
}

const firstEntry = entry('log-a', 10, 'operation-a', 'sha256:entry-a');
const firstTerminal = terminal('log-a', 11, 'operation-a', 'sha256:terminal-a');
const secondEntry = entry('log-a', 12, 'operation-b', 'sha256:entry-b');

test('same sequencer plus entry-only records proves registration order, not effect order', () => {
  assert.deepEqual(
    assessRegistrationEventOrder({
      first: { entry: firstEntry },
      second: { entry: secondEntry },
    }),
    {
      result: 'REGISTRATION_ORDER_ONLY',
      attested_effect_order_established: false,
      reason: 'no_verified_effect_terminal_before_second_pre_effect_entry',
    },
  );
});

test('same sequencer establishes attested effect order with an exact-operation terminal before the next pre-effect entry', () => {
  assert.deepEqual(
    assessRegistrationEventOrder({
      first: { entry: firstEntry, terminal: firstTerminal },
      second: { entry: secondEntry },
    }),
    {
      result: 'ATTESTED_EFFECT_ORDER_ESTABLISHED',
      attested_effect_order_established: true,
      reason: 'verified_effect_terminal_precedes_second_pre_effect_entry_in_one_sequencer',
    },
  );
});

test('a terminal for another operation cannot establish effect order', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: {
        entry: firstEntry,
        terminal: terminal('log-a', 11, 'operation-substituted', 'sha256:terminal-substituted'),
      },
      second: { entry: secondEntry },
    }).result,
    'REGISTRATION_ORDER_ONLY',
  );
});

test('an indeterminate terminal cannot establish physical effect order', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: {
        entry: firstEntry,
        terminal: terminal('log-a', 11, 'operation-a', 'sha256:terminal-indeterminate', 'INDETERMINATE'),
      },
      second: { entry: secondEntry },
    }).result,
    'REGISTRATION_ORDER_ONLY',
  );
});

test('a signed terminal without independently verified effect evidence cannot establish effect order', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: {
        entry: firstEntry,
        terminal: { ...firstTerminal, effect_evidence_verification: 'UNVERIFIABLE' },
      },
      second: { entry: secondEntry },
    }).result,
    'REGISTRATION_ORDER_ONLY',
  );
});

test('a second record that is not a verified pre-effect entry cannot establish effect order', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: { entry: firstEntry, terminal: firstTerminal },
      second: { entry: { ...secondEntry, phase: 'OBSERVED_AFTER_EFFECT' } },
    }).result,
    'REGISTRATION_ORDER_ONLY',
  );
});

test('related logs require independently verified ordering over the exact record digests', () => {
  const first = {
    entry: firstEntry,
    terminal: { ...firstTerminal, log_id: 'log-a' },
  };
  const second = { entry: { ...secondEntry, log_id: 'log-b', index: 7 } };

  assert.equal(assessRegistrationEventOrder({ first, second }).result, 'CORRESPONDENCE_ONLY');
  assert.deepEqual(
    assessRegistrationEventOrder({
      first,
      second,
      cross_log_relationship: {
        native_verification: 'VERIFIED',
        profile_id: 'example-cross-log-profile-v1',
        first_terminal_digest: 'sha256:terminal-a',
        second_entry_digest: 'sha256:entry-b',
        first_terminal_before_second_entry: true,
      },
    }),
    {
      result: 'ATTESTED_EFFECT_ORDER_ESTABLISHED',
      attested_effect_order_established: true,
      reason: 'verified_cross_log_relationship_orders_effect_terminal_before_pre_effect_entry',
    },
  );
});

test('a cross-log relationship for different records cannot establish effect order', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: { entry: firstEntry, terminal: firstTerminal },
      second: { entry: { ...secondEntry, log_id: 'log-b', index: 7 } },
      cross_log_relationship: {
        native_verification: 'VERIFIED',
        profile_id: 'example-cross-log-profile-v1',
        first_terminal_digest: 'sha256:wrong-terminal',
        second_entry_digest: 'sha256:entry-b',
        first_terminal_before_second_entry: true,
      },
    }).result,
    'CORRESPONDENCE_ONLY',
  );
});

test('a cross-log relationship cannot repair a terminal that precedes its own entry', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: {
        entry: firstEntry,
        terminal: { ...firstTerminal, index: 9 },
      },
      second: { entry: { ...secondEntry, log_id: 'log-b', index: 7 } },
      cross_log_relationship: {
        native_verification: 'VERIFIED',
        profile_id: 'example-cross-log-profile-v1',
        first_terminal_digest: 'sha256:terminal-a',
        second_entry_digest: 'sha256:entry-b',
        first_terminal_before_second_entry: true,
      },
    }).result,
    'CORRESPONDENCE_ONLY',
  );
});

test('independent logs provide correspondence only', () => {
  assert.deepEqual(
    assessRegistrationEventOrder({
      first: { entry: firstEntry, terminal: firstTerminal },
      second: { entry: { ...secondEntry, log_id: 'log-b', index: 7 } },
    }),
    {
      result: 'CORRESPONDENCE_ONLY',
      attested_effect_order_established: false,
      reason: 'independent_or_unrelated_logs',
    },
  );
});

test('two pre-effect entries do not prove completion order by themselves', () => {
  assert.equal(
    assessRegistrationEventOrder({
      first: { entry: firstEntry },
      second: { entry: secondEntry },
    }).attested_effect_order_established,
    false,
  );
});
