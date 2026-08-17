// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { CARRIER_CONTRACT, runSuite } from './run.mjs';

let cached;
function report() {
  cached ??= runSuite();
  return cached;
}

test('pins the exact Jesske AI enablement -00 source without extending the draft format', () => {
  const value = report();
  assert.equal(value.source.revision, 'draft-jesske-ai-enablement-interface-00');
  assert.equal(
    value.source.txt_sha256,
    '30c4d13d1a92a9608eed00bfc7c7cb85331c751f9d6fb92a0f33c28201709447',
  );
  assert.deepEqual(CARRIER_CONTRACT, {
    member: 'authorization_evidence',
    location: 'request metadata',
    value_semantics: 'opaque',
    interface_evidence_schema: null,
    verifier_selection: 'relying-party-pinned',
  });
  assert.equal(value.composition.jesske_depends_on_emilia, false);
});

test('one exact call.recording.start request verifies, satisfies the RP requirement, and reserves once', () => {
  const valid = report().cases.find((entry) => entry.id === 'valid_exact_recording_start');
  assert.ok(valid);
  assert.deepEqual(valid.observed, {
    native_verification: 'VERIFIED',
    acceptance: 'ACCEPTED',
    action_match: 'MATCH',
    evidence_satisfaction: 'SATISFIED',
    local_authorization: 'AUTHORIZED',
    admission: 'RESERVED',
    reason: 'reserved_for_execution',
  });
  assert.match(valid.caid, /^caid:1:call\.recording\.start\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
});

test('participant, purpose, destination, and time-window substitutions fail exact-action matching', () => {
  const ids = [
    'participant_substitution',
    'purpose_substitution',
    'destination_substitution',
    'time_window_substitution',
  ];
  for (const id of ids) {
    const hostile = report().cases.find((entry) => entry.id === id);
    assert.ok(hostile, id);
    assert.equal(hostile.observed.native_verification, 'VERIFIED', id);
    assert.equal(hostile.observed.acceptance, 'ACCEPTED', id);
    assert.equal(hostile.observed.action_match, 'MISMATCH', id);
    assert.equal(hostile.observed.evidence_satisfaction, 'UNSATISFIED', id);
    assert.equal(hostile.observed.local_authorization, 'NOT_AUTHORIZED', id);
    assert.equal(hostile.observed.admission, 'REFUSED', id);
  }
});

test('a request outside the signed action window is refused before admission', () => {
  const outside = report().cases.find((entry) => entry.id === 'outside_authorized_window');
  assert.ok(outside);
  assert.equal(outside.observed.native_verification, 'VERIFIED');
  assert.equal(outside.observed.acceptance, 'REJECTED');
  assert.equal(outside.observed.evidence_satisfaction, 'UNSATISFIED');
  assert.equal(outside.observed.admission, 'REFUSED');
  assert.match(outside.observed.reason, /outside_action_window/);
});

test('missing evidence and native-evidence replay both fail closed', () => {
  const missing = report().cases.find((entry) => entry.id === 'missing_authorization_evidence');
  assert.ok(missing);
  assert.equal(missing.observed.native_verification, 'FAILED');
  assert.equal(missing.observed.evidence_satisfaction, 'UNSATISFIED');
  assert.equal(missing.observed.admission, 'REFUSED');
  assert.match(missing.observed.reason, /authorization_evidence_missing/);

  const replay = report().cases.find((entry) => entry.id === 'native_evidence_replay');
  assert.ok(replay);
  assert.equal(replay.observed.native_verification, 'VERIFIED');
  assert.equal(replay.observed.action_match, 'MATCH');
  assert.equal(replay.observed.evidence_satisfaction, 'SATISFIED');
  assert.equal(replay.observed.local_authorization, 'AUTHORIZED');
  assert.equal(replay.observed.admission, 'REFUSED');
  assert.equal(replay.observed.reason, 'consumption_conflict');
});

test('the executable report names the limits of the bounded composition', () => {
  const value = report();
  assert.equal(value.passed, true, JSON.stringify(value, null, 2));
  assert.equal(value.summary.total, 8);
  assert.equal(value.summary.passed, 8);
  for (const limit of [
    'participant_identity_or_consent',
    'legal_permission_to_record',
    'media_capture_or_storage_effect',
    'destination_control_or_deletion',
    'global_replay_prevention',
    'independent_implementation_or_endorsement',
  ]) {
    assert.ok(value.scope_limits.includes(limit), limit);
  }
});
