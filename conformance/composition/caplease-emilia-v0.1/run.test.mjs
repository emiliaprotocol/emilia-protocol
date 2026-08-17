// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { runComparison } from './run.mjs';

function byId(report, id) {
  const check = report.checks.find((entry) => entry.id === id);
  assert.ok(check, `missing comparison check ${id}`);
  return check;
}

test('the source lock pins CapLease v1 artifacts and the exercised EMILIA runtime bytes', () => {
  const sourceLock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));

  assert.equal(sourceLock['@version'], 'CAPLEASE-EMILIA-SOURCE-LOCK-v0.1');
  assert.equal(sourceLock.caplease.arxiv_id, '2608.01710');
  assert.equal(sourceLock.caplease.version, 'v1');
  assert.match(sourceLock.caplease.pdf.sha256, /^[0-9a-f]{64}$/);
  assert.match(sourceLock.caplease.tex_source.archive_sha256, /^[0-9a-f]{64}$/);
  assert.match(sourceLock.caplease.tex_source.main_tex_sha256, /^[0-9a-f]{64}$/);
  assert.equal(sourceLock.caplease.official_repository, null);

  for (const file of sourceLock.emilia.runtime_files) {
    const bytes = readFileSync(new URL(`../../../${file.path}`, import.meta.url));
    const actual = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(actual, file.sha256, file.path);
  }
});

test('the report is source-pinned and does not claim an official CapLease implementation', async () => {
  const report = await runComparison();

  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.profile, 'CAPLEASE-EMILIA-COMPARISON-v0.1');
  assert.equal(report.source_basis.caplease.arxiv_id, '2608.01710');
  assert.equal(report.source_basis.caplease.version, 'v1');
  assert.equal(report.source_basis.caplease.implementation_kind, 'paper-derived-executable-model');
  assert.equal(report.source_basis.caplease.official_repository, null);
  assert.match(report.source_basis.caplease.availability_note, /no official code artifact/i);
  assert.equal(report.source_basis.emilia.implementation_kind, 'repository-runtime');
  assert.equal(report.source_basis.emilia.store_durable, false);
});

test('positive exact-action admission and replay resistance identify the meaningful overlap', async () => {
  const report = await runComparison();
  const positive = byId(report, 'CL-EP-01');
  const replay = byId(report, 'CL-EP-02');

  assert.equal(positive.relation, 'COMPATIBLE');
  assert.equal(positive.caplease.final_state, 'COMMITTED');
  assert.equal(positive.caplease.admissions, 1);
  assert.equal(positive.emilia.final_state, 'committed');
  assert.equal(positive.emilia.outcome, 'executed');

  assert.equal(replay.relation, 'COMPATIBLE_WITH_DIFFERENT_IDENTITY_KEYS');
  assert.equal(replay.caplease.fresh_artifact_result, 'EXISTING_AUTHORIZATION');
  assert.equal(replay.caplease.admissions, 1);
  assert.equal(replay.emilia.fresh_operation_result, 'REFUSED');
  assert.equal(replay.emilia.reason, 'action_already_committed');
});

test('material substitution, expiry, and pre-admission revocation fail closed in both systems', async () => {
  const report = await runComparison();
  const substitution = byId(report, 'CL-EP-03');
  const expiry = byId(report, 'CL-EP-04');
  const revocation = byId(report, 'CL-EP-05');

  assert.equal(substitution.relation, 'COMPATIBLE');
  assert.equal(substitution.caplease.reason, 'action_identity_mismatch');
  assert.equal(substitution.emilia.reason, 'capability_action_out_of_scope');

  assert.equal(expiry.relation, 'COMPATIBLE');
  assert.equal(expiry.caplease.reason, 'authorization_expired');
  assert.equal(expiry.emilia.reason, 'capability_expired');

  assert.equal(revocation.relation, 'COMPATIBLE');
  assert.equal(revocation.caplease.reason, 'authorization_revoked');
  assert.equal(revocation.emilia.reason, 'capability_revoked');
});

test('lost acknowledgement preserves the recovery non-equivalence', async () => {
  const report = await runComparison();
  const lostAck = byId(report, 'CL-EP-06');

  assert.equal(lostAck.relation, 'DIFFERENT_RECOVERY_CONTRACT');
  assert.deepEqual(lostAck.caplease, {
    first_result: 'ACK_LOST',
    recovery: 'RETRIED_SAME_KEY',
    final_state: 'COMMITTED',
    sink_calls: 2,
    effects: 1,
  });
  assert.deepEqual(lostAck.emilia, {
    first_result: 'INDETERMINATE',
    blind_replay: 'REFUSED',
    replay_reason: 'operation_already_committed',
    final_state: 'committed',
    original_outcome: 'indeterminate',
    reconciliation: 'executed',
    effects: 1,
    reexecuted: false,
  });
});

test('unsupported and unproven joins are labeled instead of forced into equivalence', async () => {
  const report = await runComparison();
  const reconciliation = byId(report, 'CL-EP-07');
  const identity = byId(report, 'CL-EP-08');

  assert.equal(reconciliation.relation, 'CAPLEASE_UNSUPPORTED_BY_PAPER');
  assert.equal(reconciliation.caplease.status, 'UNSUPPORTED');
  assert.equal(reconciliation.emilia.status, 'SUPPORTED');

  assert.equal(identity.relation, 'EMILIA_NOT_EQUIVALENT');
  assert.match(identity.caplease.identity_key, /sigma.*confirmation_event/);
  assert.match(identity.emilia.identity_key, /operation_namespace.*action_fence_digest/);
  assert.equal(identity.emilia.confirmation_event_uniqueness, 'NOT_CLAIMED');
});

test('the comparison inventory and report digest are deterministic', async () => {
  const first = await runComparison();
  const second = await runComparison();

  assert.deepEqual(first.summary, {
    passed: 8,
    total: 8,
    compatible: 5,
    different: 2,
    unsupported: 1,
  });
  assert.equal(first.report_digest, second.report_digest);
  assert.match(first.report_digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(first.checks.map((entry) => entry.id), [
    'CL-EP-01',
    'CL-EP-02',
    'CL-EP-03',
    'CL-EP-04',
    'CL-EP-05',
    'CL-EP-06',
    'CL-EP-07',
    'CL-EP-08',
  ]);
});
