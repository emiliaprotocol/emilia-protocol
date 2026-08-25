// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

import { runComposition } from './run.mjs';

function byId(report: any, id: string): any {
  const entry = report.checks.find((candidate: any) => candidate.id === id);
  assert.ok(entry, `missing AADP x EP case ${id}`);
  return entry;
}

test('source lock pins exact AADP -01, onedoor, and exercised EP bytes', () => {
  const lock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
  assert.equal(lock['@version'], 'AADP-EP-SOURCE-LOCK-v0.1');
  assert.equal(lock.aadp.name, 'Agent Action Decision Protocol');
  assert.equal(lock.aadp.draft, 'draft-saha-aadp-01');
  assert.deepEqual(lock.aadp.bounded_sections.slice(2, 5), [
    '5.1 Decide Request',
    '5.2 Decide Response',
    '5.3 Report Request and Response',
  ]);
  assert.match(lock.aadp.text.sha256, /^[0-9a-f]{64}$/);
  assert.match(lock.onedoor.revision, /^[0-9a-f]{40}$/);
  for (const file of lock.onedoor.inspected_files) {
    assert.match(file.url, new RegExp(lock.onedoor.revision));
    assert.match(file.sha256, /^[0-9a-f]{64}$/);
  }
  for (const file of lock.emilia.runtime_files) {
    const bytes = readFileSync(new URL(`../../../${file.path}`, import.meta.url));
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
  }
});

test('all twenty-two profile cases pass with a deterministic report', () => {
  const first = runComposition();
  const second = runComposition();
  assert.equal(first.passed, true, JSON.stringify(first, null, 2));
  assert.deepEqual(first.summary, { passed: 22, total: 22 });
  assert.equal(first.report_digest, second.report_digest);
  assert.deepEqual(first.checks.map((entry: any) => entry.id), [
    'AADP-EP-01', 'AADP-EP-02', 'AADP-EP-03', 'AADP-EP-04',
    'AADP-EP-05', 'AADP-EP-06', 'AADP-EP-07', 'AADP-EP-08',
    'AADP-EP-09', 'AADP-EP-10', 'AADP-EP-11', 'AADP-EP-12',
    'AADP-EP-13', 'AADP-EP-14', 'AADP-EP-15', 'AADP-EP-16',
    'AADP-EP-17', 'AADP-EP-18', 'AADP-EP-19', 'AADP-EP-20',
    'AADP-EP-21', 'AADP-EP-22',
  ]);
});

test('the positive case proves a digest join, not inherited authority', () => {
  const report = runComposition();
  const positive = byId(report, 'AADP-EP-01');
  const killSwitch = byId(report, 'AADP-EP-10');
  const separation = byId(report, 'AADP-EP-12');

  assert.equal(positive.actual.wire_verdict, 'permit');
  assert.equal(positive.actual.native_verification, 'VERIFIED');
  assert.equal(positive.actual.evidence_satisfaction, 'SATISFIED');
  assert.equal(killSwitch.actual.reason, 'kill_switch');
  assert.notEqual(separation.actual.permit_id, separation.actual.artifact_digest);
  assert.equal(report.claim_boundary.authorization_artifact_is_authority, false);
  assert.equal(report.claim_boundary.exactly_once_physical_effect_claimed, false);
  assert.equal(report.claim_boundary.interoperability_claimed, false);
  assert.equal(report.claim_boundary.adoption_claimed, false);
});

test('the derived hook satisfies the checked-in closed JSON Schema', () => {
  const schema = JSON.parse(readFileSync(
    new URL('../../schemas/aadp-authorization-artifact.v1.schema.json', import.meta.url),
    'utf8',
  ));
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const artifact = byId(runComposition(), 'AADP-EP-14').actual.first;
  assert.equal(validate(artifact), true, JSON.stringify(validate.errors, null, 2));
});

test('hostile and unavailable paths preserve refusal versus unavailability', () => {
  const report = runComposition();
  assert.equal(byId(report, 'AADP-EP-02').actual.verdict, 'REFUSE');
  assert.equal(byId(report, 'AADP-EP-03').actual.verdict, 'REFUSE');
  assert.equal(byId(report, 'AADP-EP-04').actual.verdict, 'REFUSE');
  assert.equal(byId(report, 'AADP-EP-05').actual.verdict, 'REFUSE');
  assert.equal(byId(report, 'AADP-EP-06').actual.verdict, 'INDETERMINATE');
  assert.equal(byId(report, 'AADP-EP-07').actual.verdict, 'INDETERMINATE');
  assert.equal(byId(report, 'AADP-EP-15').actual.native_verification, 'NOT_RUN');
  assert.equal(byId(report, 'AADP-EP-16').actual.wire_verdict, 'deny');
});

test('AADP lifecycle remains single-use and timeout-safe', () => {
  const report = runComposition();
  const replay = byId(report, 'AADP-EP-11').actual;
  const timeout = byId(report, 'AADP-EP-13').actual;
  assert.deepEqual(replay, {
    first: 'permit',
    second: 'propose',
    second_reason: 'tier_confirm',
    permits: 1,
  });
  assert.deepEqual(timeout, {
    report: 'timeout',
    retry: 'propose',
    retry_reason: 'tier_confirm',
    permits: 1,
  });
});

test('kill switch wins before malformed, unavailable, and stale EP inputs are touched', () => {
  const report = runComposition();
  for (const id of ['AADP-EP-17', 'AADP-EP-18', 'AADP-EP-19']) {
    const actual = byId(report, id).actual;
    assert.equal(actual.wire_verdict, 'deny', id);
    assert.equal(actual.reason, 'kill_switch', id);
    assert.equal(actual.ep_input_observed, false, id);
  }
});

test('the AADP wire projection never invents an indeterminate verdict', () => {
  const report = runComposition();
  const unreachable = byId(report, 'AADP-EP-20').actual;
  assert.equal(unreachable.pdp_reachable, false);
  assert.equal(unreachable.wire_response, null);
  assert.equal(unreachable.malformed_wire_verdict, 'deny');
  assert.equal(unreachable.malformed_reason, 'malformed');
  assert.equal(unreachable.malformed_ep_input_observed, false);
  assert.equal(JSON.stringify(report).includes('"verdict":"indeterminate"'), false);
  assert.equal(report.claim_boundary.aadp_wire_indeterminate_verdict_defined, false);

  const separation = byId(report, 'AADP-EP-21').actual;
  assert.equal(separation.native_verification, 'VERIFIED');
  assert.equal(separation.evidence_satisfaction, 'SATISFIED');
  assert.equal(separation.authorization_decision, false);
  assert.equal(separation.aadp_wire_verdict, 'permit');
});

test('the report digest covers the source lock and every declared hash', () => {
  const report = runComposition();
  const sourceLock = report.source_basis.source_lock;
  const serialized = JSON.stringify(report);
  const hashes = [
    sourceLock.aadp.text.sha256,
    ...sourceLock.onedoor.inspected_files.map((entry: any) => entry.sha256),
    ...sourceLock.emilia.runtime_files.map((entry: any) => entry.sha256),
  ];
  for (const hash of hashes) assert.ok(serialized.includes(hash), hash);
  assert.match(report.source_basis.source_lock_file_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(report.source_basis.source_lock_canonical_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(byId(report, 'AADP-EP-22').actual.all_hashes_bound, true);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
});
