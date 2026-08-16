// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  canonicalReportBytes,
  runSuite,
  signReport,
  verifyReportSignature,
} from './run.mjs';

const RUNNER = Object.freeze({
  runner_name: 'EMILIA reference runner',
  runner_affiliation: 'EMILIA Protocol',
  runner_revision: 'wag-aeb-v1-test',
  executed_at: '2026-08-13T20:00:00Z',
});

let cached: ReturnType<typeof runSuite> | null = null;
function report(): ReturnType<typeof runSuite> {
  cached ??= runSuite(RUNNER);
  return cached;
}

test('the WAG profile pins the exact -00 source and all executable cases pass', () => {
  const value = report();
  assert.equal(value.passed, true, JSON.stringify(value, null, 2));
  assert.equal(value.pins.wag_revision, 'draft-carleton-workload-authz-grant-00');
  assert.equal(value.pins.wag_source_commit, '13f516a5e458b89ca30f7ea47a802091dd9d4154');
  assert.equal(value.checks.length, 15);
  assert.equal(value.checks.every((entry: any) => entry.passed), true);
});

test('hostile cases cover every load-bearing WAG-to-AEB seam', () => {
  const ids = new Set(report().checks.map((entry: any) => entry.id));
  for (const id of [
    'WAG-ISSUER-SUBSTITUTION',
    'WAG-TENANT-KEY-SUBSTITUTION',
    'WAG-UNSEEN-SUBJECT-ACCEPT',
    'WAG-SUBJECT-SUBSTITUTION',
    'WAG-AUDIENCE-SUBSTITUTION',
    'WAG-RESOURCE-SUBSTITUTION',
    'WAG-PROPERTY-SUBSTITUTION',
    'WAG-EXPIRED-GRANT',
    'WAG-STATUS-UNAVAILABLE',
    'WAG-SECOND-TOKEN-ISSUANCE',
    'WAG-DOWNSTREAM-ACTION-NON-SUBSTITUTION',
    'WAG-NOT-HUMAN-APPROVAL',
  ]) assert.equal(ids.has(id), true, id);
});

test('an external run is labeled as reproduction, not independent implementation or endorsement', () => {
  const value = runSuite({
    runner_name: 'External source author',
    runner_affiliation: 'Example project',
    runner_revision: 'external-run-1',
    executed_at: '2026-08-13T20:00:00Z',
  });
  assert.equal(value.runner.execution_owner, 'runner-asserted');
  assert.equal(value.runner.implementation_owner, 'EMILIA Protocol');
  assert.equal(value.runner.independent_implementation, false);
  assert.match(value.implementation_status_markdown, /reproduced the EMILIA WAG -00 to AEB/);
  assert.match(value.implementation_status_markdown, /not an independent implementation/);
  assert.match(value.implementation_status_markdown, /not.*employer endorsement/);
});

test('the report preserves the workload-only and downstream non-substitution boundary', () => {
  const value = report();
  assert.equal(value.composition.evidence_role, 'workload-authorization-grant');
  assert.equal(value.composition.subject_kind, 'workload');
  const boundary = value.checks.find((entry: any) => entry.id === 'WAG-DOWNSTREAM-ACTION-NON-SUBSTITUTION');
  assert.equal(boundary.observed.acceptance, 'INDETERMINATE');
});

test('optional runner signature covers the exact canonical report bytes', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  const signed = signReport(report(), keys.privateKey, 'runner:test');
  assert.equal(verifyReportSignature(signed), true);
  assert.equal(
    Buffer.from(signed.signature.signed_report_b64u, 'base64url').equals(canonicalReportBytes(report())),
    true,
  );
  const changed = structuredClone(signed);
  changed.report.profile = 'tampered-profile';
  assert.equal(verifyReportSignature(changed), false);
});
