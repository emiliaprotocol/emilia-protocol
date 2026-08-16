// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { runSuite } from './run.mjs';

const RUNNER = Object.freeze({
  runner_name: 'External CHAP runner',
  runner_affiliation: 'Example project',
  runner_revision: 'example-revision',
  executed_at: '2026-08-14T18:00:00.000Z',
});

test('all pinned CHAP-to-AEB checks pass', () => {
  const report = runSuite(RUNNER);
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.deepEqual(report.summary, { passed: 11, total: 11 });
  assert.equal(report.source_pins.commit, '9e7af2b811d3368b4afba7c6d318764959c2fd0d');
});

test('current CHAP approve and override semantics stay distinct', () => {
  const report = runSuite(RUNNER);
  const plain = report.checks.find((entry) => entry.id === 'CHAP-AEB-03');
  const override = report.checks.find((entry) => entry.id === 'CHAP-AEB-02');
  const extension = report.checks.find((entry) => entry.id === 'CHAP-AEB-04');
  assert.equal(plain?.passed, true);
  assert.equal(override?.passed, true);
  assert.equal(extension?.passed, true);
  assert.match(plain?.observed ?? '', /INDETERMINATE/);
});

test('hostile cases fail closed without being mislabeled as implementation evidence', () => {
  const report = runSuite(RUNNER);
  for (const id of ['CHAP-AEB-05', 'CHAP-AEB-06', 'CHAP-AEB-07', 'CHAP-AEB-08', 'CHAP-AEB-09', 'CHAP-AEB-10']) {
    assert.equal(report.checks.find((entry) => entry.id === id)?.passed, true, id);
  }
  assert.equal(report.runner.independent_implementation, false);
  assert.match(report.implementation_status_markdown, /not an independent implementation/);
});

test('report digest covers the exact report body', () => {
  const report = runSuite(RUNNER);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
  const again = runSuite(RUNNER);
  assert.equal(report.report_digest, again.report_digest);
});
