// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { runPortableStateHandoffReport } from './run.mts';

test('portable-state handoff report stays fully green and digest-bound', () => {
  const report = runPortableStateHandoffReport();
  assert.equal(report.summary.total, 58);
  assert.equal(report.summary.passed, report.summary.total);
  assert.equal(report.cases.every((entry) => entry.status === 'PASS'), true);
  assert.match(report.report_digest, /^sha256:[0-9a-f]{64}$/);
});
