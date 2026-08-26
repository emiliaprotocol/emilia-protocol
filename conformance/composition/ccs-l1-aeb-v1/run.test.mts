// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSuite } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('CCS 1.1.19 to AEB profile passes every pinned and hostile case', () => {
  const report = runSuite() as any;
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.checks.length, 8);
  assert.equal(report.checks.every((entry: any) => entry.passed), true);
  assert.match(report.pins.ccs_sdist_sha256, /^[0-9a-f]{64}$/);
  assert.match(report.pins.ccs_wheel_sha256, /^[0-9a-f]{64}$/);
});

test('checked-in report is byte-identical to the deterministic runner output', () => {
  const expected = `${JSON.stringify(runSuite(), null, 2)}\n`;
  assert.equal(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'), expected);
});
