// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSuite, sampleReceiptSet } from './run.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('CCS-05 v1.3 independent live-run profile passes every source, binding, and hostile check', () => {
  const report = runSuite() as any;
  assert.equal(report.passed, true, JSON.stringify(report, null, 2));
  assert.equal(report.checks.length, 14);
  assert.equal(report.checks.every((entry: any) => entry.passed), true);
  assert.match(report.pins.draft_sha256, /^[0-9a-f]{64}$/);
  assert.match(report.pins.sample_set_digest, /^sha256:[0-9a-f]{64}$/);
});

test('checked-in report and sample receipt set are byte-identical to deterministic output', () => {
  assert.equal(
    readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'),
    `${JSON.stringify(runSuite(), null, 2)}\n`,
  );
  assert.equal(
    readFileSync(resolve(HERE, 'sample-receipts.reference.json'), 'utf8'),
    `${JSON.stringify(sampleReceiptSet(), null, 2)}\n`,
  );
});
