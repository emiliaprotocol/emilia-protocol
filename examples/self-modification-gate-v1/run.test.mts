// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./run.mjs', import.meta.url));

test('emits a passing, claim-bounded self-modification report on plain Node', () => {
  const result = spawnSync(process.execPath, [runner], {
    encoding: 'utf8',
    timeout: 30_000,
  });
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report['@version'], 'EMILIA-SELF-MODIFICATION-GATE-REPORT-v1');
  assert.equal(report.passed, true);
  assert.equal(report.checks_passed, 6);
  assert.equal(report.checks_total, 6);
  assert.match(report.claim_boundary, /not an external reproduction/);
  assert.match(report.claim_boundary, /not.*exactly-once physical-effect/i);
});
