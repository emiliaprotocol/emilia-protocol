// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { buildWorkspace, runSuite, vectorSet } from './run.mjs';

test('CCS draft-08 v1.3 Crossing Lab profile passes every pinned and hostile check', async () => {
  const report = await runSuite();
  assert.equal(report.passed, true);
  assert.equal(report.crossing_lab.lab_passed, true);
  assert.equal(report.checks.length, 19);
  assert.equal(report.checks.every((entry) => entry.passed), true);
});

test('fixture generation is deterministic and preserves the exact 22-field native shape', () => {
  const first = buildWorkspace();
  const second = buildWorkspace();
  assert.deepEqual(first.workspace, second.workspace);
  assert.deepEqual(first.positive, second.positive);
  assert.equal(Object.keys(first.positive).length, 22);
  assert.equal(first.workspace.config.relying_party_id, 'rp:emilia:ccs-wang-draft08');
});

test('published hostile vectors include deny, escalate, and full-digest substitution cases', () => {
  const vectors = vectorSet();
  assert.deepEqual(Object.keys(vectors.artifacts).sort(), [
    'allow-live-sum',
    'deny-policy',
    'escalate-operator-review',
    'same-prefix-different-full-digest',
  ]);
  assert.equal(vectors.artifacts['deny-policy'].verdict, 'deny');
  assert.equal(vectors.artifacts['escalate-operator-review'].verdict, 'escalate');
});
