// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createTrustedActionFirewall,
  createDefaultActionRiskManifest,
  createEg1Harness,
  cf1Conformance,
  cf1ConformanceSelfTest,
  CF1_CHECKS,
  EG1_DEFAULT_SELECTOR,
} from './index.js';

test('CF-1: the reference gate self-certifies (all checks pass)', async () => {
  const report = await cf1ConformanceSelfTest();
  assert.equal(report.standard, 'CF-1');
  assert.equal(report.passed, true, JSON.stringify(report.checks.filter((c) => !c.pass), null, 2));
  assert.equal(report.badge, 'CF-1 Enforced');
  assert.equal(report.summary.passed, CF1_CHECKS.length);
  for (const c of report.checks) assert.equal(c.pass, true, `check failed: ${c.id}`);
});

test('CF-1: report enumerates every defined check exactly once', async () => {
  const report = await cf1ConformanceSelfTest();
  const ids = report.checks.map((c) => c.id).sort();
  assert.deepEqual(ids, CF1_CHECKS.map((c) => c.id).sort());
});

test('CF-1: includes the three category checks beyond EG-1', async () => {
  const ids = CF1_CHECKS.map((c) => c.id);
  for (const id of ['consequential_action_declared', 'wrong_authority_refused', 'evidence_verifies_offline']) {
    assert.ok(ids.includes(id), `CF-1 must define ${id}`);
  }
});

test('CF-1: a gate that trusts the WRONG authority cannot earn the badge', async () => {
  const harness = createEg1Harness();
  const manifest = createDefaultActionRiskManifest();
  // The gate under test trusts the WRONG key → every valid receipt is rejected.
  const wrongHarness = createEg1Harness();
  const gate = createTrustedActionFirewall({ trustedKeys: [wrongHarness.publicKey], approverKeys: wrongHarness.approverKeys });
  const report = await cf1Conformance({ gate, harness, manifest, selector: EG1_DEFAULT_SELECTOR, action: harness.action });
  assert.equal(report.passed, false);
  const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
  // A wrong-trust gate refuses the valid receipt → valid_classA_runs fails.
  assert.equal(byId.valid_classA_runs.pass, false);
});

test('CF-1: an action the manifest does not declare consequential fails the declaration check', async () => {
  const harness = createEg1Harness();
  const manifest = createDefaultActionRiskManifest();
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys });
  const wrongHarness = createEg1Harness();
  const wrongGate = createTrustedActionFirewall({ trustedKeys: [wrongHarness.publicKey], approverKeys: wrongHarness.approverKeys });
  // A selector the default manifest does not guard → no requirement resolved.
  const report = await cf1Conformance({
    gate, wrongGate, harness, manifest,
    selector: { protocol: 'mcp', tool: 'not_a_declared_action' },
    action: harness.action,
  });
  const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
  assert.equal(byId.consequential_action_declared.pass, false);
});
