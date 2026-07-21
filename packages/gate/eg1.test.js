// SPDX-License-Identifier: Apache-2.0
// Generated from eg1.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTrustedActionFirewall, createEg1Harness, gateConformance, gateConformanceSelfTest, runEg1, EG1_CHECKS, } from './index.js';
test('EG-1: the reference gate self-certifies (all eight checks pass)', async () => {
    const report = await gateConformanceSelfTest();
    assert.equal(report.standard, 'EG-1');
    assert.equal(report.passed, true, JSON.stringify(report.checks.filter((c) => !c.pass), null, 2));
    assert.equal(report.badge, 'EG-1 Enforced');
    assert.equal(report.summary.passed, EG1_CHECKS.length);
    for (const c of report.checks)
        assert.equal(c.pass, true, `check failed: ${c.id}`);
});
test('EG-1: report enumerates every defined check exactly once', async () => {
    const report = await gateConformanceSelfTest();
    const ids = report.checks.map((c) => c.id).sort();
    assert.deepEqual(ids, EG1_CHECKS.map((c) => c.id).sort());
});
test('EG-1: a gate that does not trust the issuer cannot earn it', async () => {
    // Build a gate trusting a DIFFERENT key than the harness mints with: every
    // valid receipt is rejected, so the "valid runs" / proof / packet checks fail.
    const harness = createEg1Harness();
    const otherKey = createEg1Harness().publicKey;
    const gate = createTrustedActionFirewall({ trustedKeys: [otherKey], allowEphemeralStore: true });
    const report = await gateConformance({ gate, harness });
    assert.equal(report.passed, false);
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c.pass]));
    assert.equal(byId.valid_classA_runs, false);
    assert.equal(byId.execution_proof_binds, false);
    assert.equal(byId.reliance_packet_rely, false);
});
test('EG-1: a sham "always allow" integration fails the refusal checks', async () => {
    // The classic false claim: an integration that says it is protected but never
    // actually refuses. EG-1 must catch it — the refusal checks must fail.
    const harness = createEg1Harness();
    const shamInvoke = async () => ({ allowed: true, status: 200, reason: 'allow' });
    const report = await runEg1({ invoke: shamInvoke, harness });
    assert.equal(report.passed, false);
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c.pass]));
    assert.equal(byId.missing_receipt_refused, false);
    assert.equal(byId.software_on_classA_refused, false);
    assert.equal(byId.execution_drift_refused, false);
    assert.equal(byId.replay_refused, false);
    assert.equal(byId.tampered_refused, false);
});
test('EG-1: a "refuse everything" integration also fails (cannot run the valid action)', async () => {
    const harness = createEg1Harness();
    const denyAll = async () => ({ allowed: false, status: 428, reason: 'receipt_required' });
    const report = await runEg1({ invoke: denyAll, harness });
    assert.equal(report.passed, false);
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c.pass]));
    // It refuses the bad cases, but it never RUNS the valid one or proves execution.
    assert.equal(byId.valid_classA_runs, false);
    assert.equal(byId.execution_proof_binds, false);
    assert.equal(byId.reliance_packet_rely, false);
});
