// SPDX-License-Identifier: Apache-2.0
// Generated from demo.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { runPoppyGateDemo } from './demo.mjs';
test('joined Poppy, native EP verification and protected Gate demo passes every case', async () => {
    const report = await runPoppyGateDemo();
    assert.equal(report.passed, true, JSON.stringify(report, null, 2));
    assert.equal(report.scope, 'synthetic_local_reference');
    assert.equal(report.independent_interoperability, false);
    assert.equal(report.cases.length, 7);
});
test('false approval and changed material do not enter the provider', async () => {
    const report = await runPoppyGateDemo();
    for (const id of ['false_approval', 'changed_revision', 'tampered_evidence']) {
        const row = report.cases.find((item) => item.id === id);
        assert.equal(row.pass, true);
        assert.equal(row.provider_attempts, 0);
    }
});
test('concurrent confirmation and authenticated reconciliation do not duplicate effects', async () => {
    const report = await runPoppyGateDemo();
    const concurrent = report.cases.find((item) => item.id === 'concurrent_confirmation');
    const loss = report.cases.find((item) => item.id === 'response_loss_and_reconciliation');
    assert.equal(concurrent.provider_attempts, 1);
    assert.equal(loss.before_reconciliation, 'in_progress');
    assert.equal(loss.after_reconciliation, 'succeeded');
    assert.equal(loss.provider_attempts, 1);
});
