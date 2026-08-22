// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { runTrustedContextMultiProviderDemo } from './run.mjs';
test('multi-provider trusted-context demo passes every bounded case', () => {
    const report = runTrustedContextMultiProviderDemo();
    assert.equal(report.passed, true, JSON.stringify(report, null, 2));
    assert.equal(report.checks_passed, 7);
    assert.equal(report.checks_total, 7);
    assert.match(report.claim_boundary, /not a native provider conformance result/);
});
