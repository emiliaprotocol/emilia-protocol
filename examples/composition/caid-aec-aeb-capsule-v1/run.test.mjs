// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { buildCases, evaluateCase, runSuite } from './run.mjs';
test('profile pins the active Capsule -02 revision', () => {
    const run = runSuite();
    const capsule = run.manifest.drafts.find((entry) => entry.role === 'Capsule WHAT');
    assert.ok(capsule);
    assert.equal(capsule.revision, 'draft-mih-scitt-agent-action-capsule-02');
    assert.equal(capsule.sha256, 'sha256:493428486c85e03624bc1d90e8265b072b98265b93b7bd50d55824688a1802d8');
});
test('all eight composition attempts reproduce their expected axes', () => {
    const run = runSuite();
    assert.equal(run.report.case_count, 8);
    assert.equal(run.report.passed, true);
    assert.equal(run.report.checks.every((entry) => entry.no_crash), true);
});
test('unsupported required binding is a structured refusal, not a pass or crash', () => {
    const item = buildCases().find((entry) => entry.id === 'unsupported_required_binding');
    assert.ok(item);
    const result = evaluateCase(item);
    assert.equal(result.verifier.status, 'REFUSED');
    assert.equal(result.verifier.crashed, false);
    assert.equal(result.admission, 'REFUSED');
    assert.equal(result.outcome, 'NONE');
    assert.deepEqual(result.reason_codes, ['unsupported_required_binding:capsule.class3']);
});
test('post-dispatch timeout is sticky indeterminate and observer conflict is divergent', () => {
    const cases = buildCases();
    const timeoutCase = cases.find((entry) => entry.id === 'timeout_after_dispatch');
    const divergenceCase = cases.find((entry) => entry.id === 'independent_observer_contradiction');
    assert.ok(timeoutCase);
    assert.ok(divergenceCase);
    const timeout = evaluateCase(timeoutCase);
    const divergence = evaluateCase(divergenceCase);
    assert.equal(timeout.admission, 'CONSUMED');
    assert.equal(timeout.outcome, 'INDETERMINATE');
    assert.equal(timeout.reason_codes.includes('timeout_after_dispatch'), true);
    assert.equal(divergence.outcome, 'DIVERGENT');
    assert.equal(divergence.reason_codes.includes('provider_committed_effect_diverged'), true);
});
