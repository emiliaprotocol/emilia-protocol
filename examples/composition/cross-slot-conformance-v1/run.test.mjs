// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { NEGATIVE_IDS, buildCatalog, evaluateCase, runSuite, } from './run.mjs';
test('catalog contains one four-slot positive and thirteen paired controls', () => {
    const catalog = buildCatalog();
    assert.equal(NEGATIVE_IDS.length, 13);
    assert.equal(catalog.length, 27);
    assert.deepEqual(Object.keys(catalog[0].bundle.slots).sort(), ['audit', 'can', 'what', 'who']);
    for (const id of NEGATIVE_IDS) {
        assert.equal(catalog.filter((entry) => entry.pair_id === id).length, 2);
    }
});
test('every negative rejects for its named condition and its repair returns to pass', () => {
    const catalog = buildCatalog();
    for (const id of NEGATIVE_IDS) {
        const negative = catalog.find((entry) => entry.id === id);
        const repair = catalog.find((entry) => entry.id === `${id}.condition_removed`);
        assert.ok(negative, `${id} negative missing`);
        assert.ok(repair, `${id} repair missing`);
        const negativeResult = evaluateCase(negative);
        const repairResult = evaluateCase(repair);
        assert.equal(negativeResult.terminal, negative.expected_terminal, id);
        assert.equal(negativeResult.primary_check, negative.expected_check, id);
        assert.equal(repairResult.terminal, 'pass', `${id} repair`);
        assert.equal(repairResult.crashed, false, `${id} repair crashed`);
    }
});
test('native reports remain separate and are never upgraded by composition', () => {
    const result = evaluateCase(buildCatalog()[0]);
    assert.equal(result.terminal, 'pass');
    assert.deepEqual(result.native_results.map((entry) => entry.slot), ['can', 'who', 'what', 'audit']);
    assert.equal(result.native_results.every((entry) => entry.native_result === 'pass'), true);
});
test('unknown optional semantics remain readable but cannot satisfy a required policy', () => {
    const item = buildCatalog().find((entry) => entry.id === 'COMP-BIND-06');
    assert.ok(item);
    const result = evaluateCase(item);
    assert.equal(result.terminal, 'unsupported');
    assert.equal(result.binding_state, 'present_uninterpreted');
    assert.equal(result.crashed, false);
});
test('complete EMILIA run report passes all 27 cases without a crash', () => {
    const run = runSuite();
    assert.equal(run.report.case_count, 27);
    assert.equal(run.report.negative_pair_count, 13);
    assert.equal(run.report.passed, true);
    assert.equal(run.report.checks.every((entry) => entry.no_crash), true);
    assert.equal(run.report.checks.every((entry) => entry.native_results_match), true);
    assert.equal(run.report.checks.every((entry) => entry.join_results_match), true);
    for (const result of run.report.results) {
        assert.equal(typeof result.input_artifact_digests.action, 'string');
        assert.equal(result.native_results.every((entry) => entry.expected_result), true);
        assert.equal(result.join_results.every((entry) => entry.expected_result), true);
        for (const entry of result.join_results.filter((value) => value.status !== 'pass' && value.status !== 'not_evaluated')) {
            assert.equal(typeof entry.divergence.field, 'string');
            assert.equal(Object.hasOwn(entry.divergence, 'expected'), true);
            assert.equal(Object.hasOwn(entry.divergence, 'actual'), true);
            assert.equal(Object.hasOwn(entry.divergence, 'expected_basis'), true);
            assert.equal(Object.hasOwn(entry.divergence, 'actual_basis'), true);
        }
    }
    const reportBody = structuredClone(run.report);
    delete reportBody.report_digest;
    const canonical = (value) => {
        if (Array.isArray(value))
            return value.map(canonical);
        if (value !== null && typeof value === 'object') {
            return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
        }
        return value;
    };
    const digest = `sha256:${crypto.createHash('sha256')
        .update(JSON.stringify(canonical(reportBody))).digest('hex')}`;
    assert.equal(run.report.report_digest, digest);
});
test('condition-removed controls preserve unrelated state', () => {
    const catalog = buildCatalog();
    const bindingRepair = catalog.find((entry) => entry.id === 'COMP-BIND-06.condition_removed');
    assert.ok(bindingRepair);
    assert.equal(bindingRepair.bundle.slots.who.additional_bindings.at(-1).purpose, 'vendor_future_binding');
    assert.equal(bindingRepair.bundle.slots.who.additional_bindings.at(-1).understood, true);
    const resultRepair = catalog.find((entry) => entry.id === 'COMP-JOIN-02.condition_removed');
    assert.ok(resultRepair);
    assert.equal(resultRepair.bundle.slots.what.native_result, 'not_evaluated');
    assert.equal(resultRepair.bundle.reporting.reported_native_results.what, 'not_evaluated');
});
