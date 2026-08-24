// SPDX-License-Identifier: Apache-2.0
// Generated from run.node-test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runComposition } from './run.mjs';
function byId(report, id) {
    const entry = report.checks.find((candidate) => candidate.id === id);
    assert.ok(entry, `missing AADP x EP case ${id}`);
    return entry;
}
test('source lock pins AADP -01, onedoor inspection bytes, and EP inputs', () => {
    const lock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
    assert.equal(lock['@version'], 'AADP-EP-SOURCE-LOCK-v0.1');
    assert.equal(lock.aadp.draft, 'draft-saha-aadp-01');
    assert.match(lock.aadp.text.sha256, /^[0-9a-f]{64}$/);
    assert.match(lock.onedoor.revision, /^[0-9a-f]{40}$/);
    for (const file of lock.emilia.runtime_files) {
        const bytes = readFileSync(new URL(`../../../${file.path}`, import.meta.url));
        assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), file.sha256, file.path);
    }
});
test('all fourteen profile cases pass with a deterministic report', () => {
    const first = runComposition();
    const second = runComposition();
    assert.equal(first.passed, true, JSON.stringify(first, null, 2));
    assert.deepEqual(first.summary, { passed: 14, total: 14 });
    assert.equal(first.report_digest, second.report_digest);
    assert.deepEqual(first.checks.map((entry) => entry.id), [
        'AADP-EP-01', 'AADP-EP-02', 'AADP-EP-03', 'AADP-EP-04',
        'AADP-EP-05', 'AADP-EP-06', 'AADP-EP-07', 'AADP-EP-08',
        'AADP-EP-09', 'AADP-EP-10', 'AADP-EP-11', 'AADP-EP-12',
        'AADP-EP-13', 'AADP-EP-14',
    ]);
});
test('the positive case proves a digest join, not inherited authority', () => {
    const report = runComposition();
    const positive = byId(report, 'AADP-EP-01');
    const killSwitch = byId(report, 'AADP-EP-10');
    const separation = byId(report, 'AADP-EP-12');
    assert.equal(positive.actual.decision, 'permitted');
    assert.equal(killSwitch.actual.reason, 'kill_switch_active');
    assert.notEqual(separation.actual.permit_id, separation.actual.artifact_digest);
    assert.equal(report.claim_boundary.authorization_artifact_is_authority, false);
    assert.equal(report.claim_boundary.exactly_once_physical_effect_claimed, false);
});
test('hostile and unavailable paths preserve refusal versus indeterminate', () => {
    const report = runComposition();
    assert.equal(byId(report, 'AADP-EP-02').actual.verdict, 'REFUSE');
    assert.equal(byId(report, 'AADP-EP-03').actual.verdict, 'REFUSE');
    assert.equal(byId(report, 'AADP-EP-04').actual.verdict, 'REFUSE');
    assert.equal(byId(report, 'AADP-EP-05').actual.verdict, 'REFUSE');
    assert.equal(byId(report, 'AADP-EP-06').actual.verdict, 'INDETERMINATE');
    assert.equal(byId(report, 'AADP-EP-07').actual.verdict, 'INDETERMINATE');
});
test('AADP lifecycle remains single-use and timeout-safe', () => {
    const report = runComposition();
    const replay = byId(report, 'AADP-EP-11').actual;
    const timeout = byId(report, 'AADP-EP-13').actual;
    assert.deepEqual(replay, {
        first: 'permitted',
        second: 'proposed',
        second_reason: 'approval_ref_not_usable',
        permits: 1,
    });
    assert.deepEqual(timeout, {
        report: 'timeout',
        retry: 'proposed',
        retry_reason: 'approval_ref_not_usable',
        permits: 1,
    });
});
