// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { assertContractLock, canonicalReportBytes, runSuite, signReport, verifyReportSignature, } from './run.mjs';
const RUNNER = Object.freeze({
    runner_name: 'EMILIA reference runner',
    runner_affiliation: 'EMILIA Protocol',
    runner_revision: 'test-fixture',
    executed_at: '2026-08-11T20:00:00Z',
});
let cachedReport = null;
function referenceReport() {
    cachedReport ??= runSuite(RUNNER);
    return cachedReport;
}
test('AEB-ADAPTER-v1 compatibility lock pins the contract, documentation, and vectors', () => {
    const result = assertContractLock();
    assert.equal(result.valid, true, JSON.stringify(result, null, 2));
    assert.equal(result.contract_version, 'AEB-ADAPTER-v1');
    assert.equal(result.files.length, 3);
});
test('reference run checks native protocols separately from AEB composition', () => {
    const report = referenceReport();
    assert.equal(report.passed, true, JSON.stringify(report, null, 2));
    assert.equal(report.pins.oasnt_revision, 'draft-thallapelly-oasnt-02');
    assert.equal(report.pins.oasnt_archived_txt_sha256, 'sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603');
    assert.equal(report.source_protocol_checks.length >= 5, true);
    const publishedOasntCheck = report.source_protocol_checks.find((entry) => entry.id === 'OASNT-02-TOKEN-ACCEPT');
    assert.ok(publishedOasntCheck, 'published OASNT check must name the pinned -02 revision');
    assert.match(publishedOasntCheck.description, /OASNT-02/);
    assert.equal(report.source_protocol_checks.some((entry) => /OASNT-01/.test(`${entry.id} ${entry.description}`)), false, 'report must not mix the retired -01 label into its pinned -02 evidence');
    assert.equal(report.aeb_composition_checks.length >= 5, true);
    assert.equal(report.source_protocol_checks.every((entry) => entry.passed), true);
    assert.equal(report.aeb_composition_checks.every((entry) => entry.passed), true);
    assert.equal(report.aeb_composition_checks.some((entry) => entry.id === 'AEB-COMPOSE-APPROVE-A-EXECUTE-B'), true);
    assert.equal(report.aeb_composition_checks.some((entry) => entry.id === 'AEB-COMPOSE-REPLAY-AFTER-INDETERMINATE'), true);
});
test('two native legs join one exact action without collapsing their roles', () => {
    const report = referenceReport();
    assert.equal(report.composition.action_digest, report.composition.ccs_action_digest);
    assert.equal(report.composition.action_digest, report.composition.oasnt_action_digest);
    assert.equal(report.composition.caid, report.composition.ccs_caid);
    assert.equal(report.composition.caid, report.composition.oasnt_caid);
    assert.deepEqual(report.composition.evidence_roles, [
        'human-authorization',
        'machine-policy-decision',
    ]);
    assert.equal(report.composition.evaluation_verdict, 'SATISFIED');
    assert.equal(report.composition.first_admission, 'AUTHORIZED');
    assert.equal(report.composition.first_outcome, 'RECONCILIATION_REQUIRED');
    assert.equal(report.composition.replay_admission, 'REFUSED');
});
test('checked-in reference report matches the current runner output', () => {
    const checkedIn = JSON.parse(readFileSync(new URL('report.reference.json', import.meta.url), 'utf8'));
    const current = runSuite({
        runner_name: checkedIn.runner.name,
        runner_affiliation: checkedIn.runner.affiliation,
        runner_revision: checkedIn.runner.revision,
        executed_at: checkedIn.runner.executed_at,
    });
    assert.deepEqual(checkedIn, current);
});
test('an external execution is not mislabeled as an independent implementation', () => {
    const report = runSuite({
        runner_name: 'Source author',
        runner_affiliation: 'External project',
        runner_revision: 'external-run-1',
        executed_at: '2026-08-11T20:00:00Z',
    });
    assert.equal(report.runner.execution_owner, 'runner-asserted');
    assert.equal(report.runner.implementation_owner, 'EMILIA Protocol');
    assert.equal(report.runner.independent_implementation, false);
    assert.match(report.implementation_status_markdown, /reproduced the EMILIA reference composition/);
    assert.match(report.implementation_status_markdown, /not an independent implementation/);
});
test('report digest and optional runner signature cover the exact canonical report', () => {
    const report = runSuite({
        runner_name: 'External runner',
        runner_affiliation: 'Example project',
        runner_revision: 'external-run-1',
        executed_at: '2026-08-11T20:00:00Z',
    });
    const keys = crypto.generateKeyPairSync('ed25519');
    const signed = signReport(report, keys.privateKey, 'runner:test');
    assert.equal(verifyReportSignature(signed), true);
    assert.equal(Buffer.from(signed.signature.signed_report_b64u, 'base64url').equals(canonicalReportBytes(report)), true);
    const changed = structuredClone(signed);
    changed.report.passed = false;
    assert.equal(verifyReportSignature(changed), false);
});
