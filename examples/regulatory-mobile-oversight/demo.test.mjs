// SPDX-License-Identifier: Apache-2.0
// Generated from demo.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildSyntheticRegulatoryDemo, verifyRegulatoryEvidence, } from './lib.mjs';
const demo = await buildSyntheticRegulatoryDemo();
test('deterministic mobile fixture exercises the regulator evidence path', () => {
    assert.equal(demo.onlineResult.valid, true);
    assert.equal(demo.effect.applied, true);
    assert.equal(demo.replayResult.verdict, 'refuse_replay');
    assert.equal(demo.offlineReport.valid, true);
    assert.deepEqual(Object.values(demo.offlineReport.checks), Array(Object.keys(demo.offlineReport.checks).length).fill(true));
});
test('action and presentation substitution both refuse offline', () => {
    const action = structuredClone(demo.evidence);
    action.receipt.action.units_approved = '999';
    const actionReport = verifyRegulatoryEvidence(action, demo.trustBundle);
    assert.equal(actionReport.valid, false);
    assert.equal(actionReport.checks.receipt, false);
    const presentation = structuredClone(demo.evidence);
    presentation.presentation.material_fields.units_approved = 999;
    const presentationReport = verifyRegulatoryEvidence(presentation, demo.trustBundle);
    assert.equal(presentationReport.valid, false);
    assert.equal(presentationReport.checks.presentation_binding, false);
});
test('evidence never supplies its own reviewer or operator trust keys', () => {
    const wrongReviewer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const wrongPins = structuredClone(demo.trustBundle);
    wrongPins.approver_keys[demo.evidence.execution_record.device_key_id].public_key =
        wrongReviewer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const reviewerReport = verifyRegulatoryEvidence(demo.evidence, wrongPins);
    assert.equal(reviewerReport.valid, false);
    assert.equal(reviewerReport.checks.receipt, false);
    assert.equal(reviewerReport.checks.enrollment_binding, false);
    const missingOperatorKey = structuredClone(demo.trustBundle);
    missingOperatorKey.execution_record_keys = {};
    const operatorReport = verifyRegulatoryEvidence(demo.evidence, missingOperatorKey);
    assert.equal(operatorReport.valid, false);
    assert.equal(operatorReport.checks.execution_record_signature, false);
});
test('unknown package and trust claims are refused instead of ignored', () => {
    const evidence = structuredClone(demo.evidence);
    evidence.regulator_approved = true;
    const evidenceReport = verifyRegulatoryEvidence(evidence, demo.trustBundle);
    assert.equal(evidenceReport.valid, false);
    assert.equal(evidenceReport.checks.package_shape, false);
    const trust = structuredClone(demo.trustBundle);
    trust.operator_is_infallible = true;
    const trustReport = verifyRegulatoryEvidence(demo.evidence, trust);
    assert.equal(trustReport.valid, false);
    assert.equal(trustReport.checks.trust_bundle_shape, false);
});
test('runtime statement and audit record cannot be detached or relabeled', () => {
    const runtime = structuredClone(demo.evidence);
    runtime.execution_record.decision = 'denied';
    const runtimeReport = verifyRegulatoryEvidence(runtime, demo.trustBundle);
    assert.equal(runtimeReport.valid, false);
    assert.equal(runtimeReport.checks.execution_record_signature, false);
    assert.equal(runtimeReport.checks.receipt_execution_join, false);
    const audit = structuredClone(demo.evidence);
    audit.audit_record.action_hash = `sha256:${'00'.repeat(32)}`;
    const auditReport = verifyRegulatoryEvidence(audit, demo.trustBundle);
    assert.equal(auditReport.valid, false);
    assert.equal(auditReport.checks.audit_record_join, false);
});
test('the report separates direct verification, operator assertions, and nonclaims', () => {
    assert.match(demo.attestationFixture, /no Apple assertion/);
    assert.ok(demo.offlineReport.directly_recomputed_offline.includes('Class-A passkey signature under an out-of-band pinned reviewer key'));
    assert.ok(demo.offlineReport.operator_attested_not_independently_replayed.includes('Apple App Attest or Google Play Integrity passed at execution time'));
    assert.ok(demo.offlineReport.not_established.includes('legal or regulatory compliance'));
    assert.ok(demo.offlineReport.not_established.includes('the real-world effect of the authorized action'));
    const exported = JSON.stringify({ evidence: demo.evidence, trust: demo.trustBundle });
    assert.doesNotMatch(exported, /private_key|BEGIN PRIVATE KEY/);
});
