// SPDX-License-Identifier: Apache-2.0
// Generated from scenario.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSelfModificationHarness, selfModificationDigest, } from './scenario.mjs';
test('admits one exact evaluated candidate and enters the promotion provider once', async () => {
    const harness = createSelfModificationHarness();
    assert.equal(harness.compiled.programs.length, 2);
    assert.equal(harness.compiled.programs[1]?.root_caid, harness.action.caid);
    const result = await harness.run();
    assert.equal(result.ok, true);
    assert.equal(result.outcome, 'executed');
    assert.equal(result.caid, harness.action.caid);
    assert.equal(harness.providerCalls(), 1);
    assert.equal(harness.capabilityState().consumed_amount, 1);
});
test('refuses candidate substitution before any evidence or provider effect', async () => {
    const harness = createSelfModificationHarness();
    const substituted = {
        ...harness.action,
        candidate_artifact_digest: selfModificationDigest('attacker-candidate'),
    };
    const result = await harness.run({ action: substituted });
    assert.equal(result.ok, false);
    assert.equal(result.outcome, 'refused');
    assert.equal(result.reason, 'action_binding_invalid');
    assert.equal(harness.providerCalls(), 0);
    assert.equal(harness.capabilityState().consumed_amount, 0);
});
test('refuses a changed-path set that is not the one committed by the change digest', async () => {
    const harness = createSelfModificationHarness();
    const result = await harness.run({
        action: { ...harness.action, changed_paths: ['src/other.ts'] },
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'action_binding_invalid');
    assert.equal(harness.providerCalls(), 0);
});
test('refuses evaluator drift and reports bound to another evaluator epoch', async () => {
    const harness = createSelfModificationHarness();
    const suiteDrift = await harness.run({
        fitnessClaims: { suite_digest: selfModificationDigest('changed-suite') },
    });
    assert.equal(suiteDrift.ok, false);
    assert.equal(suiteDrift.reason, 'fitness_suite_mismatch');
    assert.equal(harness.providerCalls(), 0);
    const otherCandidate = createSelfModificationHarness();
    const candidateDrift = await otherCandidate.run({
        fitnessClaims: { candidate_artifact_digest: selfModificationDigest('other-candidate') },
    });
    assert.equal(candidateDrift.ok, false);
    assert.equal(candidateDrift.reason, 'fitness_candidate_mismatch');
    assert.equal(otherCandidate.providerCalls(), 0);
});
test('refuses a candidate that edits the evaluator or admission control in the same action', async () => {
    for (const changedPath of [
        'evaluation/suite.yml',
        'packages/gate/src/autonomy-control-plane-profile.ts',
        '.github/workflows/self-modification-gate.yml',
    ]) {
        const harness = createSelfModificationHarness({ changedPaths: [changedPath] });
        const result = await harness.run();
        assert.equal(result.ok, false, changedPath);
        assert.equal(result.reason, 'control_plane_overlap', changedPath);
        assert.equal(harness.providerCalls(), 0, changedPath);
    }
});
test('a new operation id cannot promote the same exact candidate twice', async () => {
    const harness = createSelfModificationHarness();
    const first = await harness.run();
    assert.equal(first.outcome, 'executed');
    const replayAction = { ...harness.action, operation_id: 'promotion:retry:2' };
    const replay = await harness.run({
        action: replayAction,
        operationId: replayAction.operation_id,
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, 'action_already_committed');
    assert.equal(harness.providerCalls(), 1);
});
test('concurrent admissions still enter the promotion provider once', async () => {
    let releaseProvider;
    let signalEntered;
    const entered = new Promise((resolve) => { signalEntered = resolve; });
    const release = new Promise((resolve) => { releaseProvider = resolve; });
    const harness = createSelfModificationHarness({
        provider: async () => {
            signalEntered();
            await release;
            return { status: 'promoted' };
        },
    });
    const firstPromise = harness.run();
    await entered;
    const competingAction = { ...harness.action, operation_id: 'promotion:concurrent:2' };
    const competing = await harness.run({
        action: competingAction,
        operationId: competingAction.operation_id,
    });
    releaseProvider();
    const first = await firstPromise;
    assert.equal(first.outcome, 'executed');
    assert.equal(competing.ok, false);
    assert.equal(competing.reason, 'action_in_flight');
    assert.equal(harness.providerCalls(), 1);
});
test('a lost provider acknowledgement consumes the promotion budget and blocks blind retry', async () => {
    const harness = createSelfModificationHarness({
        provider: async () => {
            throw new Error('provider acknowledgement lost');
        },
    });
    const first = await harness.run();
    assert.equal(first.ok, false);
    assert.equal(first.outcome, 'indeterminate');
    assert.equal(first.reason, 'effect_indeterminate');
    assert.equal(harness.providerCalls(), 1);
    assert.equal(harness.capabilityState().consumed_amount, 1);
    const replayAction = { ...harness.action, operation_id: 'promotion:retry:after-timeout' };
    const replay = await harness.run({
        action: replayAction,
        operationId: replayAction.operation_id,
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, 'action_already_committed');
    assert.equal(harness.providerCalls(), 1);
});
