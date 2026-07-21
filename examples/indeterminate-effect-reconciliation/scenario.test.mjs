// SPDX-License-Identifier: Apache-2.0
// Generated from scenario.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { createIndeterminateEffectHarness, runIndeterminateEffectDemo, } from './scenario.mts';
test('committed provider effect is not replayed after its response is lost', async () => {
    const result = await runIndeterminateEffectDemo();
    assert.equal(result.first_attempt.ok, false);
    assert.equal(result.first_attempt.reason, 'effect_indeterminate');
    assert.deepEqual(result.capability_operation, {
        status: 'committed',
        outcome: 'indeterminate',
        amount: 25_000,
        currency: 'USD',
        action_digest: result.provider.action_digest,
    });
    assert.equal(result.retry.ok, false);
    assert.equal(result.retry.reason, 'operation_already_committed');
    assert.equal(result.provider.execution_attempts, 1);
    assert.equal(result.provider.committed_effects, 1);
    assert.equal(result.reconciliation.ok, true);
    assert.equal(result.reconciliation.outcome, 'executed');
    assert.equal(result.reconciliation.authenticated_provider_evidence, true);
    assert.equal(result.reconciliation.reexecuted, false);
    assert.equal(result.reconciliation.action_digest, result.provider.action_digest);
    assert.match(result.reconciliation.provider_evidence_digest, /^sha256:[0-9a-f]{64}$/);
    assert.match(result.reconciliation.record_digest, /^sha256:[0-9a-f]{64}$/);
});
test('tampered provider evidence cannot reconcile an indeterminate operation', async () => {
    const harness = createIndeterminateEffectHarness();
    await harness.attempt();
    const evidence = harness.provider.getSignedEvidence(harness.operationId);
    evidence.body.effect.amount = 99_999_999;
    await assert.rejects(() => harness.reconcile(evidence), /capability_reconciliation_evidence_rejected/);
    assert.equal(harness.reconciliationLedger.get(harness.operationId), null);
    assert.equal(harness.provider.executionAttempts, 1);
});
test('provider evidence for another action is refused even when authentically signed', async () => {
    const harness = createIndeterminateEffectHarness();
    await harness.attempt();
    const wrongActionEvidence = harness.provider.signEvidence({
        operationId: harness.operationId,
        action: {
            ...harness.action,
            destination: 'acct:attacker',
        },
    });
    await assert.rejects(() => harness.reconcile(wrongActionEvidence), /capability_reconciliation_evidence_rejected/);
    assert.equal(harness.reconciliationLedger.get(harness.operationId), null);
    assert.equal(harness.provider.executionAttempts, 1);
});
