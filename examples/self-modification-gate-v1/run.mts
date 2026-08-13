// SPDX-License-Identifier: Apache-2.0

import {
  createSelfModificationHarness,
  selfModificationDigest,
} from './scenario.mjs';

type CaseResult = { case_id: string; passed: boolean; error?: string };

async function runCase(caseId: string, run: () => Promise<boolean>): Promise<CaseResult> {
  try {
    return { case_id: caseId, passed: await run() };
  } catch (error) {
    return {
      case_id: caseId,
      passed: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

const cases: CaseResult[] = [];

cases.push(await runCase('SMG-01-exact-candidate-promoted', async () => {
  const harness = createSelfModificationHarness();
  const result = await harness.run();
  return result.ok === true
    && result.outcome === 'executed'
    && harness.providerCalls() === 1;
}));

cases.push(await runCase('SMG-02-candidate-substitution-refused', async () => {
  const harness = createSelfModificationHarness();
  const result = await harness.run({
    action: {
      ...harness.action,
      candidate_artifact_digest: selfModificationDigest('substituted-candidate'),
    },
  });
  return result.reason === 'action_binding_invalid'
    && harness.providerCalls() === 0;
}));

cases.push(await runCase('SMG-03-evaluator-epoch-drift-refused', async () => {
  const harness = createSelfModificationHarness();
  const result = await harness.run({
    fitnessClaims: { suite_digest: selfModificationDigest('different-evaluator-suite') },
  });
  return result.reason === 'fitness_suite_mismatch'
    && harness.providerCalls() === 0;
}));

cases.push(await runCase('SMG-04-control-plane-self-edit-refused', async () => {
  const harness = createSelfModificationHarness({
    changedPaths: ['packages/gate/src/autonomy-control-plane-profile.ts'],
  });
  const result = await harness.run();
  return result.reason === 'control_plane_overlap'
    && harness.providerCalls() === 0;
}));

cases.push(await runCase('SMG-05-fresh-operation-cannot-repromote-candidate', async () => {
  const harness = createSelfModificationHarness();
  const first = await harness.run();
  const retryAction = { ...harness.action, operation_id: 'promotion:retry:2' };
  const replay = await harness.run({
    action: retryAction,
    operationId: retryAction.operation_id,
  });
  return first.outcome === 'executed'
    && replay.reason === 'action_already_committed'
    && harness.providerCalls() === 1;
}));

cases.push(await runCase('SMG-06-lost-acknowledgement-is-indeterminate', async () => {
  const harness = createSelfModificationHarness({
    provider: async () => { throw new Error('provider acknowledgement lost'); },
  });
  const first = await harness.run();
  const retryAction = { ...harness.action, operation_id: 'promotion:retry:unknown-outcome' };
  const replay = await harness.run({
    action: retryAction,
    operationId: retryAction.operation_id,
  });
  return first.outcome === 'indeterminate'
    && first.reason === 'effect_indeterminate'
    && replay.reason === 'action_already_committed'
    && harness.providerCalls() === 1
    && harness.capabilityState().consumed_amount === 1;
}));

const report = {
  '@version': 'EMILIA-SELF-MODIFICATION-GATE-REPORT-v1',
  generated_at: '2026-08-12T19:00:00.000Z',
  claim_boundary: 'This local reference run demonstrates exact-candidate and evaluator-policy binding, control-plane separation, one admitted promotion attempt in one in-memory authority domain, and honest unknown-outcome handling. It is not an external reproduction, production deployment, evaluator-quality proof, or exactly-once physical-effect claim.',
  passed: cases.every((entry) => entry.passed),
  checks_passed: cases.filter((entry) => entry.passed).length,
  checks_total: cases.length,
  cases,
};

console.log(JSON.stringify(report, null, 2));
if (!report.passed) process.exitCode = 1;
