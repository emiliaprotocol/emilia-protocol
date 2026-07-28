#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { pathToFileURL } from 'node:url';
import {
  RELIANCE_RISK_BOOLEAN_FIELDS,
  RELIANCE_RISK_MODEL_VERSION,
  RELIANCE_RISK_OBLIGATIONS,
  enumerateRelianceRiskStates,
  evaluateRelianceRiskState,
  obligationHolds,
} from './reliance-risk-plane.model.mjs';

// The governed security-case verifier requires the runner to name every
// obligation literally. Keeping this executable map separate from the model
// declaration also makes drift between the model and runner fail closed.
const EXECUTED_OBLIGATIONS = Object.freeze({
  ProgramAcceptedBeforeReserve: true,
  AuthorizationRequired: true,
  ExposureCapacityRequired: true,
  ReservationRequiredBeforeInvoke: true,
  IndeterminateRemainsOpen: true,
  NoBlindRetryFromIndeterminate: true,
  IndependentReconcilerRequired: true,
  RefusalNeverAuthorizes: true,
  LossScheduleNeverAuthorizes: true,
  CoverageDoesNotProveCompleteness: true,
  TerminalStateNotSuperseded: true,
});

function governedObligations() {
  const executed = Object.keys(EXECUTED_OBLIGATIONS);
  if (JSON.stringify(executed) !== JSON.stringify(RELIANCE_RISK_OBLIGATIONS)) {
    throw new Error('risk-plane model and runner obligation sets differ');
  }
  return executed;
}

export function runRelianceRiskChecks() {
  const states = [...enumerateRelianceRiskStates()];
  const obligationNames = governedObligations();
  const obligations = Object.fromEntries(obligationNames.map((obligation) => {
    const soundCounterexample = states.find((state) => !obligationHolds(
      state, evaluateRelianceRiskState(state), obligation,
    ));
    const unsafeCounterexample = states.find((state) => {
      const sound = evaluateRelianceRiskState(state);
      const unsafe = evaluateRelianceRiskState(state, obligation);
      return obligationHolds(state, sound, obligation) && !obligationHolds(state, unsafe, obligation);
    });
    return [obligation, {
      verified: soundCounterexample === undefined,
      states_checked: states.length,
      counterexample: soundCounterexample ?? null,
      mutation_counterexample: unsafeCounterexample ?? null,
    }];
  }));
  const verified = obligationNames.every((name) => obligations[name].verified
    && obligations[name].counterexample === null && obligations[name].mutation_counterexample !== null);
  return {
    model: RELIANCE_RISK_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    domains: { states: states.length, independent_boolean_inputs: RELIANCE_RISK_BOOLEAN_FIELDS.length },
    assumptions: [
      'Program, authorization, status, signature, and reconciliation inputs are produced by their separately specified verifiers.',
      'Exposure reserve and aggregate-limit evaluation are one linearizable transaction.',
      'Reconciliation authority is authenticated independently of the origin and executor.',
      'Population completeness is external evidence and is never inferred from a reconciliation attestation.',
    ],
    limitations: [
      'Finite same-team bounded exploration, not an unbounded proof or implementation refinement proof.',
      'Database linearizability, cryptography, identity proofing, legal enforceability, solvency, causation, and payment are external.',
    ],
    obligations,
    verified,
  };
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  const result = runRelianceRiskChecks();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result));
  else {
    console.log(`${result.model}: ${result.verified ? 'PASS' : 'FAIL'}`);
    for (const name of governedObligations()) {
      const row = result.obligations[name];
      console.log(`${name}: ${row.verified ? 'verified' : 'FAILED'} (${row.states_checked} states; unsafe counterexample: ${row.mutation_counterexample ? 'found' : 'missing'})`);
    }
  }
  if (!result.verified) process.exitCode = 1;
}
