#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { pathToFileURL } from 'node:url';

import {
  BOUNDARY_DOMAINS,
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  evaluateBoundary,
} from './aec_execution_fleet_assurance.model.mjs';
import { UNSAFE_COMPARISONS } from './aec_execution_fleet_assurance.unsafe.mjs';

function counterexample(input, evaluation) {
  return {
    input: structuredClone(input),
    observation: structuredClone(evaluation.observation),
    trace: [...evaluation.trace],
  };
}

function checkObligation(name) {
  const domain = BOUNDARY_DOMAINS[name];
  const unsafe = UNSAFE_COMPARISONS[name];
  if (!Array.isArray(domain) || domain.length === 0) {
    throw new Error(`bounded domain is missing for ${name}`);
  }
  if (!unsafe?.mutation || !unsafe?.semantics) {
    throw new Error(`unsafe comparison is missing for ${name}`);
  }

  let violation = null;
  for (const input of domain) {
    const evaluation = evaluateBoundary(name, input);
    if (!evaluation.safe) {
      violation = counterexample(input, evaluation);
      break;
    }
  }

  let unsafeStatesChecked = 0;
  let unsafeCounterexample = null;
  for (const input of domain) {
    unsafeStatesChecked += 1;
    const evaluation = evaluateBoundary(name, input, unsafe.semantics);
    if (!evaluation.safe) {
      unsafeCounterexample = counterexample(input, evaluation);
      break;
    }
  }

  return {
    states_checked: domain.length,
    mutation_states_checked: unsafeStatesChecked,
    verified: violation === null,
    counterexample: violation,
    mutation_counterexample: unsafeCounterexample,
    unsafe: {
      mutation: unsafe.mutation,
      states_checked: unsafeStatesChecked,
      counterexample: unsafeCounterexample,
    },
  };
}

const OBLIGATION_EXECUTORS = Object.freeze({
  ConstructorTrustInputsImmutable: checkObligation,
  VerifierMethodCaptured: checkObligation,
  TransactionScopedTrustRefused: checkObligation,
  CanonicalActionKeyOnly: checkObligation,
  ReservationOwnerFenced: checkObligation,
  ReservationNeverExpires: checkObligation,
  SharedHeadAppendAtomic: checkObligation,
  EvidenceReadbackAcknowledgementExact: checkObligation,
  ResponseLossFreezesReplay: checkObligation,
  ReplicasShareConsumptionDomain: checkObligation,
  RestartCannotAdoptReservation: checkObligation,
  ReservationFailureCannotExecute: checkObligation,
  ProviderExecutionAtMostOnce: checkObligation,
});

export function runAecExecutionFleetAssuranceChecks() {
  const obligations = Object.fromEntries(
    FORMAL_OBLIGATIONS.map((name) => [
      name,
      OBLIGATION_EXECUTORS[name](name),
    ]),
  );
  const mutationsExposed = FORMAL_OBLIGATIONS.filter(
    (name) => obligations[name].unsafe.counterexample !== null,
  ).length;
  const verified = FORMAL_OBLIGATIONS.every((name) => (
    obligations[name].verified === true
    && obligations[name].counterexample === null
    && obligations[name].unsafe.counterexample !== null
  ));

  return {
    model: FORMAL_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    domains: Object.fromEntries(
      FORMAL_OBLIGATIONS.map((name) => [name, BOUNDARY_DOMAINS[name].length]),
    ),
    assumptions: [
      'All consequential provider paths are mediated by the AEC execution gate.',
      'The shared consumption backend linearizes add-if-absent and conditional owner-fenced transitions.',
      'The shared evidence backend linearizes compare-and-append for one stream head and returns truthful durable readback.',
      'The canonical action digest uniquely identifies one intended effect instance.',
    ],
    obligations,
    unsafe_comparison: {
      mutations_checked: FORMAL_OBLIGATIONS.length,
      mutations_exposed: mutationsExposed,
    },
    verified,
    limitations: [
      'Finite same-team model over two trust values, two owners, two replicas, one restart, and bounded retry patterns.',
      'This model does not establish backend durability, provider truth, cryptographic security, or database linearizability.',
      'At-most-once provider entry is not business-level exactly-once effect; indeterminate outcomes still require authenticated reconciliation.',
      'The model-to-runtime scenarios are selected deterministic traces, not a mechanized implementation refinement proof.',
    ],
  };
}

const invokedAsScript =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedAsScript) {
  const result = runAecExecutionFleetAssuranceChecks();
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(result));
  } else {
    console.log(`${result.model}: ${result.verified ? 'PASS' : 'FAIL'}`);
    for (const name of FORMAL_OBLIGATIONS) {
      const obligation = result.obligations[name];
      console.log(
        `${name}: ${obligation.verified ? 'verified' : 'FAILED'} `
        + `(${obligation.states_checked} states; unsafe counterexample: `
        + `${obligation.unsafe.counterexample ? 'found' : 'missing'})`,
      );
    }
  }
  if (!result.verified) process.exitCode = 1;
}
