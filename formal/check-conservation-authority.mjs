#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic bounded exhaustive checker for Conservation of Authority.
 * Each obligation is paired with one deliberately weakened implementation;
 * verification requires the sound model to hold and the mutant to produce a
 * concrete counterexample.
 */
import { pathToFileURL } from 'node:url';
import {
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  enumerateBranchAllocationStates,
  enumerateConcurrentReservationStates,
  enumerateDelegationPaths,
  evaluateBranchAllocation,
  evaluateConcurrentReservation,
  evaluateDelegationPath,
} from './conservation-authority.model.mjs';

function witness(entry, detail = undefined) {
  if (!entry) return null;
  return JSON.parse(JSON.stringify(detail === undefined ? entry : { state: entry, detail }));
}

function resultRow(statesChecked, mutationStatesChecked, violation, mutationCounterexample) {
  return {
    states_checked: statesChecked,
    mutation_states_checked: mutationStatesChecked,
    verified: violation === undefined,
    counterexample: witness(violation),
    mutation_counterexample: witness(mutationCounterexample),
  };
}

function checkDelegationPath(paths) {
  const violation = paths.find((state) => {
    const result = evaluateDelegationPath(state);
    return result.accepted && !result.path_contained;
  });
  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const state of paths) {
    mutationStatesChecked += 1;
    const result = evaluateDelegationPath(state, { ignoreSelectorContainment: true });
    if (result.accepted && !result.path_contained) {
      mutationCounterexample = state;
      break;
    }
  }
  return resultRow(paths.length, mutationStatesChecked, violation, mutationCounterexample);
}

function checkAggregateBranchBudget(states) {
  const violation = states.find((state) => {
    const result = evaluateBranchAllocation(state);
    return result.accepted
      && (!result.aggregate_within_parent || !result.reservations_within_allocations);
  });
  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const state of states) {
    mutationStatesChecked += 1;
    const result = evaluateBranchAllocation(state, { ignoreAggregateSiblingBudget: true });
    if (result.accepted && !result.aggregate_within_parent) {
      mutationCounterexample = state;
      break;
    }
  }
  return resultRow(states.length, mutationStatesChecked, violation, mutationCounterexample);
}

function checkAuthoritativeAllocation(states) {
  const violation = states.find((state) => (
    evaluateBranchAllocation(state).accepted && !state.allocation_epoch_matches_authority
  ));
  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const state of states) {
    mutationStatesChecked += 1;
    const materialAllocation = state.allocations.some((allocation) => (
      allocation.cents > 0 || allocation.calls > 0
    ));
    if (!state.allocation_epoch_matches_authority
        && materialAllocation
        && evaluateBranchAllocation(state, { trustUnpinnedAllocation: true }).accepted) {
      mutationCounterexample = state;
      break;
    }
  }
  return resultRow(states.length, mutationStatesChecked, violation, mutationCounterexample);
}

function checkAtomicReservations(states) {
  const violation = states.find((state) => {
    const result = evaluateConcurrentReservation(state);
    return result.accepted && !result.committed_within_allocation;
  });
  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const state of states) {
    mutationStatesChecked += 1;
    const result = evaluateConcurrentReservation(state, { nonAtomicSnapshot: true });
    if (result.accepted && !result.committed_within_allocation) {
      mutationCounterexample = state;
      break;
    }
  }
  return resultRow(states.length, mutationStatesChecked, violation, mutationCounterexample);
}

export function runFormalChecks() {
  const delegationPaths = [...enumerateDelegationPaths()];
  const branchAllocationStates = [...enumerateBranchAllocationStates()];
  const concurrentReservationStates = [...enumerateConcurrentReservationStates()];
  const obligations = {
    DelegationPathAuthorityNeverAmplifies: checkDelegationPath(delegationPaths),
    AggregateBranchBudgetIsConserved: checkAggregateBranchBudget(branchAllocationStates),
    AuthoritativeAllocationIsRequired: checkAuthoritativeAllocation(branchAllocationStates),
    ConcurrentReservationsAreAtomic: checkAtomicReservations(concurrentReservationStates),
  };
  const complete = FORMAL_OBLIGATIONS.every((obligationName) => obligations[obligationName]);
  const verified = complete && Object.values(obligations).every((row) => (
    row.verified === true
    && row.counterexample === null
    && row.mutation_counterexample !== null
  ));
  return {
    model: FORMAL_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    domains: {
      delegation_paths: delegationPaths.length,
      branch_allocation_states: branchAllocationStates.length,
      concurrent_reservation_states: concurrentReservationStates.length,
      budget_dimensions: 2,
    },
    assumptions: [
      'Delegation is accepted only from the direct parent capability resolved by the relying party.',
      'Sibling allocations come from one authoritative, epoch-pinned parent allocation ledger.',
      'Reservations are committed by an atomic compare-and-update operation against that ledger.',
      'Action and audience equality are exact; expiry order and each budget dimension are authenticated inputs.',
    ],
    obligations,
    verified,
    limitations: [
      'Finite same-team bounded exploration, not an unbounded protocol proof.',
      'The model contains two actions, two audiences, two budget dimensions, two sibling branches, and limits from zero through two.',
      'No cryptographic break, registry compromise, database isolation failure, or physical-world truth is modeled.',
      'Path containment and aggregate sibling conservation are separate properties and must not be combined into a scalar authority score.',
    ],
  };
}

function printHuman(result) {
  console.log(`${result.model}: ${result.verified ? 'PASS' : 'FAIL'}`);
  for (const obligationName of FORMAL_OBLIGATIONS) {
    const row = result.obligations[obligationName];
    console.log(
      `${obligationName}: ${row.verified ? 'verified' : 'FAILED'} `
      + `(${row.states_checked} states; mutation counterexample: `
      + `${row.mutation_counterexample ? 'found' : 'missing'})`,
    );
  }
}

const invokedAsScript = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  const result = runFormalChecks();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result));
  else printHuman(result);
  if (!result.verified) process.exitCode = 1;
}
