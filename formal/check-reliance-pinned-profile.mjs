#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic bounded checker for the pinned-profile reliance model.
 *
 * Every obligation must hold in the sound evaluator and must have a concrete
 * state that the corresponding one-leg unsafe evaluator admits.
 */

import { pathToFileURL } from "node:url";
import {
  BOOLEAN_STATE_FIELDS,
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  UNSAFE_RELIANCE_VARIANTS,
  enumerateRelianceStates,
  evaluateRelianceState,
  relianceRequirementSatisfied,
} from "./reliance-pinned-profile.model.mjs";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function checkObligation(states, obligation) {
  const violation = states.find((state) => {
    const result = evaluateRelianceState(state);
    return (
      result.accepted &&
      !relianceRequirementSatisfied(state, obligation)
    );
  });

  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const state of states) {
    mutationStatesChecked += 1;
    if (relianceRequirementSatisfied(state, obligation)) continue;
    const sound = evaluateRelianceState(state);
    const unsafe = evaluateRelianceState(
      state,
      UNSAFE_RELIANCE_VARIANTS[obligation],
    );
    if (!sound.accepted && unsafe.accepted) {
      mutationCounterexample = { state, sound, unsafe };
      break;
    }
  }

  return {
    states_checked: states.length,
    mutation_states_checked: mutationStatesChecked,
    verified: violation === undefined,
    counterexample: violation === undefined ? null : clone(violation),
    mutation_counterexample:
      mutationCounterexample === undefined
        ? null
        : clone(mutationCounterexample),
  };
}

const OBLIGATION_CHECKERS = Object.freeze({
  PinnedProfileRequired: checkObligation,
  SignedMaterialRequired: checkObligation,
  AssuranceRequired: checkObligation,
  OrganizationAuthorityRequired: checkObligation,
  ExactRegistryHeadRequired: checkObligation,
  RegistryEpochFloorOrdered: checkObligation,
  PolicyRequired: checkObligation,
  AuthenticatedRevocationRequired: checkObligation,
  FreshRevocationRequired: checkObligation,
  IssuerRequired: checkObligation,
  UnconsumedStateRequired: checkObligation,
});

export function runFormalChecks() {
  const states = [...enumerateRelianceStates()];
  const obligations = Object.fromEntries(
    FORMAL_OBLIGATIONS.map((obligation) => [
      obligation,
      OBLIGATION_CHECKERS[obligation](states, obligation),
    ]),
  );
  const verified = FORMAL_OBLIGATIONS.every((obligation) => {
    const row = obligations[obligation];
    return (
      row.verified === true &&
      row.counterexample === null &&
      row.mutation_counterexample !== null
    );
  });

  return {
    model: FORMAL_MODEL_VERSION,
    method: "bounded_exhaustive_state_exploration",
    domains: {
      states: states.length,
      independent_boolean_requirements: BOOLEAN_STATE_FIELDS.length,
      registry_epochs: 3,
      minimum_registry_epochs: 3,
    },
    assumptions: [
      "The relying party authenticates and pins the profile before evaluation.",
      "Each modeled Boolean is the result of its separately specified verifier, not a presenter assertion.",
      "Registry epochs are non-negative ordered integers and registry-head equality is exact.",
      "The unconsumed result comes from the relying party's atomic consumption domain.",
    ],
    obligations,
    verified,
    limitations: [
      "Finite same-team bounded exploration, not an unbounded protocol proof or implementation refinement proof.",
      "Cryptographic algorithms, parser behavior, policy authorship, clocks, registry availability, and database isolation are external.",
      "The model proves conjunction and refusal independence; it does not infer legal authority, human comprehension, or physical truth.",
    ],
  };
}

function printHuman(result) {
  console.log(`${result.model}: ${result.verified ? "PASS" : "FAIL"}`);
  for (const obligation of FORMAL_OBLIGATIONS) {
    const row = result.obligations[obligation];
    console.log(
      `${obligation}: ${row.verified ? "verified" : "FAILED"} ` +
        `(${row.states_checked} states; unsafe counterexample: ` +
        `${row.mutation_counterexample ? "found" : "missing"})`,
    );
  }
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  const result = runFormalChecks();
  if (process.argv.includes("--json")) console.log(JSON.stringify(result));
  else printHuman(result);
  if (!result.verified) process.exitCode = 1;
}
