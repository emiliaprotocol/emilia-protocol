#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic bounded checker for AE-CHALLENGE-v1 durable registration,
 * exact-body binding, restart persistence, and first-valid-attempt consumption.
 */

import { pathToFileURL } from "node:url";
import {
  CHALLENGE_CONFIGURATION_FIELDS,
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  REGISTRATION_OBLIGATIONS,
  SOUND_CHALLENGE_CONFIGURATION,
  UNSAFE_CHALLENGE_VARIANTS,
  challengeRequirementSatisfied,
  enumerateChallengeConfigurations,
  evaluateChallengeRegistration,
  evaluateConcurrentRegistrations,
  evaluateConcurrentValidAttempts,
  simulateChallengeLifecycle,
} from "./evidence-challenge-lifecycle.model.mjs";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function row(
  statesChecked,
  mutationStatesChecked,
  violation,
  mutationCounterexample,
) {
  return {
    states_checked: statesChecked,
    mutation_states_checked: mutationStatesChecked,
    verified: violation === undefined,
    counterexample: violation === undefined ? null : clone(violation),
    mutation_counterexample:
      mutationCounterexample === undefined
        ? null
        : clone(mutationCounterexample),
  };
}

function checkRegistrationObligation(configurations, obligation) {
  const violation = configurations.find((configuration) => {
    const result = evaluateChallengeRegistration(configuration);
    return (
      result.registered &&
      !challengeRequirementSatisfied(configuration, obligation)
    );
  });
  let mutationStatesChecked = 0;
  let mutationCounterexample;
  for (const configuration of configurations) {
    mutationStatesChecked += 1;
    if (challengeRequirementSatisfied(configuration, obligation)) continue;
    const sound = evaluateChallengeRegistration(configuration);
    const unsafe = evaluateChallengeRegistration(
      configuration,
      UNSAFE_CHALLENGE_VARIANTS[obligation],
    );
    if (!sound.registered && unsafe.registered) {
      mutationCounterexample = { configuration, sound, unsafe };
      break;
    }
  }
  return row(
    configurations.length,
    mutationStatesChecked,
    violation,
    mutationCounterexample,
  );
}

function checkRegistrationBeforeExposure(configurations) {
  const violation = configurations.find((configuration) => {
    const result = evaluateChallengeRegistration(configuration);
    return result.exposed && !result.registered;
  });
  const hostile = {
    ...SOUND_CHALLENGE_CONFIGURATION,
    exact_action_digest: false,
  };
  const unsafe = evaluateChallengeRegistration(
    hostile,
    UNSAFE_CHALLENGE_VARIANTS.RegistrationPrecedesExposure,
  );
  return row(
    configurations.length,
    1,
    violation,
    unsafe.exposed && !unsafe.registered ? { hostile, unsafe } : undefined,
  );
}

function checkRestartPersistence() {
  const sound = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    { restart_before_attempt: true },
  );
  const unsafe = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    { restart_before_attempt: true },
    UNSAFE_CHALLENGE_VARIANTS.RegistrationPersistsAcrossRestart,
  );
  const violation =
    sound.registration_persisted && sound.evaluated
      ? undefined
      : { sound };
  const counterexample =
    !unsafe.registration_persisted && !unsafe.evaluated
      ? { sound, unsafe }
      : undefined;
  return row(1, 1, violation, counterexample);
}

function checkConcurrentRegistration() {
  const sound = evaluateConcurrentRegistrations(
    SOUND_CHALLENGE_CONFIGURATION,
  );
  const unsafe = evaluateConcurrentRegistrations(
    SOUND_CHALLENGE_CONFIGURATION,
    UNSAFE_CHALLENGE_VARIANTS.ConcurrentRegistrationIsUnique,
  );
  return row(
    1,
    1,
    sound.unique_registration ? undefined : { sound },
    !unsafe.unique_registration ? { sound, unsafe } : undefined,
  );
}

function checkFirstValidAttempt() {
  const options = {
    challenge_valid: true,
    presentation_admissible: false,
  };
  const sound = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
  );
  const unsafe = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
    UNSAFE_CHALLENGE_VARIANTS.FirstValidAttemptConsumes,
  );
  return row(
    1,
    1,
    sound.evaluated && sound.consumed ? undefined : { sound },
    unsafe.evaluated && !unsafe.consumed ? { sound, unsafe } : undefined,
  );
}

function checkInvalidAttempt() {
  const options = {
    challenge_valid: false,
    presentation_admissible: true,
  };
  const sound = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
  );
  const unsafe = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
    UNSAFE_CHALLENGE_VARIANTS.InvalidAttemptIsInert,
  );
  return row(
    1,
    1,
    !sound.evaluated && !sound.consumed ? undefined : { sound },
    unsafe.consumed ? { sound, unsafe } : undefined,
  );
}

function checkConcurrentConsumption() {
  const sound = evaluateConcurrentValidAttempts(
    SOUND_CHALLENGE_CONFIGURATION,
  );
  const unsafe = evaluateConcurrentValidAttempts(
    SOUND_CHALLENGE_CONFIGURATION,
    UNSAFE_CHALLENGE_VARIANTS.ConcurrentConsumptionIsOneTime,
  );
  return row(
    1,
    1,
    sound.one_time ? undefined : { sound },
    !unsafe.one_time ? { sound, unsafe } : undefined,
  );
}

function checkConsumedPersistence() {
  const options = {
    challenge_valid: true,
    presentation_admissible: true,
    restart_after_attempt: true,
  };
  const sound = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
  );
  const unsafe = simulateChallengeLifecycle(
    SOUND_CHALLENGE_CONFIGURATION,
    options,
    UNSAFE_CHALLENGE_VARIANTS.ConsumedStatePersistsAcrossRestart,
  );
  return row(
    1,
    1,
    sound.consumed && sound.replay_refused ? undefined : { sound },
    !unsafe.consumed && !unsafe.replay_refused
      ? { sound, unsafe }
      : undefined,
  );
}

const REGISTRATION_CHECKERS = Object.freeze({
  DurableStorageRequired: checkRegistrationObligation,
  AtomicRegistrationRequired: checkRegistrationObligation,
  BodyBoundStorageRequired: checkRegistrationObligation,
  PermanentConsumptionRequired: checkRegistrationObligation,
  ExactActionDigestBound: checkRegistrationObligation,
  MissingEvidenceBound: checkRegistrationObligation,
  FreshnessPolicyContextBound: checkRegistrationObligation,
  ExpiryBound: checkRegistrationObligation,
  NonceBound: checkRegistrationObligation,
  PresentationMethodBound: checkRegistrationObligation,
});

const LIFECYCLE_CHECKERS = Object.freeze({
  RegistrationPrecedesExposure: checkRegistrationBeforeExposure,
  RegistrationPersistsAcrossRestart: checkRestartPersistence,
  ConcurrentRegistrationIsUnique: checkConcurrentRegistration,
  FirstValidAttemptConsumes: checkFirstValidAttempt,
  InvalidAttemptIsInert: checkInvalidAttempt,
  ConcurrentConsumptionIsOneTime: checkConcurrentConsumption,
  ConsumedStatePersistsAcrossRestart: checkConsumedPersistence,
});

export function runFormalChecks() {
  const configurations = [...enumerateChallengeConfigurations()];
  const obligations = Object.fromEntries(
    REGISTRATION_OBLIGATIONS.map((obligation) => [
      obligation,
      REGISTRATION_CHECKERS[obligation](configurations, obligation),
    ]),
  );
  for (const [obligation, checker] of Object.entries(LIFECYCLE_CHECKERS)) {
    obligations[obligation] = checker(configurations);
  }

  const verified = FORMAL_OBLIGATIONS.every((obligation) => {
    const result = obligations[obligation];
    return (
      result.verified === true &&
      result.counterexample === null &&
      result.mutation_counterexample !== null
    );
  });

  return {
    model: FORMAL_MODEL_VERSION,
    method: "bounded_exhaustive_state_exploration",
    domains: {
      challenge_configurations: configurations.length,
      independently_varied_configuration_fields:
        CHALLENGE_CONFIGURATION_FIELDS.length,
      concurrent_registration_workers: 2,
      concurrent_presentation_workers: 2,
      process_restarts: 2,
    },
    assumptions: [
      "The backend capability flags truthfully describe one shared storage domain.",
      "Atomic registration is insert-if-absent and atomic consumption is compare-and-set over the exact body digest.",
      "A valid attempt means the challenge structure, policy context, audience, and expiry already passed before consumption.",
      "Presentation admissibility is evaluated only after the valid challenge is consumed.",
    ],
    obligations,
    verified,
    limitations: [
      "Finite same-team bounded exploration, not an unbounded protocol proof or implementation refinement proof.",
      "Storage-driver correctness, crash recovery, clocks, canonical hashing, and policy-verifier correctness remain executable or deployment evidence.",
      "AE-CHALLENGE-v1 requests evidence; it does not authorize, reserve, or promise execution.",
    ],
  };
}

function printHuman(result) {
  console.log(`${result.model}: ${result.verified ? "PASS" : "FAIL"}`);
  for (const obligation of FORMAL_OBLIGATIONS) {
    const resultRow = result.obligations[obligation];
    console.log(
      `${obligation}: ${resultRow.verified ? "verified" : "FAILED"} ` +
        `(${resultRow.states_checked} states; unsafe counterexample: ` +
        `${resultRow.mutation_counterexample ? "found" : "missing"})`,
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
