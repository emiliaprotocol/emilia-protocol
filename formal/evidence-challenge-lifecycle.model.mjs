// SPDX-License-Identifier: Apache-2.0
/**
 * EP-EVIDENCE-CHALLENGE-LIFECYCLE-BOUNDED-MODEL-v1
 *
 * Finite executable model of the standalone AE-CHALLENGE-v1 wire and state
 * lifecycle. It models the challenge as an evidence request, never as AEB/AEC
 * authorization. Registration binds the entire wire body before exposure;
 * restart preserves open and consumed state; the first structurally valid
 * attempt consumes even when its presentation is inadmissible.
 */

export const FORMAL_MODEL_VERSION =
  "EP-EVIDENCE-CHALLENGE-LIFECYCLE-BOUNDED-MODEL-v1";

export const REGISTRATION_OBLIGATIONS = Object.freeze([
  "DurableStorageRequired",
  "AtomicRegistrationRequired",
  "BodyBoundStorageRequired",
  "PermanentConsumptionRequired",
  "ExactActionDigestBound",
  "MissingEvidenceBound",
  "FreshnessPolicyContextBound",
  "ExpiryBound",
  "NonceBound",
  "PresentationMethodBound",
]);

export const LIFECYCLE_OBLIGATIONS = Object.freeze([
  "RegistrationPrecedesExposure",
  "RegistrationPersistsAcrossRestart",
  "ConcurrentRegistrationIsUnique",
  "FirstValidAttemptConsumes",
  "InvalidAttemptIsInert",
  "ConcurrentConsumptionIsOneTime",
  "ConsumedStatePersistsAcrossRestart",
]);

export const FORMAL_OBLIGATIONS = Object.freeze([
  ...REGISTRATION_OBLIGATIONS,
  ...LIFECYCLE_OBLIGATIONS,
]);

const REGISTRATION_FIELDS = Object.freeze({
  DurableStorageRequired: "durable_storage",
  AtomicRegistrationRequired: "atomic_registration",
  BodyBoundStorageRequired: "body_bound_storage",
  PermanentConsumptionRequired: "permanent_consumption",
  ExactActionDigestBound: "exact_action_digest",
  MissingEvidenceBound: "missing_evidence",
  FreshnessPolicyContextBound: "freshness_policy_context",
  ExpiryBound: "expiry",
  NonceBound: "nonce",
  PresentationMethodBound: "presentation_method",
});

export const CHALLENGE_CONFIGURATION_FIELDS = Object.freeze(
  Object.values(REGISTRATION_FIELDS),
);

export const SOUND_CHALLENGE_CONFIGURATION = Object.freeze(
  Object.fromEntries(
    CHALLENGE_CONFIGURATION_FIELDS.map((field) => [field, true]),
  ),
);

export const UNSAFE_CHALLENGE_VARIANTS = Object.freeze({
  ...Object.fromEntries(
    REGISTRATION_OBLIGATIONS.map((obligation) => [
      obligation,
      Object.freeze({ bypass_obligation: obligation }),
    ]),
  ),
  RegistrationPrecedesExposure: Object.freeze({
    expose_before_registration: true,
  }),
  RegistrationPersistsAcrossRestart: Object.freeze({
    drop_registration_on_restart: true,
  }),
  ConcurrentRegistrationIsUnique: Object.freeze({
    non_atomic_registration: true,
  }),
  FirstValidAttemptConsumes: Object.freeze({
    skip_first_valid_consumption: true,
  }),
  InvalidAttemptIsInert: Object.freeze({
    consume_invalid_attempt: true,
  }),
  ConcurrentConsumptionIsOneTime: Object.freeze({
    non_atomic_consumption: true,
  }),
  ConsumedStatePersistsAcrossRestart: Object.freeze({
    reopen_consumed_after_restart: true,
  }),
});

export function challengeRequirementSatisfied(input, obligation) {
  const field = REGISTRATION_FIELDS[obligation];
  if (!field) {
    throw new Error(`unknown challenge registration obligation: ${obligation}`);
  }
  return input[field] === true;
}

export function evaluateChallengeRegistration(input, semantics = {}) {
  const checks = Object.fromEntries(
    REGISTRATION_OBLIGATIONS.map((obligation) => [
      obligation,
      semantics.bypass_obligation === obligation
        ? true
        : challengeRequirementSatisfied(input, obligation),
    ]),
  );
  const failedObligation =
    REGISTRATION_OBLIGATIONS.find(
      (obligation) => checks[obligation] !== true,
    ) ?? null;
  const registered = failedObligation === null;
  return {
    accepted: registered,
    registered,
    exposed:
      registered || semantics.expose_before_registration === true,
    failed_obligation: failedObligation,
    checks,
  };
}

export function evaluateConcurrentRegistrations(input, semantics = {}) {
  const registration = evaluateChallengeRegistration(input, semantics);
  const winners = !registration.registered
    ? 0
    : semantics.non_atomic_registration === true
      ? 2
      : 1;
  return {
    ...registration,
    registration_winners: winners,
    unique_registration: winners <= 1,
  };
}

export function simulateChallengeLifecycle(
  input,
  {
    challenge_valid = true,
    presentation_admissible = true,
    restart_before_attempt = false,
    restart_after_attempt = false,
  } = {},
  semantics = {},
) {
  const registration = evaluateChallengeRegistration(input, semantics);
  let registered = registration.registered;
  let consumed = false;
  let evaluated = false;
  let accepted = false;

  if (
    restart_before_attempt &&
    semantics.drop_registration_on_restart === true
  ) {
    registered = false;
  }
  const registrationPersisted =
    !restart_before_attempt || registered === registration.registered;

  if (registration.exposed && registered) {
    if (!challenge_valid) {
      if (semantics.consume_invalid_attempt === true) consumed = true;
    } else {
      evaluated = true;
      if (semantics.skip_first_valid_consumption !== true) consumed = true;
      accepted = presentation_admissible;
    }
  }

  if (
    restart_after_attempt &&
    consumed &&
    semantics.reopen_consumed_after_restart === true
  ) {
    consumed = false;
  }

  return {
    registration,
    registered,
    exposed: registration.exposed,
    registration_persisted: registrationPersisted,
    challenge_valid,
    evaluated,
    accepted,
    consumed,
    replay_refused: consumed,
  };
}

export function evaluateConcurrentValidAttempts(input, semantics = {}) {
  const registration = evaluateChallengeRegistration(input, semantics);
  if (!registration.registered || !registration.exposed) {
    return {
      ...registration,
      admitted_attempts: 0,
      consumed: false,
      one_time: true,
    };
  }
  const admittedAttempts =
    semantics.non_atomic_consumption === true ? 2 : 1;
  return {
    ...registration,
    admitted_attempts: admittedAttempts,
    consumed: true,
    one_time: admittedAttempts <= 1,
  };
}

export function* enumerateChallengeConfigurations() {
  const combinations = 1 << CHALLENGE_CONFIGURATION_FIELDS.length;
  for (let mask = 0; mask < combinations; mask += 1) {
    yield Object.fromEntries(
      CHALLENGE_CONFIGURATION_FIELDS.map((field, index) => [
        field,
        (mask & (1 << index)) !== 0,
      ]),
    );
  }
}

export const MODEL_INTERNALS = Object.freeze({
  registrationFields: REGISTRATION_FIELDS,
});
