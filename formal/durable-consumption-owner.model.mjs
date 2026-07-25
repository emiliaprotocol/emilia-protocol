// SPDX-License-Identifier: Apache-2.0
/**
 * EP-DURABLE-CONSUMPTION-OWNER-BOUNDED-MODEL-v1
 *
 * Finite same-team model of one replay-defense key shared by two workers and
 * one restarted process. The backend compare-and-set primitive is abstracted
 * as atomic; the model checks the ownership and terminal-state obligations
 * that the Gate builds on top of that acceptance root.
 */

export const FORMAL_MODEL_VERSION =
  "EP-DURABLE-CONSUMPTION-OWNER-BOUNDED-MODEL-v1";

export const FORMAL_OBLIGATIONS = Object.freeze([
  "AtMostOneConcurrentReservation",
  "OnlyReservationOwnerMayCommit",
  "OnlyReservationOwnerMayRelease",
  "RestartCannotAdoptAbandonedReservation",
  "CommittedConsumptionNeverReopens",
]);

export const OWNERS = Object.freeze(["owner-a", "owner-b"]);
export const PRESENTERS = Object.freeze([...OWNERS, "restarted-process"]);
export const BACKEND_STATES = Object.freeze([
  "AVAILABLE",
  "RESERVED_OWNER_A",
  "RESERVED_OWNER_B",
  "COMMITTED",
]);

function reservationState(owner) {
  return owner === "owner-a" ? "RESERVED_OWNER_A" : "RESERVED_OWNER_B";
}

export function reservationOwner(state) {
  if (state === "RESERVED_OWNER_A") return "owner-a";
  if (state === "RESERVED_OWNER_B") return "owner-b";
  return null;
}

export function reserve(state, owner, semantics = {}) {
  const accepted =
    state === "AVAILABLE" ||
    (semantics.reopenCommitted === true && state === "COMMITTED");
  return {
    accepted,
    state: accepted ? reservationState(owner) : state,
  };
}

export function commit(state, presenter, semantics = {}) {
  const owner = reservationOwner(state);
  const accepted =
    owner !== null &&
    (presenter === owner || semantics.ignoreCommitOwner === true);
  return { accepted, state: accepted ? "COMMITTED" : state };
}

export function release(state, presenter, semantics = {}) {
  const owner = reservationOwner(state);
  const accepted =
    owner !== null &&
    (presenter === owner || semantics.ignoreReleaseOwner === true);
  return { accepted, state: accepted ? "AVAILABLE" : state };
}

export function concurrentReserve(order, semantics = {}) {
  let state = "AVAILABLE";
  const accepted = [];
  for (const owner of order) {
    const result =
      semantics.nonAtomicSnapshot === true
        ? { accepted: true, state: reservationState(owner) }
        : reserve(state, owner);
    accepted.push(result.accepted);
    state = result.state;
  }
  return { accepted, state };
}

export function* enumerateOwnerTransitions() {
  for (const state of BACKEND_STATES) {
    for (const presenter of PRESENTERS) {
      yield { state, presenter };
    }
  }
}

export function* enumerateReservationOrders() {
  yield ["owner-a", "owner-b"];
  yield ["owner-b", "owner-a"];
}

