#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { pathToFileURL } from "node:url";
import {
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  commit,
  concurrentReserve,
  enumerateOwnerTransitions,
  enumerateReservationOrders,
  release,
  reservationOwner,
  reserve,
} from "./durable-consumption-owner.model.mjs";

function row(statesChecked, violation, mutationStatesChecked, mutation) {
  return {
    states_checked: statesChecked,
    mutation_states_checked: mutationStatesChecked,
    verified: violation === undefined,
    counterexample: violation ?? null,
    mutation_counterexample: mutation ?? null,
  };
}

function checkConcurrentReservation(orders) {
  const violation = orders.find((order) => {
    const result = concurrentReserve(order);
    return result.accepted.filter(Boolean).length !== 1;
  });
  let checked = 0;
  let mutation;
  for (const order of orders) {
    checked += 1;
    const result = concurrentReserve(order, { nonAtomicSnapshot: true });
    if (result.accepted.filter(Boolean).length > 1) {
      mutation = { order, result };
      break;
    }
  }
  return row(orders.length, violation, checked, mutation);
}

function checkOwner(transitions, operation, mutationFlag) {
  const apply = operation === "commit" ? commit : release;
  const violation = transitions.find(({ state, presenter }) => {
    const result = apply(state, presenter);
    return result.accepted && reservationOwner(state) !== presenter;
  });
  let checked = 0;
  let mutation;
  for (const entry of transitions) {
    checked += 1;
    const owner = reservationOwner(entry.state);
    const result = apply(entry.state, entry.presenter, {
      [mutationFlag]: true,
    });
    if (
      owner !== null &&
      entry.presenter !== owner &&
      result.accepted
    ) {
      mutation = { ...entry, owner, result };
      break;
    }
  }
  return row(transitions.length, violation, checked, mutation);
}

function checkRestart(transitions) {
  const relevant = transitions.filter(
    ({ state, presenter }) =>
      reservationOwner(state) !== null && presenter === "restarted-process",
  );
  const violation = relevant.find(
    ({ state, presenter }) =>
      commit(state, presenter).accepted || release(state, presenter).accepted,
  );
  const mutation = relevant
    .map((entry) => ({
      ...entry,
      commit: commit(entry.state, entry.presenter, {
        ignoreCommitOwner: true,
      }),
    }))
    .find((entry) => entry.commit.accepted);
  return row(relevant.length, violation, relevant.length, mutation);
}

function checkCommittedNeverReopens() {
  const sound = reserve("COMMITTED", "owner-a");
  const mutation = reserve("COMMITTED", "owner-a", {
    reopenCommitted: true,
  });
  return row(
    1,
    sound.accepted ? { state: "COMMITTED", result: sound } : undefined,
    1,
    mutation.accepted
      ? { state: "COMMITTED", owner: "owner-a", result: mutation }
      : undefined,
  );
}

export function runFormalChecks() {
  const transitions = [...enumerateOwnerTransitions()];
  const orders = [...enumerateReservationOrders()];
  const obligations = {
    AtMostOneConcurrentReservation: checkConcurrentReservation(orders),
    OnlyReservationOwnerMayCommit: checkOwner(
      transitions,
      "commit",
      "ignoreCommitOwner",
    ),
    OnlyReservationOwnerMayRelease: checkOwner(
      transitions,
      "release",
      "ignoreReleaseOwner",
    ),
    RestartCannotAdoptAbandonedReservation: checkRestart(transitions),
    CommittedConsumptionNeverReopens: checkCommittedNeverReopens(),
  };
  const verified = FORMAL_OBLIGATIONS.every((name) => {
    const result = obligations[name];
    return (
      result?.verified === true &&
      result.counterexample === null &&
      result.mutation_counterexample !== null
    );
  });
  return {
    model: FORMAL_MODEL_VERSION,
    method: "bounded_exhaustive_state_exploration",
    domains: {
      backend_states: 4,
      presenters: 3,
      reservation_orders: orders.length,
    },
    assumptions: [
      "The shared backend linearizes add-if-absent, compare-and-set, and conditional delete.",
      "Reservation tokens are unpredictable opaque values and are never reconstructed after restart.",
      "Abandoned reservations remain fenced until an authenticated reconciliation path resolves them.",
    ],
    obligations,
    verified,
    limitations: [
      "Finite same-team model of one key, two owners, and one restarted process.",
      "Backend durability and linearizability are acceptance roots, not established by this model.",
      "Business-level exactly-once effects still require downstream idempotency or reconciliation.",
    ],
  };
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  const result = runFormalChecks();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(result));
  } else {
    console.log(`${result.model}: ${result.verified ? "PASS" : "FAIL"}`);
    for (const name of FORMAL_OBLIGATIONS) {
      const obligation = result.obligations[name];
      console.log(
        `${name}: ${obligation.verified ? "verified" : "FAILED"} ` +
          `(${obligation.states_checked} states; mutation counterexample: ` +
          `${obligation.mutation_counterexample ? "found" : "missing"})`,
      );
    }
  }
  if (!result.verified) process.exitCode = 1;
}

