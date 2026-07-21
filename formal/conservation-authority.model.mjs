// SPDX-License-Identifier: Apache-2.0
/**
 * EP-CONSERVATION-OF-AUTHORITY-BOUNDED-MODEL-v1
 *
 * Finite executable abstraction of two different conservation questions:
 *
 * 1. Path non-amplification: every delegated capability narrows each authority
 *    dimension relative to its direct parent.
 * 2. Aggregate branch conservation: explicit sibling allocations and their
 *    reservations remain within an authoritative parent allocation ledger.
 *
 * Authority is intentionally not collapsed into a scalar. Action selectors and
 * audiences are sets; spend and call limits are separate budget dimensions;
 * expiry is an ordered bound. Aggregate conservation is meaningful only under
 * the stated authoritative-allocation and atomic-reservation assumptions.
 */

export const FORMAL_MODEL_VERSION = 'EP-CONSERVATION-OF-AUTHORITY-BOUNDED-MODEL-v1';

export const FORMAL_OBLIGATIONS = Object.freeze([
  'DelegationPathAuthorityNeverAmplifies',
  'AggregateBranchBudgetIsConserved',
  'AuthoritativeAllocationIsRequired',
  'ConcurrentReservationsAreAtomic',
]);

export const RESOURCE_DIMENSIONS = Object.freeze(['cents', 'calls']);
export const ACTION_UNIVERSE = Object.freeze(['inspect', 'release']);
export const AUDIENCE_UNIVERSE = Object.freeze(['merchant-a', 'merchant-b']);

const LIMITS = Object.freeze([0, 1, 2]);

function subsets(values) {
  const result = [];
  for (let mask = 0; mask < (1 << values.length); mask += 1) {
    result.push(values.filter((_, index) => (mask & (1 << index)) !== 0));
  }
  return result;
}

const ACTION_SETS = Object.freeze(subsets(ACTION_UNIVERSE));
const AUDIENCE_SETS = Object.freeze(subsets(AUDIENCE_UNIVERSE));

export function setContained(child, parent) {
  return child.every((value) => parent.includes(value));
}

export function vectorWithin(candidate, ceiling) {
  return RESOURCE_DIMENSIONS.every((dimension) => candidate[dimension] <= ceiling[dimension]);
}

export function addVectors(...vectors) {
  return Object.fromEntries(RESOURCE_DIMENSIONS.map((dimension) => [
    dimension,
    vectors.reduce((total, vector) => total + vector[dimension], 0),
  ]));
}

export function authorityContained(child, parent) {
  return setContained(child.actions, parent.actions)
    && setContained(child.audiences, parent.audiences)
    && vectorWithin(child.budget, parent.budget)
    && child.expires_at_step <= parent.expires_at_step;
}

function delegationEdgeAccepted(parent, child, semantics = {}) {
  const selectorsContained = semantics.ignoreSelectorContainment === true
    ? true
    : setContained(child.actions, parent.actions)
      && setContained(child.audiences, parent.audiences);
  return selectorsContained
    && vectorWithin(child.budget, parent.budget)
    && child.expires_at_step <= parent.expires_at_step;
}

export function evaluateDelegationPath(state, semantics = {}) {
  const accepted = delegationEdgeAccepted(state.root, state.branch, semantics)
    && delegationEdgeAccepted(state.branch, state.leaf, semantics);
  return {
    accepted,
    path_contained: authorityContained(state.branch, state.root)
      && authorityContained(state.leaf, state.branch),
  };
}

export function evaluateBranchAllocation(state, semantics = {}) {
  const allocationAuthoritative = semantics.trustUnpinnedAllocation === true
    ? true
    : state.allocation_epoch_matches_authority;
  const eachAllocationWithinParent = state.allocations.every((allocation) => (
    vectorWithin(allocation, state.parent_budget)
  ));
  const allocationTotal = addVectors(...state.allocations);
  const aggregateWithinParent = semantics.ignoreAggregateSiblingBudget === true
    ? true
    : vectorWithin(allocationTotal, state.parent_budget);
  const reservationsWithinAllocations = state.reservations.every((reservation, index) => (
    vectorWithin(reservation, state.allocations[index])
  ));
  return {
    accepted: allocationAuthoritative
      && eachAllocationWithinParent
      && aggregateWithinParent
      && reservationsWithinAllocations,
    allocation_authoritative: state.allocation_epoch_matches_authority,
    aggregate_within_parent: vectorWithin(allocationTotal, state.parent_budget),
    reservations_within_allocations: reservationsWithinAllocations,
    allocation_total: allocationTotal,
  };
}

function reserveAtomically(allocation, committed, requests) {
  let current = { ...committed };
  const accepted = [];
  for (const request of requests) {
    const candidate = addVectors(current, request);
    const permitted = vectorWithin(candidate, allocation);
    accepted.push(permitted);
    if (permitted) current = candidate;
  }
  return { accepted, committed: current };
}

function reserveFromStaleSnapshot(allocation, committed, requests) {
  const accepted = requests.map((request) => vectorWithin(addVectors(committed, request), allocation));
  const acceptedRequests = requests.filter((_, index) => accepted[index]);
  return {
    accepted,
    committed: addVectors(committed, ...acceptedRequests),
  };
}

export function evaluateConcurrentReservation(state, semantics = {}) {
  if (!state.allocation_epoch_matches_authority || !vectorWithin(state.committed, state.allocation)) {
    return {
      accepted: false,
      allocation_authoritative: state.allocation_epoch_matches_authority,
      committed: { ...state.committed },
      committed_within_allocation: vectorWithin(state.committed, state.allocation),
      request_results: [false, false],
    };
  }
  const result = semantics.nonAtomicSnapshot === true
    ? reserveFromStaleSnapshot(state.allocation, state.committed, state.requests)
    : reserveAtomically(state.allocation, state.committed, state.requests);
  return {
    accepted: true,
    allocation_authoritative: true,
    committed: result.committed,
    committed_within_allocation: vectorWithin(result.committed, state.allocation),
    request_results: result.accepted,
  };
}

function* vectors() {
  for (const cents of LIMITS) {
    for (const calls of LIMITS) yield { cents, calls };
  }
}

function* capabilities() {
  for (const actions of ACTION_SETS) {
    for (const audiences of AUDIENCE_SETS) {
      for (const budget of vectors()) {
        for (const expires_at_step of LIMITS) {
          yield { actions, audiences, budget, expires_at_step };
        }
      }
    }
  }
}

export function* enumerateDelegationPaths() {
  const root = {
    actions: [...ACTION_UNIVERSE],
    audiences: [...AUDIENCE_UNIVERSE],
    budget: { cents: 2, calls: 2 },
    expires_at_step: 2,
  };
  const domain = [...capabilities()];
  for (const branch of domain) {
    for (const leaf of domain) yield { root, branch, leaf };
  }
}

export function* enumerateBranchAllocationStates() {
  const domain = [...vectors()];
  for (const parent_budget of domain) {
    for (const allocationA of domain) {
      for (const allocationB of domain) {
        for (const reservationA of domain) {
          for (const reservationB of domain) {
            for (const allocation_epoch_matches_authority of [false, true]) {
              yield {
                parent_budget,
                allocations: [allocationA, allocationB],
                reservations: [reservationA, reservationB],
                allocation_epoch_matches_authority,
              };
            }
          }
        }
      }
    }
  }
}

export function* enumerateConcurrentReservationStates() {
  const domain = [...vectors()];
  for (const allocation of domain) {
    for (const committed of domain) {
      for (const requestA of domain) {
        for (const requestB of domain) {
          for (const allocation_epoch_matches_authority of [false, true]) {
            yield {
              allocation,
              committed,
              requests: [requestA, requestB],
              allocation_epoch_matches_authority,
            };
          }
        }
      }
    }
  }
}

export const MODEL_INTERNALS = Object.freeze({
  resourceDimensions: RESOURCE_DIMENSIONS,
  limits: LIMITS,
});
