#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { pathToFileURL } from 'node:url';
import {
  CAP_BUCKETS,
  CLAIM_RESULTS,
  FORMAL_MODEL_VERSION,
  claimAndReserve,
  claimBeforeCapacity,
  claimWithDoubleCountedOutstanding,
  claimWithRecomputedBuckets,
  claimWithExpiryFirst,
  finalizeReservation,
  initialState,
  presenterMatchesAudience,
  registerOutstanding,
  replayKey,
  retryWindowValid,
  twoIndependentShardClaims,
  twoConcurrentDuplicatesSound,
  twoConcurrentDuplicatesSplit,
  withinCaps,
} from './evidence-challenge-claim-capacity.model.mjs';

function invariant(condition, message) {
  if (!condition) throw new Error(`${FORMAL_MODEL_VERSION}: ${message}`);
}

function checkedProperty(states_checked, mutation_counterexample) {
  return {
    states_checked,
    mutation_states_checked: 1,
    checked: true,
    verified: false,
    claim_boundary: 'finite same-team scenarios only; not a proof of arbitrary executions or storage refinement',
    mutation_counterexample,
  };
}

function values(cap) {
  return Array.from({ length: cap + 1 }, (_, index) => index);
}

function vectors(cap) {
  const result = [];
  for (const aggregate of values(cap)) {
    for (const presenter of values(cap)) {
      for (const audience of values(cap)) {
        for (const tenant of values(cap)) {
          result.push({ aggregate, presenter, audience, tenant });
        }
      }
    }
  }
  return result;
}

function allBucketsEqual(vector, expected) {
  return CAP_BUCKETS.every((bucket) => vector[bucket] === expected);
}

export function runClaimCapacityChecks() {
  const unitVector = Object.fromEntries(CAP_BUCKETS.map((bucket) => [bucket, 1]));
  const base = {
    issuer: 'https://issuer.example',
    nonce: 'nonce-128-bits-or-more',
    body_digest: 'sha256:body-a',
    units: unitVector,
    now_ms: 1_000,
    expires_at_ms: 2_000,
  };
  let states = 0;
  const mutations = [];

  for (const cap of [1, 2]) {
    for (const used of vectors(cap)) {
      states += 1;
      const state = initialState({ cap, used });
      const result = claimAndReserve(state, base);
      invariant(withinCaps(result.state), 'sound transition exceeded a cap bucket');
      const fullBucket = CAP_BUCKETS.some((bucket) => used[bucket] === cap);
      if (fullBucket) {
        invariant(result.result === CLAIM_RESULTS.CAPACITY, 'full bucket did not refuse');
        invariant(result.state.replay.size === 0, 'capacity refusal burned the nonce');
      } else {
        invariant(result.result === CLAIM_RESULTS.CLAIMED, 'available capacity did not claim');
        invariant(result.state.replay.size === 1, 'claim did not bind replay state');
      }
    }
  }

  const duplicate = twoConcurrentDuplicatesSound(base, initialState({ cap: 1 }));
  invariant(duplicate.first.result === CLAIM_RESULTS.CLAIMED, 'first duplicate did not claim');
  invariant(duplicate.second.result === CLAIM_RESULTS.REPLAY, 'second duplicate was not replay');
  invariant(allBucketsEqual(duplicate.state.used, 1), 'duplicate presentation reserved a bucket twice');

  const conflicting = claimAndReserve(duplicate.state, {
    ...base,
    body_digest: 'sha256:body-b',
  });
  invariant(conflicting.result === CLAIM_RESULTS.COLLISION, 'same nonce with another body was not a collision');
  invariant(allBucketsEqual(conflicting.state.used, 1), 'body collision changed capacity');

  const unavailable = claimAndReserve(initialState({ cap: 1 }), {
    ...base,
    owner_result_certain: false,
  });
  const possibleStates = unavailable.possible_states ?? [];
  invariant(unavailable.result === CLAIM_RESULTS.UNAVAILABLE, 'uncertain owner result was classified as a verdict');
  invariant(possibleStates.length === 2, 'uncertain result did not preserve both authoritative possibilities');
  invariant(possibleStates.every(withinCaps), 'uncertain result admitted an over-cap authoritative state');

  const expired = claimAndReserve(initialState({ cap: 1 }), {
    ...base,
    now_ms: 2_000,
  });
  invariant(expired.result === CLAIM_RESULTS.EXPIRED, 'expired challenge did not receive the closed expired result');
  invariant(expired.state.replay.size === 0 && allBucketsEqual(expired.state.used, 0), 'expired challenge claimed or reserved state');

  const replayAfterExpiry = claimAndReserve(duplicate.state, {
    ...base,
    now_ms: 2_000,
  });
  invariant(replayAfterExpiry.result === CLAIM_RESULTS.REPLAY, 'retained claimed replay was masked by expiry');

  const collisionAfterExpiry = claimAndReserve(duplicate.state, {
    ...base,
    body_digest: 'sha256:body-b',
    now_ms: 2_000,
  });
  invariant(collisionAfterExpiry.result === CLAIM_RESULTS.COLLISION, 'retained claimed collision was masked by expiry');

  const open = registerOutstanding(initialState({ cap: 1 }), base);
  invariant(open.registered, 'stateful-open challenge did not register');
  const openCollisionAfterExpiry = claimAndReserve(open.state, {
    ...base,
    body_digest: 'sha256:body-b',
    now_ms: 2_000,
  });
  invariant(openCollisionAfterExpiry.result === CLAIM_RESULTS.EXPIRED, 'open collision incorrectly preceded expiry');

  const expiryFirst = claimWithExpiryFirst(duplicate.state, {
    ...base,
    now_ms: 2_000,
  });
  invariant(expiryFirst.result === CLAIM_RESULTS.EXPIRED, 'expiry-first mutation did not mask retained replay state');
  mutations.push('expiry_before_retained_claim');

  const split = twoConcurrentDuplicatesSplit(base, initialState({ cap: 1 }));
  invariant(!withinCaps(split.state), 'split mutation did not expose over-reservation');
  mutations.push('split_capacity_before_claim');

  const burned = claimBeforeCapacity(base, initialState({ cap: 1, used: 1 }));
  invariant(burned.result === CLAIM_RESULTS.CAPACITY && burned.state.replay.size === 1, 'claim-first mutation did not expose nonce burn');
  mutations.push('claim_before_capacity');

  const splitShards = twoIndependentShardClaims({ global_cap: 1, units: 1 });
  invariant(splitShards.overallocated, 'independent-shard mutation did not expose global cap over-allocation');
  mutations.push('independent_shards_without_quota_or_coordinator');

  const registered = registerOutstanding(initialState({ cap: 2 }), base);
  const transferred = claimAndReserve(registered.state, {
    ...base,
    units: Object.fromEntries(CAP_BUCKETS.map((bucket) => [bucket, 2])),
  });
  invariant(transferred.result === CLAIM_RESULTS.CLAIMED, 'stateful outstanding debit did not transfer');
  invariant(allBucketsEqual(transferred.state.used, 2), 'stateful transfer double-counted its existing debit');
  invariant(transferred.state.outstanding.size === 0, 'stateful transfer left the old outstanding record');

  const registeredAtCap = registerOutstanding(initialState({ cap: 1 }), base);
  const transferredAtCap = claimAndReserve(registeredAtCap.state, base);
  invariant(transferredAtCap.result === CLAIM_RESULTS.CLAIMED, 'zero-increment transfer refused at the cap');
  invariant(allBucketsEqual(transferredAtCap.state.used, 1), 'zero-increment transfer changed capacity');

  const doubleCountSource = registerOutstanding(initialState({ cap: 3 }), base);
  const doubleCounted = claimWithDoubleCountedOutstanding(doubleCountSource.state, {
    ...base,
    units: Object.fromEntries(CAP_BUCKETS.map((bucket) => [bucket, 2])),
  });
  invariant(allBucketsEqual(doubleCounted.state.used, 3), 'double-count mutation did not expose the leaked debit');
  mutations.push('stateful_outstanding_debit_counted_twice');

  const scopedRegistration = registerOutstanding(initialState({ cap: 2 }), {
    ...base,
    units: { aggregate: 1, presenter: 0, audience: 1, tenant: 1 },
  });
  const scopedTransfer = claimAndReserve(scopedRegistration.state, {
    ...base,
    units: { aggregate: 2, presenter: 1, audience: 1, tenant: 2 },
  });
  invariant(scopedTransfer.result === CLAIM_RESULTS.CLAIMED, 'scoped stateful debit did not transfer');
  invariant(scopedTransfer.state.used.audience === 1, 'claim dropped the pinned audience debit');
  invariant(scopedTransfer.state.used.presenter === 1, 'claim omitted the authenticated presenter debit');
  const recomputedScope = claimWithRecomputedBuckets(scopedRegistration.state, {
    ...base,
    units: { aggregate: 2, presenter: 1, audience: 0, tenant: 2 },
  });
  invariant(recomputedScope.state.used.audience === 0, 'scope-recompute mutation did not drop the pinned audience debit');
  mutations.push('claim_recomputed_and_dropped_pinned_scope');

  const tupleA = replayKey('a\u0000b', 'c');
  const tupleB = replayKey('a', 'b\u0000c');
  invariant(tupleA !== tupleB, 'structured replay key admitted delimiter collision');

  if (typeof transferred.owner_token !== 'string') {
    throw new Error(`${FORMAL_MODEL_VERSION}: claimed transition omitted its owner token`);
  }
  const reservation = transferred.state.reservations.get(transferred.owner_token);
  if (!reservation || reservation.owner_token !== transferred.owner_token) {
    throw new Error(`${FORMAL_MODEL_VERSION}: reservation omitted its fencing token`);
  }
  invariant(!finalizeReservation(reservation, 'worker-a').accepted, 'stale worker passed fencing');
  invariant(finalizeReservation(reservation, 'worker-a', { ignore_fence: true }).accepted, 'fence mutation was not exposed');
  mutations.push('stale_owner_without_fence');

  invariant(retryWindowValid({ not_before_ms: 1_000, jitter_sec: 1, expires_at_ms: 3_000 }), 'valid retry window refused');
  invariant(!retryWindowValid({ not_before_ms: 1_000, jitter_sec: 2, expires_at_ms: 3_000 }), 'jitter reaching expiry accepted');
  invariant(!retryWindowValid({ not_before_ms: 3_000, jitter_sec: 0, expires_at_ms: 3_000 }), 'not_before at expiry accepted');

  invariant(presenterMatchesAudience({ audience: 'agent-a', authenticated_presenter: 'agent-a' }), 'bound presenter refused');
  invariant(!presenterMatchesAudience({ audience: 'agent-a', authenticated_presenter: 'agent-b' }), 'wrong presenter accepted');

  return {
    model: FORMAL_MODEL_VERSION,
    method: 'finite_scenario_enumeration_with_mutation_counterexamples',
    scenario_check_complete: true,
    verified: false,
    states_checked: states + 17,
    mutation_counterexamples: mutations,
    checked_properties: {
      CompoundClaimAndCapacityAtomic: checkedProperty(states, {
        mutation: 'split_capacity_before_claim',
        observed_used: split.state.used,
        caps: split.state.caps,
      }),
      DuplicateReservesOnce: checkedProperty(1, {
        mutation: 'split_capacity_before_claim',
        leaked_reservation: 'worker-b-leaked',
      }),
      CapacityRefusalDoesNotClaim: checkedProperty(1, {
        mutation: 'claim_before_capacity',
        replay_records_after_refusal: burned.state.replay.size,
      }),
      BodyCollisionIsNotReplay: checkedProperty(2, {
        mutation: 'treat_different_body_as_exact_replay',
        conflicting_body: 'sha256:body-b',
      }),
      OwnerUncertaintyIsUnavailable: checkedProperty(1, {
        mutation: 'collapse_uncertainty_to_unclaimed',
        authoritative_possibilities: possibleStates.length,
      }),
      ExpiredDoesNotClaimOrReserve: checkedProperty(2, {
        mutation: 'check_expiry_outside_owner_transition',
        now_ms: 2_000,
        expires_at_ms: base.expires_at_ms,
      }),
      ClaimedReplayPrecedesExpiry: checkedProperty(2, {
        mutation: 'check_expiry_before_retained_claimed_record',
        now_ms: 2_000,
        expires_at_ms: base.expires_at_ms,
      }),
      SingleOwnerCapacityConserved: checkedProperty(1, {
        mutation: 'independent_shards_without_quota_or_coordinator',
        global_used: splitShards.global_used,
        global_cap: splitShards.global_cap,
      }),
      StatefulDebitTransfersWithoutDoubleCount: checkedProperty(2, {
        mutation: 'stateful_outstanding_debit_counted_twice',
        sound_used: transferred.state.used,
        mutated_used: doubleCounted.state.used,
      }),
      PinnedScopedDebitSurvivesClaim: checkedProperty(1, {
        mutation: 'claim_recomputed_and_dropped_pinned_scope',
        sound_used: scopedTransfer.state.used,
        mutated_used: recomputedScope.state.used,
      }),
      ReplayKeyTupleIsUnambiguous: checkedProperty(1, {
        mutation: 'nul_delimiter_tuple_collision',
        first_key: tupleA,
        second_key: tupleB,
      }),
      ReservationTokenMismatchRefused: checkedProperty(1, {
        mutation: 'stale_owner_without_fence',
        stale_owner: 'worker-a',
        current_owner: reservation.owner_token,
      }),
      RetryWindowPrecedesExpiry: checkedProperty(3, {
        mutation: 'jitter_reaches_expiry',
        not_before_ms: 1_000,
        jitter_sec: 2,
        expires_at_ms: 3_000,
      }),
      PresenterMatchesAudience: checkedProperty(2, {
        mutation: 'accept_wrong_authenticated_presenter',
        audience: 'agent-a',
        authenticated_presenter: 'agent-b',
      }),
    },
    limitations: [
      'Finite same-team scenario exploration, not a storage-driver refinement or database isolation proof.',
      'The model explores small bounds for four named cap buckets; deployments can define additional buckets.',
      'Crash atomicity, quota transfer, authenticated alias mapping, and self-describing envelope verification require separate implementation evidence.',
      'Evidence verification, policy correctness, and transport authentication are outside this model.',
    ],
  };
}

const invokedAsScript = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  const result = runClaimCapacityChecks();
  if (process.argv.includes('--json')) console.log(JSON.stringify(result));
  else {
    console.log(`${result.model}: PASS`);
    console.log(`finite scenarios checked: ${result.states_checked}`);
    console.log(`unsafe mutations exposed: ${result.mutation_counterexamples.join(', ')}`);
    for (const [name, row] of Object.entries(result.checked_properties)) {
      console.log(`${name}: ${row.checked ? 'checked in bounded scenarios' : 'FAILED'}`);
    }
  }
}
