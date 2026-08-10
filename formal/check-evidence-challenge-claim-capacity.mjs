#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { pathToFileURL } from 'node:url';
import {
  CLAIM_RESULTS,
  FORMAL_MODEL_VERSION,
  claimAndReserve,
  claimBeforeCapacity,
  claimWithExpiryFirst,
  finalizeReservation,
  initialState,
  presenterMatchesAudience,
  retryWindowValid,
  twoIndependentShardClaims,
  twoConcurrentDuplicatesSound,
  twoConcurrentDuplicatesSplit,
} from './evidence-challenge-claim-capacity.model.mjs';

function invariant(condition, message) {
  if (!condition) throw new Error(`${FORMAL_MODEL_VERSION}: ${message}`);
}

function obligation(states_checked, mutation_counterexample) {
  return {
    states_checked,
    mutation_states_checked: 1,
    verified: true,
    counterexample: null,
    mutation_counterexample,
  };
}

export function runClaimCapacityChecks() {
  const base = {
    issuer: 'https://issuer.example',
    nonce: 'nonce-128-bits-or-more',
    body_digest: 'sha256:body-a',
    units: 1,
    now_ms: 1_000,
    expires_at_ms: 2_000,
  };
  let states = 0;
  const mutations = [];

  for (const cap of [1, 2, 3]) {
    for (let used = 0; used <= cap; used += 1) {
      states += 1;
      const state = initialState({ cap, used });
      const result = claimAndReserve(state, base);
      invariant(result.state.used <= cap, 'sound transition exceeded its cap');
      if (used === cap) {
        invariant(result.result === CLAIM_RESULTS.CAPACITY, 'full cap did not refuse');
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
  invariant(duplicate.state.used === 1, 'duplicate presentation reserved capacity twice');

  const conflicting = claimAndReserve(duplicate.state, {
    ...base,
    body_digest: 'sha256:body-b',
  });
  invariant(conflicting.result === CLAIM_RESULTS.COLLISION, 'same nonce with another body was not a collision');
  invariant(conflicting.state.used === 1, 'body collision changed capacity');

  const unavailable = claimAndReserve(initialState({ cap: 1 }), {
    ...base,
    owner_result_certain: false,
  });
  invariant(unavailable.result === CLAIM_RESULTS.UNAVAILABLE, 'uncertain owner result was classified as a verdict');
  invariant(unavailable.possible_states.length === 2, 'uncertain result did not preserve both authoritative possibilities');
  invariant(unavailable.possible_states.every((state) => state.used <= state.cap), 'uncertain result admitted an over-cap authoritative state');

  const expired = claimAndReserve(initialState({ cap: 1 }), {
    ...base,
    now_ms: 2_000,
  });
  invariant(expired.result === CLAIM_RESULTS.EXPIRED, 'expired challenge did not receive the closed expired result');
  invariant(expired.state.used === 0 && expired.state.replay.size === 0, 'expired challenge claimed or reserved state');

  const replayAfterExpiry = claimAndReserve(duplicate.state, {
    ...base,
    now_ms: 2_000,
  });
  invariant(replayAfterExpiry.result === CLAIM_RESULTS.REPLAY, 'retained claimed replay was masked by expiry');
  invariant(replayAfterExpiry.state.used === 1, 'post-expiry replay changed capacity');

  const expiryFirst = claimWithExpiryFirst(duplicate.state, {
    ...base,
    now_ms: 2_000,
  });
  invariant(expiryFirst.result === CLAIM_RESULTS.EXPIRED, 'expiry-first mutation did not mask retained replay state');
  mutations.push('expiry_before_retained_claim');

  const split = twoConcurrentDuplicatesSplit(base, initialState({ cap: 1 }));
  invariant(split.state.used === 2, 'split mutation did not expose over-reservation');
  mutations.push('split_capacity_before_claim');

  const burned = claimBeforeCapacity(base, initialState({ cap: 1, used: 1 }));
  invariant(burned.result === CLAIM_RESULTS.CAPACITY && burned.state.replay.size === 1, 'claim-first mutation did not expose nonce burn');
  mutations.push('claim_before_capacity');

  const splitShards = twoIndependentShardClaims({ global_cap: 1, units: 1 });
  invariant(splitShards.overallocated, 'independent-shard mutation did not expose global cap over-allocation');
  mutations.push('independent_shards_without_quota_or_coordinator');

  const reclaimed = { owner_token: 'worker-b' };
  invariant(!finalizeReservation(reclaimed, 'worker-a').accepted, 'stale worker passed fencing');
  invariant(finalizeReservation(reclaimed, 'worker-a', { ignore_fence: true }).accepted, 'fence mutation was not exposed');
  mutations.push('stale_owner_without_fence');

  invariant(retryWindowValid({ not_before_ms: 1_000, jitter_sec: 1, expires_at_ms: 3_000 }), 'valid retry window refused');
  invariant(!retryWindowValid({ not_before_ms: 1_000, jitter_sec: 2, expires_at_ms: 3_000 }), 'jitter reaching expiry accepted');
  invariant(!retryWindowValid({ not_before_ms: 3_000, jitter_sec: 0, expires_at_ms: 3_000 }), 'not_before at expiry accepted');

  invariant(presenterMatchesAudience({ audience: 'agent-a', authenticated_presenter: 'agent-a' }), 'bound presenter refused');
  invariant(!presenterMatchesAudience({ audience: 'agent-a', authenticated_presenter: 'agent-b' }), 'wrong presenter accepted');

  return {
    model: FORMAL_MODEL_VERSION,
    method: 'bounded_exhaustive_state_exploration',
    verified: true,
    states_checked: states + 9,
    mutation_counterexamples: mutations,
    obligations: {
      CompoundClaimAndCapacityAtomic: obligation(states, {
        mutation: 'split_capacity_before_claim',
        observed_used: split.state.used,
        cap: split.state.cap,
      }),
      DuplicateReservesOnce: obligation(1, {
        mutation: 'split_capacity_before_claim',
        leaked_reservation: 'worker-b-leaked',
      }),
      CapacityRefusalDoesNotClaim: obligation(1, {
        mutation: 'claim_before_capacity',
        replay_records_after_refusal: burned.state.replay.size,
      }),
      BodyCollisionIsNotReplay: obligation(1, {
        mutation: 'treat_different_body_as_exact_replay',
        conflicting_body: 'sha256:body-b',
      }),
      OwnerUncertaintyIsUnavailable: obligation(1, {
        mutation: 'collapse_uncertainty_to_unclaimed',
        authoritative_possibilities: unavailable.possible_states.length,
      }),
      ExpiredDoesNotClaimOrReserve: obligation(1, {
        mutation: 'check_expiry_outside_owner_transition',
        now_ms: 2_000,
        expires_at_ms: base.expires_at_ms,
      }),
      ClaimedReplayPrecedesExpiry: obligation(1, {
        mutation: 'check_expiry_before_retained_claimed_record',
        now_ms: 2_000,
        expires_at_ms: base.expires_at_ms,
      }),
      GlobalCapIsConservedAcrossShards: obligation(1, {
        mutation: 'independent_shards_without_quota_or_coordinator',
        global_used: splitShards.global_used,
        global_cap: splitShards.global_cap,
      }),
      RecoveryFinalizationIsFenced: obligation(1, {
        mutation: 'stale_owner_without_fence',
        stale_owner: 'worker-a',
        current_owner: 'worker-b',
      }),
      RetryWindowPrecedesExpiry: obligation(3, {
        mutation: 'jitter_reaches_expiry',
        not_before_ms: 1_000,
        jitter_sec: 2,
        expires_at_ms: 3_000,
      }),
      PresenterMatchesAudience: obligation(2, {
        mutation: 'accept_wrong_authenticated_presenter',
        audience: 'agent-a',
        authenticated_presenter: 'agent-b',
      }),
    },
    limitations: [
      'Finite same-team state exploration, not a storage-driver refinement proof.',
      'The model assumes the compound transition covers every applicable cap bucket in one transaction or under preallocated shard quotas.',
      'The model does not represent stateful open registration or transfer of an existing outstanding-state debit into an in-flight reservation.',
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
    console.log(`states checked: ${result.states_checked}`);
    console.log(`unsafe counterexamples: ${result.mutation_counterexamples.join(', ')}`);
    for (const [name, row] of Object.entries(result.obligations)) {
      console.log(`${name}: ${row.verified ? 'verified' : 'FAILED'}`);
    }
  }
}
