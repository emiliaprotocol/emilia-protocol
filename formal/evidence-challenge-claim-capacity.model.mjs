// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AE-CHALLENGE-CLAIM-CAPACITY-BOUNDED-MODEL-v1
 *
 * A finite model of the owner-side transition added after the -06 hostile
 * review.  Replay classification and refusal-path capacity are deliberately
 * one transition.  Modeling them as two ordered operations admits either a
 * capacity leak on duplicate presentations or a nonce burn at capacity.
 */

export const FORMAL_MODEL_VERSION =
  'EP-AE-CHALLENGE-CLAIM-CAPACITY-BOUNDED-MODEL-v1';

export const FORMAL_OBLIGATIONS = Object.freeze([
  'CompoundClaimAndCapacityAtomic',
  'DuplicateReservesOnce',
  'CapacityRefusalDoesNotClaim',
  'BodyCollisionIsNotReplay',
  'OwnerUncertaintyIsUnavailable',
  'ExpiredDoesNotClaimOrReserve',
  'ClaimedReplayPrecedesExpiry',
  'GlobalCapIsConservedAcrossShards',
  'RecoveryFinalizationIsFenced',
  'RetryWindowPrecedesExpiry',
  'PresenterMatchesAudience',
]);

export const CLAIM_RESULTS = Object.freeze({
  CLAIMED: 'claimed_with_capacity',
  REPLAY: 'exact_body_replay',
  COLLISION: 'nonce_body_collision',
  CAPACITY: 'capacity_refused',
  EXPIRED: 'expired',
  UNAVAILABLE: 'owner_unavailable',
});

export function initialState({ cap = 1, used = 0 } = {}) {
  return {
    cap,
    used,
    replay: new Map(),
    reservations: new Map(),
  };
}

function cloneState(state) {
  return {
    cap: state.cap,
    used: state.used,
    replay: new Map(state.replay),
    reservations: new Map(state.reservations),
  };
}

/**
 * Sound owner-side primitive.  The replay key is scoped by authenticated
 * issuer identity and nonce.  All cap buckets represented by `units` commit
 * with the nonce claim or neither does.
 */
export function claimAndReserve(
  state,
  {
    issuer,
    nonce,
    body_digest,
    units = 1,
    now_ms = 0,
    expires_at_ms = 1,
    owner_reachable = true,
    owner_result_certain = true,
  },
) {
  const next = cloneState(state);
  if (!owner_reachable || !owner_result_certain) {
    // The caller cannot infer whether the owner committed before the response
    // was lost.  Both authoritative outcomes remain possible, while the only
    // safe externally reported result is unavailability.
    const possible_states = [next];
    if (!owner_result_certain) {
      possible_states.push(claimAndReserve(state, {
        issuer,
        nonce,
        body_digest,
        units,
        now_ms,
        expires_at_ms,
        owner_reachable: true,
        owner_result_certain: true,
      }).state);
    }
    return { result: CLAIM_RESULTS.UNAVAILABLE, state: next, possible_states };
  }
  const key = `${issuer}\u0000${nonce}`;
  const existing = next.replay.get(key);
  if (existing !== undefined) {
    return {
      result:
        existing.body_digest === body_digest
          ? CLAIM_RESULTS.REPLAY
          : CLAIM_RESULTS.COLLISION,
      state: next,
    };
  }
  if (!Number.isSafeInteger(now_ms) || !Number.isSafeInteger(expires_at_ms)) {
    return { result: CLAIM_RESULTS.UNAVAILABLE, state: next, possible_states: [next] };
  }
  if (now_ms >= expires_at_ms) {
    return { result: CLAIM_RESULTS.EXPIRED, state: next };
  }
  if (!Number.isSafeInteger(units) || units <= 0 || next.used + units > next.cap) {
    return { result: CLAIM_RESULTS.CAPACITY, state: next };
  }
  const owner_token = `${key}:${body_digest}`;
  next.used += units;
  next.replay.set(key, { body_digest, owner_token });
  next.reservations.set(owner_token, { key, units, body_digest });
  return { result: CLAIM_RESULTS.CLAIMED, owner_token, state: next };
}

export function twoConcurrentDuplicatesSound(input, state = initialState()) {
  const first = claimAndReserve(state, input);
  const second = claimAndReserve(first.state, input);
  return { first, second, state: second.state };
}

/** Mutation: two workers reserve from the same snapshot before either claims. */
export function twoConcurrentDuplicatesSplit(input, state = initialState()) {
  const key = `${input.issuer}\u0000${input.nonce}`;
  const bothSawAbsent = !state.replay.has(key);
  const bothSawCapacity = state.used + input.units <= state.cap;
  const next = cloneState(state);
  if (bothSawAbsent && bothSawCapacity) {
    next.used += input.units * 2;
    next.replay.set(key, { body_digest: input.body_digest, owner_token: 'worker-a' });
    next.reservations.set('worker-a', { key, units: input.units });
    next.reservations.set('worker-b-leaked', { key, units: input.units });
  }
  return { state: next, bothSawAbsent, bothSawCapacity };
}

/** Mutation: a global cap is checked independently by two owner shards. */
export function twoIndependentShardClaims({ global_cap = 1, units = 1 } = {}) {
  const shardA = { observed_global_used: 0, reserved: units };
  const shardB = { observed_global_used: 0, reserved: units };
  return {
    global_cap,
    global_used: shardA.reserved + shardB.reserved,
    overallocated: shardA.reserved + shardB.reserved > global_cap,
  };
}

/** Mutation: claim is committed before the cap decision. */
export function claimBeforeCapacity(input, state = initialState()) {
  const next = cloneState(state);
  const key = `${input.issuer}\u0000${input.nonce}`;
  next.replay.set(key, { body_digest: input.body_digest, owner_token: null });
  const capacityAvailable = next.used + input.units <= next.cap;
  if (capacityAvailable) next.used += input.units;
  return {
    result: capacityAvailable ? CLAIM_RESULTS.CLAIMED : CLAIM_RESULTS.CAPACITY,
    state: next,
  };
}

/** Mutation: expiry is classified before a retained claimed replay record. */
export function claimWithExpiryFirst(state, input) {
  const next = cloneState(state);
  if (input.now_ms >= input.expires_at_ms) {
    return { result: CLAIM_RESULTS.EXPIRED, state: next };
  }
  return claimAndReserve(state, input);
}

/**
 * A reclaimed reservation is safe only when a fencing token prevents the old
 * worker from publishing a late follow-up or other state transition.
 */
export function finalizeReservation(
  reservation,
  presented_owner_token,
  { ignore_fence = false } = {},
) {
  const accepted =
    ignore_fence || reservation.owner_token === presented_owner_token;
  return { accepted };
}

export function retryWindowValid({ not_before_ms, jitter_sec, expires_at_ms }) {
  return Number.isSafeInteger(not_before_ms)
    && Number.isSafeInteger(jitter_sec)
    && jitter_sec >= 0
    && Number.isSafeInteger(expires_at_ms)
    && not_before_ms < expires_at_ms
    && not_before_ms + jitter_sec * 1000 < expires_at_ms;
}

export function presenterMatchesAudience({ audience, authenticated_presenter }) {
  return typeof audience === 'string'
    && audience.length > 0
    && audience === authenticated_presenter;
}
