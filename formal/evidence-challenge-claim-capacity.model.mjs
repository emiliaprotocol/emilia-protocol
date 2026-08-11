// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AE-CHALLENGE-CLAIM-CAPACITY-BOUNDED-MODEL-v3
 *
 * A finite executable model of the owner-side transition added after the -06
 * hostile review. Replay classification, expiry, transfer of a stateful-open
 * debit, and reservation across every applicable capacity bucket are one
 * transition. This is scenario exploration, not a storage-driver proof.
 */

export const FORMAL_MODEL_VERSION =
  'EP-AE-CHALLENGE-CLAIM-CAPACITY-BOUNDED-MODEL-v3';

export const CAP_BUCKETS = Object.freeze([
  'aggregate',
  'presenter',
  'audience',
  'tenant',
]);

export const CHECKED_PROPERTIES = Object.freeze([
  'CompoundClaimAndCapacityAtomic',
  'DuplicateReservesOnce',
  'CapacityRefusalDoesNotClaim',
  'BodyCollisionIsNotReplay',
  'OwnerUncertaintyIsUnavailable',
  'ExpiredDoesNotClaimOrReserve',
  'ClaimedReplayPrecedesExpiry',
  'SingleOwnerCapacityConserved',
  'StatefulDebitTransfersWithoutDoubleCount',
  'PinnedScopedDebitSurvivesClaim',
  'ReplayKeyTupleIsUnambiguous',
  'ReservationTokenMismatchRefused',
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

/** @typedef {Record<string, number>} CapacityVector */
/**
 * @typedef {object} ClaimInput
 * @property {string} issuer
 * @property {string} nonce
 * @property {string} body_digest
 * @property {number|CapacityVector} [units]
 * @property {number} [now_ms]
 * @property {number} [expires_at_ms]
 * @property {boolean} [owner_reachable]
 * @property {boolean} [owner_result_certain]
 */
/**
 * @typedef {object} ClaimState
 * @property {CapacityVector} caps
 * @property {CapacityVector} used
 * @property {Map<string, any>} replay
 * @property {Map<string, any>} outstanding
 * @property {Map<string, any>} reservations
 */

/**
 * @param {number|CapacityVector|null|undefined} value
 * @param {number} [fallback]
 * @returns {CapacityVector}
 */
function vector(value, fallback = 0) {
  if (Number.isSafeInteger(value)) {
    const scalar = /** @type {number} */ (value);
    return Object.fromEntries(CAP_BUCKETS.map((bucket) => [bucket, scalar]));
  }
  const source = value && typeof value === 'object' ? value : {};
  return Object.fromEntries(CAP_BUCKETS.map((bucket) => [
    bucket,
    Number.isSafeInteger(source[bucket]) ? source[bucket] : fallback,
  ]));
}

export function replayKey(issuer, nonce) {
  // A structured tuple avoids delimiter collisions such as ("a\\0b", "c")
  // versus ("a", "b\\0c").
  return JSON.stringify([issuer, nonce]);
}

/**
 * @param {{cap?: number, caps?: number|CapacityVector, used?: number|CapacityVector}} [input]
 * @returns {ClaimState}
 */
export function initialState({ cap = 1, caps, used = 0 } = {}) {
  return {
    caps: vector(caps ?? cap),
    used: vector(used),
    replay: new Map(),
    outstanding: new Map(),
    reservations: new Map(),
  };
}

/** @param {ClaimState} state @returns {ClaimState} */
function cloneState(state) {
  return {
    caps: { ...state.caps },
    used: { ...state.used },
    replay: new Map(state.replay),
    outstanding: new Map(state.outstanding),
    reservations: new Map(state.reservations),
  };
}

/** @param {ClaimState} state */
export function withinCaps(state) {
  return CAP_BUCKETS.every((bucket) => (
    Number.isSafeInteger(state.used[bucket])
    && Number.isSafeInteger(state.caps[bucket])
    && state.used[bucket] >= 0
    && state.used[bucket] <= state.caps[bucket]
  ));
}

/** @param {ClaimState} state @param {CapacityVector} delta */
function capacityAvailable(state, delta) {
  return CAP_BUCKETS.every((bucket) => (
    Number.isSafeInteger(delta[bucket])
    && delta[bucket] >= 0
    && state.used[bucket] + delta[bucket] <= state.caps[bucket]
  ));
}

/** @param {CapacityVector} target @param {CapacityVector} delta */
function addVector(target, delta) {
  for (const bucket of CAP_BUCKETS) target[bucket] += delta[bucket];
}

/** Register and debit a stateful-open challenge before it is exposed. */
/** @param {ClaimState} state @param {ClaimInput} input */
export function registerOutstanding(state, {
  issuer,
  nonce,
  body_digest,
  units = 1,
}) {
  const next = cloneState(state);
  const key = replayKey(issuer, nonce);
  const debit = vector(units);
  if (next.replay.has(key) || next.outstanding.has(key) || !capacityAvailable(next, debit)) {
    return { registered: false, state: next };
  }
  addVector(next.used, debit);
  next.outstanding.set(key, { body_digest, units: debit });
  return { registered: true, state: next };
}

/**
 * Sound owner-side primitive. `units` is the conservative total reservation
 * required while evaluation is in flight. For stateful issuance, an existing
 * outstanding debit is transferred and only the positive incremental delta is
 * added. Every bucket commits with the replay claim or none does.
 */
/** @param {ClaimState} state @param {ClaimInput} input */
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

  const key = replayKey(issuer, nonce);
  const claimed = next.replay.get(key);
  if (claimed !== undefined) {
    return {
      result: claimed.body_digest === body_digest
        ? CLAIM_RESULTS.REPLAY
        : CLAIM_RESULTS.COLLISION,
      state: next,
    };
  }
  if (!Number.isSafeInteger(now_ms) || !Number.isSafeInteger(expires_at_ms)) {
    return { result: CLAIM_RESULTS.UNAVAILABLE, state: next, possible_states: [next] };
  }
  // Expiry precedes classification of an unclaimed stateful-open body.
  if (now_ms >= expires_at_ms) {
    return { result: CLAIM_RESULTS.EXPIRED, state: next };
  }

  const outstanding = next.outstanding.get(key);
  if (outstanding !== undefined && outstanding.body_digest !== body_digest) {
    return { result: CLAIM_RESULTS.COLLISION, state: next };
  }

  const target = vector(units);
  const existing = outstanding?.units ?? vector(0);
  const incremental = Object.fromEntries(CAP_BUCKETS.map((bucket) => [
    bucket,
    Math.max(0, target[bucket] - existing[bucket]),
  ]));
  if (!capacityAvailable(next, incremental)) {
    return { result: CLAIM_RESULTS.CAPACITY, state: next };
  }

  addVector(next.used, incremental);
  next.outstanding.delete(key);
  const owner_token = JSON.stringify([key, body_digest]);
  next.replay.set(key, { body_digest, owner_token });
  next.reservations.set(owner_token, {
    key,
    units: target,
    body_digest,
    owner_token,
  });
  return { result: CLAIM_RESULTS.CLAIMED, owner_token, state: next };
}

/** @param {ClaimInput} input @param {ClaimState} [state] */
export function twoConcurrentDuplicatesSound(input, state = initialState()) {
  const first = claimAndReserve(state, input);
  const second = claimAndReserve(first.state, input);
  return { first, second, state: second.state };
}

/** Mutation: two workers reserve from the same snapshot before either claims. */
/** @param {ClaimInput} input @param {ClaimState} [state] */
export function twoConcurrentDuplicatesSplit(input, state = initialState()) {
  const key = replayKey(input.issuer, input.nonce);
  const units = vector(input.units ?? 1);
  const bothSawAbsent = !state.replay.has(key);
  const bothSawCapacity = capacityAvailable(state, units);
  const next = cloneState(state);
  if (bothSawAbsent && bothSawCapacity) {
    addVector(next.used, Object.fromEntries(CAP_BUCKETS.map((bucket) => [
      bucket,
      units[bucket] * 2,
    ])));
    next.replay.set(key, { body_digest: input.body_digest, owner_token: 'worker-a' });
    next.reservations.set('worker-a', { key, units, owner_token: 'worker-a' });
    next.reservations.set('worker-b-leaked', { key, units, owner_token: 'worker-b-leaked' });
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

/** Mutation: a stateful-open debit is counted again rather than transferred. */
/** @param {ClaimState} state @param {ClaimInput} input */
export function claimWithDoubleCountedOutstanding(state, input) {
  const next = cloneState(state);
  const requested = vector(input.units ?? 1);
  if (capacityAvailable(next, requested)) addVector(next.used, requested);
  return { state: next };
}

/** Mutation: recomputing claim buckets replaces and releases the pinned issuance scope. */
/** @param {ClaimState} state @param {ClaimInput} input */
export function claimWithRecomputedBuckets(state, input) {
  const next = cloneState(state);
  const key = replayKey(input.issuer, input.nonce);
  const existing = next.outstanding.get(key)?.units ?? vector(0);
  const requested = vector(input.units ?? 1);
  for (const bucket of CAP_BUCKETS) {
    next.used[bucket] = next.used[bucket] - existing[bucket] + requested[bucket];
  }
  return { state: next };
}

/** Mutation: claim is committed before the cap decision. */
/** @param {ClaimInput} input @param {ClaimState} [state] */
export function claimBeforeCapacity(input, state = initialState()) {
  const next = cloneState(state);
  const key = replayKey(input.issuer, input.nonce);
  next.replay.set(key, { body_digest: input.body_digest, owner_token: null });
  const requested = vector(input.units ?? 1);
  const available = capacityAvailable(next, requested);
  if (available) addVector(next.used, requested);
  return {
    result: available ? CLAIM_RESULTS.CLAIMED : CLAIM_RESULTS.CAPACITY,
    state: next,
  };
}

/** Mutation: expiry is classified before a retained claimed replay record. */
/** @param {ClaimState} state @param {ClaimInput} input */
export function claimWithExpiryFirst(state, input) {
  const next = cloneState(state);
  if (Number.isSafeInteger(input.now_ms) && Number.isSafeInteger(input.expires_at_ms)
      && /** @type {number} */ (input.now_ms) >= /** @type {number} */ (input.expires_at_ms)) {
    return { result: CLAIM_RESULTS.EXPIRED, state: next };
  }
  return claimAndReserve(state, input);
}

export function finalizeReservation(
  reservation,
  presented_owner_token,
  { ignore_fence = false } = {},
) {
  return {
    accepted: ignore_fence || reservation.owner_token === presented_owner_token,
  };
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
