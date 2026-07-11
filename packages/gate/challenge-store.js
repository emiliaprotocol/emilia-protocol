// SPDX-License-Identifier: Apache-2.0
/**
 * Durable, body-bound lifecycle store for AE-CHALLENGE-v1.
 *
 * Registration is atomic insert-if-absent. Consumption is an atomic transition
 * from the digest of the exact registered body to a consumed state carrying
 * that same digest. A presenter that changes action, profile, expiry, or any
 * other challenge member cannot consume the original registration even when it
 * reuses the challenge id and nonce.
 */
import { hashCanonical } from './execution-binding.js';

export const DURABLE_CHALLENGE_STORE_VERSION = 'EP-DURABLE-CHALLENGE-STORE-v1';
const OPEN_PREFIX = 'challenge-open:v1:';
const CONSUMED_PREFIX = 'challenge-consumed:v1:';

function assertChallenge(challenge) {
  if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) {
    throw new Error('challenge must be an object');
  }
  if (challenge['@version'] !== 'AE-CHALLENGE-v1') throw new Error('unsupported challenge version');
  if (typeof challenge.challenge_id !== 'string' || !challenge.challenge_id.trim()) throw new Error('challenge_id is required');
  if (typeof challenge.nonce !== 'string' || !challenge.nonce.trim()) throw new Error('challenge nonce is required');
}

export function challengeStorageKey(challenge) {
  assertChallenge(challenge);
  return `ae-challenge:${hashCanonical({ challenge_id: challenge.challenge_id, nonce: challenge.nonce })}`;
}

export function challengeBodyDigest(challenge) {
  assertChallenge(challenge);
  return hashCanonical(challenge);
}

export function createDurableChallengeStore(backend) {
  for (const method of ['addIfAbsent', 'compareAndSet', 'has']) {
    if (typeof backend?.[method] !== 'function') {
      throw new Error(`createDurableChallengeStore: backend must implement atomic async ${method}()`);
    }
  }

  return {
    async register(challenge) {
      const key = challengeStorageKey(challenge);
      const digest = challengeBodyDigest(challenge);
      return (await backend.addIfAbsent(key, `${OPEN_PREFIX}${digest}`)) === true;
    },

    async consume(challenge) {
      const key = challengeStorageKey(challenge);
      const digest = challengeBodyDigest(challenge);
      return (await backend.compareAndSet(
        key,
        `${OPEN_PREFIX}${digest}`,
        `${CONSUMED_PREFIX}${digest}`,
      )) === true;
    },

    async has(challenge) {
      return (await backend.has(challengeStorageKey(challenge))) === true;
    },
  };
}

export default { createDurableChallengeStore, challengeStorageKey, challengeBodyDigest, DURABLE_CHALLENGE_STORE_VERSION };
