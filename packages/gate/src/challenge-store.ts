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

export const DURABLE_CHALLENGE_STORE_VERSION = 'EP-DURABLE-CHALLENGE-STORE-v3';
const OPEN_PREFIX = 'challenge-open:v3:';
const CONSUMED_PREFIX = 'challenge-consumed:v3:';
const LEGACY_SINGLE_ISSUER_IDENTITY = 'urn:emilia:challenge-issuer:legacy-single-store';

function assertChallenge(challenge) {
  if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) {
    throw new Error('challenge must be an object');
  }
  if (challenge['@version'] !== 'AE-CHALLENGE-v1') throw new Error('unsupported challenge version');
  if (typeof challenge.challenge_id !== 'string' || !challenge.challenge_id.trim()) throw new Error('challenge_id is required');
  if (typeof challenge.nonce !== 'string' || !challenge.nonce.trim()) throw new Error('challenge nonce is required');
}

function normalizedIssuerIdentity(issuerIdentity?: string) {
  if (issuerIdentity === undefined) return LEGACY_SINGLE_ISSUER_IDENTITY;
  if (typeof issuerIdentity !== 'string' || !issuerIdentity.trim()) {
    throw new Error('authenticated issuer identity must be a non-empty string');
  }
  return issuerIdentity;
}

export function challengeStorageKey(challenge, issuerIdentity?: string) {
  assertChallenge(challenge);
  // The authenticated issuer identity and nonce form the replay key. The
  // correlation-only challenge_id is intentionally excluded. The legacy
  // sentinel preserves source compatibility for explicitly single-issuer,
  // non-conforming callers; production -07 use requires issuerScoped=true.
  return `ae-challenge:v3:${hashCanonical({
    issuer: normalizedIssuerIdentity(issuerIdentity),
    nonce: challenge.nonce,
  })}`;
}

export function challengeBodyDigest(challenge) {
  assertChallenge(challenge);
  // Domain separation is part of the stored body identity. The same JSON
  // value used by another protocol domain must not have the same digest.
  return hashCanonical({
    domain: 'AE-CHALLENGE-BODY-v1',
    challenge,
  });
}

export function createDurableChallengeStore(
  backend,
  { issuerIdentity }: { issuerIdentity?: string } = {},
) {
  for (const method of ['addIfAbsent', 'compareAndSet', 'has']) {
    if (typeof backend?.[method] !== 'function') {
      throw new Error(`createDurableChallengeStore: backend must implement atomic async ${method}()`);
    }
  }

  const issuer = normalizedIssuerIdentity(issuerIdentity);
  const issuerScoped = issuerIdentity !== undefined;
  const canClassify = typeof backend.get === 'function';

  function keyFor(challenge) {
    return challengeStorageKey(challenge, issuer);
  }

  async function classify(challenge) {
    if (!canClassify) {
      throw new Error('challenge backend cannot authoritatively classify replay state');
    }
    const value = await backend.get(keyFor(challenge));
    if (value === undefined || value === null) return 'absent';
    const digest = challengeBodyDigest(challenge);
    if (typeof value !== 'string') {
      throw new Error('challenge store contains a malformed authoritative state value');
    }
    if (value.startsWith(OPEN_PREFIX)) {
      return value.slice(OPEN_PREFIX.length) === digest
        ? 'open-exact'
        : 'open-body-collision';
    }
    if (value.startsWith(CONSUMED_PREFIX)) {
      return value.slice(CONSUMED_PREFIX.length) === digest
        ? 'claimed-exact'
        : 'claimed-body-collision';
    }
    throw new Error('challenge store contains an unknown authoritative state value');
  }

  return {
    durable: backend.durable === true,
    atomicRegistration: true,
    bodyBound: true,
    permanentConsumption: true,
    authoritativeClassification: canClassify,
    issuerScoped,
    issuerIdentity: issuer,
    async register(challenge) {
      const key = keyFor(challenge);
      const digest = challengeBodyDigest(challenge);
      return (await backend.addIfAbsent(key, `${OPEN_PREFIX}${digest}`)) === true;
    },

    async consume(challenge) {
      const key = keyFor(challenge);
      const digest = challengeBodyDigest(challenge);
      return (await backend.compareAndSet(
        key,
        `${OPEN_PREFIX}${digest}`,
        `${CONSUMED_PREFIX}${digest}`,
      )) === true;
    },

    ...(canClassify ? { classify } : {}),

    async has(challenge) {
      return (await backend.has(keyFor(challenge))) === true;
    },
  };
}

export default { createDurableChallengeStore, challengeStorageKey, challengeBodyDigest, DURABLE_CHALLENGE_STORE_VERSION };
