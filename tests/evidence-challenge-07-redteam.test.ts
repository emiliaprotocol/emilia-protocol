// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  createRegisteredEvidenceChallenge,
  evaluateRegisteredPresentation,
} from '../lib/negotiate/evidence-challenge.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../lib/evidence/policy-packs.js';
import { createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createMemoryBackend } from '../packages/gate/store.js';

const policy = getPolicyPack('ep:pack:wire-transfer:v1');
const actionA = {
  type: 'urn:ep:action:payments.wire_transfer',
  amount: '250000.00',
  currency: 'USD',
};
const actionB = { ...actionA, amount: '250000.01' };
const beforeExpiry = '2026-07-03T12:01:00Z';
const afterExpiry = '2026-07-03T12:11:00Z';
const expiresAt = '2026-07-03T12:10:00Z';
const verifiers = {
  authorization_receipt: (artifact) => ({
    valid: true,
    action_digest: artifact.action,
    issued_at: artifact.issued_at,
    revoked: false,
  }),
  policy_permit: (artifact) => ({
    valid: true,
    action_digest: artifact.action,
    issued_at: artifact.issued_at,
  }),
  workload_identity: (artifact) => ({
    valid: true,
    action_digest: artifact.action,
    issued_at: artifact.issued_at,
  }),
};

function completeGraph(action = actionA) {
  const actionDigest = artifactDigest(action);
  const artifacts = ['authorization_receipt', 'policy_permit', 'workload_identity'].map((typ) => ({
    typ,
    action: actionDigest,
    issued_at: '2026-07-03T12:00:00Z',
  }));
  return {
    '@version': 'EP-AEC-v1',
    action,
    requirement: policy.requirement,
    components: artifacts.map((evidence) => ({ type: evidence.typ, evidence })),
  };
}

describe('AE-CHALLENGE -07 hostile runtime obligations', () => {
  it('scopes one nonce independently under two authenticated issuer identities', async () => {
    const backend = createMemoryBackend();
    const issuerA = createDurableChallengeStore(backend, {
      issuerIdentity: 'https://issuer-a.example',
    });
    const issuerB = createDurableChallengeStore(backend, {
      issuerIdentity: 'https://issuer-b.example',
    });
    const challenge = {
      '@version': 'AE-CHALLENGE-v1',
      challenge_id: 'issuer-scope-a',
      nonce: 'same-nonce-different-issuer-0001',
      action_digest: artifactDigest(actionA),
      expires_at: expiresAt,
    };

    expect(await issuerA.register(challenge)).toBe(true);
    expect(await issuerB.register({ ...challenge, challenge_id: 'issuer-scope-b' })).toBe(true);
  });

  it('classifies a retained exact-body claim as replay even after challenge expiry', async () => {
    const store = createDurableChallengeStore({ ...createMemoryBackend(), durable: true }, {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'retained-replay-precedence',
      nonce: 'retained-replay-precedence-0001',
      expires_at: expiresAt,
    });
    expect((await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
    })).verdict).toBe('admissible');

    const replay = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: afterExpiry,
    });
    expect(replay.verdict).toBe('refused');
    expect(replay.reasons.join(' ')).toContain('replay');
  });

  it('rederives the digest from the separately held current action before claim', async () => {
    const store = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'current-action-rederivation',
      nonce: 'current-action-rederivation-0001',
      expires_at: expiresAt,
    });

    const result = await evaluateRegisteredPresentation(challenge, completeGraph(actionA), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionB,
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('current proposed action');
  });

  it('distinguishes a different-body nonce collision from an exact-body replay', async () => {
    const store = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'body-collision-a',
      nonce: 'body-collision-shared-nonce-0001',
      expires_at: expiresAt,
    });
    const collision = {
      ...challenge,
      challenge_id: 'body-collision-b',
      action_digest: artifactDigest(actionB),
    };

    const result = await evaluateRegisteredPresentation(collision, completeGraph(actionB), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionB,
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('body collision');
  });

  it('does not relabel an unregistered expired body as an expired registered challenge', async () => {
    const store = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = {
      ...(await createRegisteredEvidenceChallenge(actionA, policy, {
        challengeStore: createDurableChallengeStore(createMemoryBackend(), {
          issuerIdentity: 'https://different-owner.example',
        }),
        challenge_id: 'not-registered-here',
        nonce: 'not-registered-here-0000000001',
        expires_at: expiresAt,
      })),
    };

    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: afterExpiry,
      current_action: actionA,
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('not registered');
    expect(result.reasons.join(' ')).not.toContain('expired');
  });

  it('classifies an expired open different-body attempt as expired, not collision', async () => {
    const store = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'expired-open-body-a',
      nonce: 'expired-open-body-collision-0001',
      expires_at: expiresAt,
    });
    const collision = {
      ...challenge,
      challenge_id: 'expired-open-body-b',
      action_digest: artifactDigest(actionB),
    };

    const result = await evaluateRegisteredPresentation(collision, completeGraph(actionB), policy, {
      challengeStore: store,
      verifiers,
      as_of: afterExpiry,
      current_action: actionB,
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('expired');
    expect(result.reasons.join(' ')).not.toContain('collision');
  });

  it('refuses conflicting legacy and authenticated presenter identities', async () => {
    const store = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'conflicting-presenters',
      nonce: 'conflicting-presenters-000000001',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
    });
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      expected_audience: 'https://legacy-conflict.example',
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('conflicting authenticated presenter');
  });

  it('requires explicit issuer scope and a separately held current action in production', async () => {
    const backend = createMemoryBackend();
    const legacyStore = createDurableChallengeStore(backend);
    await expect(createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: legacyStore,
      challenge_id: 'production-issuer-scope',
      nonce: 'production-issuer-scope-0000001',
      expires_at: expiresAt,
      production: true,
    })).rejects.toThrow(/issuerScoped/);

    const store = createDurableChallengeStore({ ...createMemoryBackend(), durable: true }, {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'production-current-action',
      nonce: 'production-current-action-000001',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: false,
    });
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: {
        ...store,
        async compoundClaimAndCapacity() {
          return { result: 'owner_unavailable' };
        },
      },
      verifiers,
      as_of: beforeExpiry,
      production: true,
      authenticated_presenter: 'https://presenter.example',
    });
    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('current proposed action is required');
  });

  it('uses effective NODE_ENV production mode and refuses a missing presenter', async () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const raw = createDurableChallengeStore({ ...createMemoryBackend(), durable: true }, {
        issuerIdentity: 'https://issuer.example',
      });
      const declared = {
        ...raw,
        async compoundClaimAndCapacity() {
          return { result: 'owner_unavailable' };
        },
      };
      const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
        challengeStore: raw,
        challenge_id: 'effective-production-mode',
        nonce: 'effective-production-mode-0001',
        expires_at: expiresAt,
        audience: 'https://presenter.example',
        production: false,
      });
      const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
        challengeStore: declared,
        verifiers,
        as_of: beforeExpiry,
        current_action: actionA,
      });
      expect(result.verdict).toBe('refused');
      expect(result.reasons.join(' ')).toContain('authenticated presenter is required');
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });

  it('returns typed unavailability when a claim may have committed before timeout', async () => {
    const raw = createDurableChallengeStore(createMemoryBackend(), {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: raw,
      challenge_id: 'timeout-after-commit',
      nonce: 'timeout-after-commit-00000001',
      expires_at: expiresAt,
    });
    let verifierCalls = 0;
    const uncertainStore = {
      ...raw,
      async consume(value) {
        await raw.consume(value);
        throw new Error('timeout_after_commit_unknown');
      },
    };
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: uncertainStore,
      verifiers: new Proxy(verifiers, {
        get(target, property) {
          verifierCalls += 1;
          return target[property];
        },
      }),
      as_of: beforeExpiry,
      current_action: actionA,
    });
    expect(result.verdict).toBe('unavailable');
    expect(result.state_changed).toBe('unknown');
    expect(result.next_challenge).toBeNull();
    expect(verifierCalls).toBe(0);
  });

  it('uses only the compound owner transition in production evaluation', async () => {
    const raw = createDurableChallengeStore({ ...createMemoryBackend(), durable: true }, {
      issuerIdentity: 'https://issuer.example',
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: raw,
      challenge_id: 'compound-production-path',
      nonce: 'compound-production-path-0001',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: false,
    });
    let compoundCalls = 0;
    const productionStore = {
      ...raw,
      async classify() {
        throw new Error('split classification must not run');
      },
      async consume() {
        throw new Error('split consume must not run');
      },
      async compoundClaimAndCapacity(value, context) {
        compoundCalls += 1;
        expect(value).toBe(challenge);
        expect(context).toEqual({
          as_of: beforeExpiry,
          audience: 'https://presenter.example',
          authenticated_presenter: 'https://presenter.example',
        });
        return { result: 'claimed_with_capacity' };
      },
    };
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: productionStore,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
    });
    expect(result.verdict).toBe('admissible');
    expect(compoundCalls).toBe(1);
  });
});
