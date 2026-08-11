// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CHALLENGE_PRESENTATION_METHOD,
  createRegisteredEvidenceChallenge,
  createEvidenceChallenge,
  evaluateRegisteredPresentation,
} from '../lib/negotiate/evidence-challenge.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../lib/evidence/policy-packs.js';
import {
  createAuthoritativeChallengeOwnerStore,
  createDurableChallengeStore,
  createMemoryChallengeOwnerBackend,
} from '../packages/gate/challenge-store.js';
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
const testNonce = (label) => crypto.createHash('sha256').update(label).digest('base64url').slice(0, 24);
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

function createTestOwner(now = () => Date.parse(beforeExpiry), cap = 8) {
  const backend = createMemoryChallengeOwnerBackend({ now });
  const store = createAuthoritativeChallengeOwnerStore(
    { ...backend, durable: true },
    {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: (challenge) => [
        { key: 'aggregate', limit: cap },
        { key: `audience:${challenge.audience ?? 'none'}`, limit: cap },
      ],
      recoveryAuthorizer: () => false,
    },
  );
  return { backend, store };
}

describe('AE-CHALLENGE -07 hostile runtime obligations', () => {
  it('emits only absolute URI identifiers in the transport-neutral wire object', () => {
    const challenge = createEvidenceChallenge(actionA, policy, {
      expires_at: expiresAt,
      audience: 'https://presenter.example',
    });
    const absolute = (value) => {
      expect(() => new URL(value)).not.toThrow();
      expect(new URL(value).protocol.length).toBeGreaterThan(1);
    };

    absolute(challenge.action_profile);
    absolute(challenge.policy_id);
    expect(challenge.present_as).toEqual([CHALLENGE_PRESENTATION_METHOD]);
    challenge.present_as.forEach(absolute);
    for (const requirement of challenge.required_evidence) {
      absolute(requirement.type);
      requirement.profiles?.forEach(absolute);
      requirement.proof_predicates?.forEach(absolute);
    }
  });

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
      nonce: testNonce('same-nonce-different-issuer'),
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
      nonce: testNonce('retained-replay-precedence'),
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
      nonce: testNonce('current-action-rederivation'),
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
      nonce: testNonce('body-collision-shared'),
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
        nonce: testNonce('not-registered-here'),
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
      nonce: testNonce('expired-open-body-collision'),
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
      nonce: testNonce('conflicting-presenters'),
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
    })).rejects.toThrow(/authoritative owner store/);

    const { store } = createTestOwner();
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'production-current-action',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
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
      const { store } = createTestOwner();
      const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
        challengeStore: store,
        challenge_id: 'effective-production-mode',
        expires_at: expiresAt,
        audience: 'https://presenter.example',
        production: false,
      });
      const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
        challengeStore: store,
        verifiers,
        as_of: beforeExpiry,
        current_action: actionA,
        production: false,
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
      nonce: testNonce('timeout-after-commit'),
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
    const { backend, store } = createTestOwner();
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'compound-production-path',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
    });
    expect(result.verdict).toBe('admissible');
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
  });

  it('uses authoritative owner time, not caller time, for evidence freshness', async () => {
    const ownerTime = Date.parse('2026-07-03T12:09:00Z');
    const { store } = createTestOwner(() => ownerTime);
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      challenge_id: 'authoritative-evidence-time',
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });

    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      // A caller-controlled old time would incorrectly make the receipt look fresh.
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
    });
    expect(result.verdict).toBe('stale');
    expect(result.result.replay.as_of).toBe('2026-07-03T12:09:00.000Z');
  });

  it('rejects a caller-selected production follow-up nonce before claiming owner state', async () => {
    const { backend, store } = createTestOwner();
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });
    const result = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
      nonce: testNonce('attacker-selected-followup'),
    });

    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('generated internally');
    expect([...backend.records.values()][0]?.state).toBe('open');
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
  });

  it('terminalizes owner state when a local follow-up configuration is malformed', async () => {
    const { backend, store } = createTestOwner();
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });
    const partial = {
      ...completeGraph(),
      components: completeGraph().components.slice(0, 1),
    };
    const result = await evaluateRegisteredPresentation(challenge, partial, policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
      next_expires_at: 'not-a-timestamp',
    });

    expect(result.verdict).toBe('refused');
    expect(result.reasons.join(' ')).toContain('follow-up challenge could not be safely created');
    expect([...backend.records.values()][0]?.state).toBe('finalized');
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
  });

  it('returns no follow-up when owner finalization committed but its acknowledgement was lost', async () => {
    const base = createMemoryChallengeOwnerBackend({ now: () => Date.parse(beforeExpiry) });
    let transactions = 0;
    const uncertainBackend = {
      ...base,
      durable: true,
      async transaction(work) {
        transactions += 1;
        const result = await base.transaction(work);
        if (transactions === 3) throw new Error('finalization_ack_lost');
        return result;
      },
    };
    const store = createAuthoritativeChallengeOwnerStore(uncertainBackend, {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: () => [{ key: 'aggregate', limit: 4 }],
      recoveryAuthorizer: () => false,
    });
    const challenge = await createRegisteredEvidenceChallenge(actionA, policy, {
      challengeStore: store,
      expires_at: expiresAt,
      audience: 'https://presenter.example',
      production: true,
    });
    const partial = {
      ...completeGraph(),
      components: completeGraph().components.slice(0, 1),
    };
    const result = await evaluateRegisteredPresentation(challenge, partial, policy, {
      challengeStore: store,
      verifiers,
      as_of: beforeExpiry,
      current_action: actionA,
      authenticated_presenter: 'https://presenter.example',
      production: true,
    });
    expect(result).toMatchObject({
      verdict: 'unavailable',
      state_changed: 'unknown',
      next_challenge: null,
    });
    expect(base.records.size).toBe(2);
  });
});
