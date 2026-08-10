// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  createRegisteredEvidenceChallenge,
  evaluateRegisteredPresentation,
} from '../lib/negotiate/evidence-challenge.js';
import { artifactDigest } from '../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../lib/evidence/policy-packs.js';
import { challengeStorageKey, createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createMemoryBackend } from '../packages/gate/store.js';
import {
  CONSUMPTION_SQL,
  createPostgresBackend,
} from '../packages/gate/store-postgres.js';

const policy = getPolicyPack('ep:pack:wire-transfer:v1');
const action = { type: 'urn:ep:action:payments.wire_transfer', amount: '250000.00', currency: 'USD' };
const asOf = '2026-07-03T12:01:00Z';
const expiresAt = '2026-07-03T12:10:00Z';
const verifiers = {
  authorization_receipt: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at, revoked: false }),
  policy_permit: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at }),
  workload_identity: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at }),
};

function createLocalPostgresHarness() {
  const rows = new Map<string, { state: string; consumed_at: number; expires_at: number | null }>();
  return {
    rows,
    async query(text, params) {
      await Promise.resolve();
      switch (text) {
        case CONSUMPTION_SQL.addIfAbsent: {
          const [key, state, consumedAt, expiresAt] = params;
          if (rows.has(key)) return { rowCount: 0, rows: [] };
          rows.set(key, { state, consumed_at: consumedAt, expires_at: expiresAt });
          return { rowCount: 1, rows: [] };
        }
        case CONSUMPTION_SQL.compareAndSet: {
          const [key, expected, replacement, consumedAt, expiresAt] = params;
          if (rows.get(key)?.state !== expected) return { rowCount: 0, rows: [] };
          rows.set(key, { state: replacement, consumed_at: consumedAt, expires_at: expiresAt });
          return { rowCount: 1, rows: [] };
        }
        case CONSUMPTION_SQL.has:
          return rows.has(params[0])
            ? { rowCount: 1, rows: [{ present: true }] }
            : { rowCount: 0, rows: [] };
        default:
          throw new Error(`unexpected challenge Postgres statement: ${text}`);
      }
    },
  };
}

function completeGraph() {
  const actionDigest = artifactDigest(action);
  const artifacts = ['authorization_receipt', 'policy_permit', 'workload_identity'].map((typ) => ({
    typ, action: actionDigest, issued_at: '2026-07-03T12:00:00Z',
  }));
  return {
    '@version': 'EP-AEC-v1',
    action,
    requirement: policy.requirement,
    components: artifacts.map((evidence) => ({ type: evidence.typ, evidence })),
  };
}

describe('durable AE-CHALLENGE lifecycle', () => {
  it('atomically registers one exact challenge across 100 concurrent workers', async () => {
    const backend = createMemoryBackend();
    const stores = Array.from({ length: 100 }, () => createDurableChallengeStore(backend));
    const challenge = {
      '@version': 'AE-CHALLENGE-v1', challenge_id: 'challenge-atomic', nonce: 'nonce-atomic',
      action_digest: artifactDigest(action), expires_at: expiresAt,
    };
    const results = await Promise.all(stores.map((store) => store.register(challenge)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('treats the nonce as the replay key even when challenge_id changes', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const first = {
      '@version': 'AE-CHALLENGE-v1', challenge_id: 'correlation-a', nonce: 'nonce-shared-across-ids-0001',
      action_digest: artifactDigest(action), expires_at: expiresAt,
    };
    const second = { ...first, challenge_id: 'correlation-b' };
    expect(challengeStorageKey(first)).toMatch(/^ae-challenge:v2:/);
    expect(challengeStorageKey(second)).toBe(challengeStorageKey(first));
    expect(await store.register(first)).toBe(true);
    expect(await store.register(second)).toBe(false);
    expect(await store.consume(second)).toBe(false);
    expect(await store.consume(first)).toBe(true);
  });

  it('survives restart and admits exactly one concurrent presentation', async () => {
    const backend = createMemoryBackend();
    const issuerStore = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: issuerStore, challenge_id: 'challenge-restart', nonce: 'nonce-restart-0001', expires_at: expiresAt,
    });

    const restartedA = createDurableChallengeStore(backend);
    const restartedB = createDurableChallengeStore(backend);
    const results = await Promise.all([
      evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: restartedA, verifiers, as_of: asOf }),
      evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: restartedB, verifiers, as_of: asOf }),
    ]);
    expect(results.filter((result) => result.verdict === 'admissible')).toHaveLength(1);
    expect(results.filter((result) => result.verdict === 'refused')).toHaveLength(1);
    expect(results.find((result) => result.verdict === 'refused').reasons.join(' ')).toContain('replay');
  });

  it('uses the Postgres durable backend across adapter restart and admits one of 64 concurrent presentations', async () => {
    const postgres = createLocalPostgresHarness();
    const issueBackend = createPostgresBackend({
      query: postgres.query,
      now: () => Date.parse(asOf),
    });
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: createDurableChallengeStore(issueBackend),
      challenge_id: 'challenge-postgres-restart',
      nonce: 'nonce-postgres-restart-0001',
      expires_at: expiresAt,
      production: true,
    });

    const results = await Promise.all(
      Array.from({ length: 64 }, async () => {
        const restartedBackend = createPostgresBackend({
          query: postgres.query,
          now: () => Date.parse(asOf),
        });
        return evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
          challengeStore: createDurableChallengeStore(restartedBackend),
          verifiers,
          as_of: asOf,
          production: true,
        });
      }),
    );

    expect(results.filter((result) => result.verdict === 'admissible')).toHaveLength(1);
    expect(results.filter((result) => result.verdict === 'refused')).toHaveLength(63);
    expect([...postgres.rows.values()].at(-1)?.state).toMatch(/^challenge-consumed:v2:/);
  });

  it('requires every production storage capability and permits only explicit test-only ephemeral mode', async () => {
    const ephemeral = createDurableChallengeStore(createMemoryBackend());
    await expect(createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: ephemeral,
      challenge_id: 'challenge-production-ephemeral-refused',
      nonce: 'nonce-production-refused-0001',
      expires_at: expiresAt,
      production: true,
    })).rejects.toThrow(/durable lifecycle capabilities: durable/);

    const testOnly = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: ephemeral,
      challenge_id: 'challenge-test-only-ephemeral',
      nonce: 'nonce-test-only-ephemeral-0001',
      expires_at: expiresAt,
      production: true,
      test_only_ephemeral: true,
    });
    expect(testOnly.challenge_id).toBe('challenge-test-only-ephemeral');

    const postgres = createLocalPostgresHarness();
    const secure = createDurableChallengeStore(createPostgresBackend({
      query: postgres.query,
      now: () => Date.parse(asOf),
    }));
    for (const capability of [
      'durable',
      'atomicRegistration',
      'bodyBound',
      'permanentConsumption',
    ]) {
      await expect(createRegisteredEvidenceChallenge(action, policy, {
        challengeStore: { ...secure, [capability]: false },
        challenge_id: `challenge-missing-${capability}`,
        nonce: `nonce-missing-${capability}-0001`,
        expires_at: expiresAt,
        production: true,
      })).rejects.toThrow(new RegExp(capability));
    }
  });

  it('binds action, missing evidence, freshness/policy, expiry, nonce, and presentation method', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-body', nonce: 'nonce-body-0000001', expires_at: expiresAt,
    });
    const mutations = [
      { ...challenge, action_digest: `sha256:${'ef'.repeat(32)}` },
      { ...challenge, action_profile: 'https://attacker.example/action-profile' },
      {
        ...challenge,
        required_evidence: challenge.required_evidence.map((entry, index) => (
          index === 0 ? { ...entry, max_age_sec: 1 } : entry
        )),
      },
      { ...challenge, policy_digest: `sha256:${'cd'.repeat(32)}` },
      { ...challenge, expires_at: '2026-07-03T12:11:00Z' },
      { ...challenge, nonce: 'nonce-body-tampered-0001' },
      { ...challenge, present_as: ['EP-AEG-v1'] },
    ];
    for (const tampered of mutations) {
      const refused = await evaluateRegisteredPresentation(
        tampered,
        completeGraph(),
        policy,
        { challengeStore: store, verifiers, as_of: asOf },
      );
      expect(refused.verdict).toBe('refused');
    }

    const original = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: store, verifiers, as_of: asOf });
    expect(original.verdict).toBe('admissible');
  });

  it('refuses an action swap without consuming the registered challenge', async () => {
    const store = createDurableChallengeStore(createMemoryBackend());
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store,
      challenge_id: 'challenge-first-valid-attempt',
      nonce: 'nonce-first-valid-attempt-0001',
      expires_at: expiresAt,
    });
    const swapped = {
      ...completeGraph(),
      action: { ...action, amount: '250000.01' },
    };
    const first = await evaluateRegisteredPresentation(challenge, swapped, policy, {
      challengeStore: store,
      verifiers,
      as_of: asOf,
    });
    expect(first.verdict).toBe('refused');
    expect(first.reasons.join(' ')).toContain('action swap');

    const retry = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store,
      verifiers,
      as_of: asOf,
    });
    expect(retry.verdict).toBe('admissible');
  });

  it('refuses policy drift without consuming the registered challenge', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-policy', nonce: 'nonce-policy-00001', expires_at: expiresAt,
    });
    const weakened = { ...policy, requirement: 'authorization_receipt' };
    const refused = await evaluateRegisteredPresentation(challenge, completeGraph(), weakened, {
      challengeStore: store, verifiers, as_of: asOf,
    });
    expect(refused.verdict).toBe('refused');
    expect(refused.reasons.join(' ')).toContain('policy');

    const original = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store, verifiers, as_of: asOf,
    });
    expect(original.verdict).toBe('admissible');
  });

  it('registers a missing-evidence follow-up before returning it', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-followup', nonce: 'nonce-first-000001', expires_at: expiresAt,
    });
    const partial = {
      ...completeGraph(),
      components: completeGraph().components.slice(0, 1),
    };
    const first = await evaluateRegisteredPresentation(challenge, partial, policy, {
      challengeStore: store, verifiers, as_of: asOf, nonce: 'nonce-second-00001',
    });
    expect(first.verdict).toBe('missing_evidence');
    expect(await createDurableChallengeStore(backend).has(first.next_challenge)).toBe(true);
  });

  it('refuses weak caller-supplied nonces before durable registration', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    await expect(createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store,
      challenge_id: 'challenge-weak-nonce',
      nonce: 'too-short',
      expires_at: expiresAt,
    })).rejects.toThrow(/16-128 base64url/);
  });

  it('propagates backend outage without an in-memory fallback', async () => {
    const outage = new Error('durable_challenge_backend_unavailable');
    const backend = {
      async addIfAbsent() { throw outage; },
      async compareAndSet() { throw outage; },
      async has() { throw outage; },
    };
    const store = createDurableChallengeStore(backend);
    await expect(createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-outage', nonce: 'nonce-outage-00001', expires_at: expiresAt,
    })).rejects.toThrow(/backend_unavailable/);
  });
});
