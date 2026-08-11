// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  createAuthoritativeChallengeOwnerStore,
  createMemoryChallengeOwnerBackend,
  isAuthoritativeChallengeOwnerStore,
} from '../packages/gate/challenge-store.js';

const nonce = (label) => crypto.createHash('sha256').update(label).digest('base64url').slice(0, 24);
const bodyDigest = `sha256:${'ab'.repeat(32)}`;
const policyDigest = `sha256:${'cd'.repeat(32)}`;
const actionDigest = `sha256:${'ef'.repeat(32)}`;

function challenge(label, expiresAt = '2026-07-03T12:10:00Z') {
  return {
    '@version': 'AE-CHALLENGE-v1',
    challenge_id: label,
    nonce: nonce(label),
    action_digest: actionDigest,
    action_profile: 'https://emiliaprotocol.ai/profiles/artifact-digest-v1',
    policy_id: 'https://issuer.example/policies/test-v1',
    policy_digest: policyDigest,
    expires_at: expiresAt,
    audience: 'https://presenter.example',
    present_as: ['https://emiliaprotocol.ai/profiles/ep-aec-v1'],
    required_evidence: [{
      requirement_id: 'authorization',
      type: 'https://emiliaprotocol.ai/ns/evidence-type/authorization_receipt',
    }],
    body_digest: bodyDigest,
  };
}

function fixture({ cap = 8, now = Date.parse('2026-07-03T12:01:00Z') } = {}) {
  const clock = { now };
  const backend = createMemoryChallengeOwnerBackend({ now: () => clock.now });
  let tokenCounter = 0;
  const store = createAuthoritativeChallengeOwnerStore(
    { ...backend, durable: true },
    {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: () => [{ key: 'aggregate', limit: cap }],
      ownerTokenFactory: () => `owner-token-${String(++tokenCounter).padStart(32, '0')}`,
      recoveryAuthorizer: (authorization) => authorization === 'operator-approved',
      recoveryAfterMs: 1_000,
    },
  );
  return { backend, clock, store };
}

function presenterScopedFixture({ cap = 8 } = {}) {
  const backend = createMemoryChallengeOwnerBackend({
    now: () => Date.parse('2026-07-03T12:01:00Z'),
  });
  const store = createAuthoritativeChallengeOwnerStore(
    { ...backend, durable: true },
    {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: (_challenge, context) => [
        { key: 'aggregate', limit: cap },
        { key: `presenter:${context.authenticated_presenter ?? 'anonymous'}`, limit: cap },
      ],
      recoveryAuthorizer: () => false,
    },
  );
  return { backend, store };
}

describe('AE-CHALLENGE authoritative owner contract', () => {
  it('does not let a spread copy impersonate the branded production store', () => {
    const { store } = fixture();
    expect(isAuthoritativeChallengeOwnerStore(store)).toBe(true);
    expect(isAuthoritativeChallengeOwnerStore({ ...store })).toBe(false);
  });

  it('claims one duplicate, reports the other as replay, and debits once', async () => {
    const { backend, store } = fixture({ cap: 2 });
    const value = challenge('duplicate');
    expect(await store.registerOutstanding(value)).toBe(true);
    const [a, b] = await Promise.all([
      store.compoundClaimAndCapacity(value, { authenticated_presenter: value.audience }),
      store.compoundClaimAndCapacity(value, { authenticated_presenter: value.audience }),
    ]);
    expect([a.result, b.result].sort()).toEqual(['claimed_with_capacity', 'exact_body_replay']);
    expect(backend.capacity.get('aggregate')?.used).toBe(2);
  });

  it('preserves replay and capacity invariants across randomized bucket sets', async () => {
    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 2, max: 8 }),
      fc.uniqueArray(fc.constantFrom(
        'aggregate', 'constructor', 'toString', 'A-upper', 'a-lower', 'tenant:1',
      ), { minLength: 1, maxLength: 6 }),
      fc.integer({ min: 0, max: 1_000_000 }),
      async (cap, bucketKeys, sample) => {
        const backend = createMemoryChallengeOwnerBackend({
          now: () => Date.parse('2026-07-03T12:01:00Z'),
        });
        const store = createAuthoritativeChallengeOwnerStore(
          { ...backend, durable: true },
          {
            issuerIdentity: 'https://issuer.example',
            capacityPolicy: () => bucketKeys.map((key) => ({ key, limit: cap })),
            recoveryAuthorizer: () => false,
          },
        );
        const value = challenge(`property-${sample}`);
        expect(await store.registerOutstanding(value, {
          authenticated_presenter: value.audience,
        })).toBe(true);

        const attempts = await Promise.all([
          store.compoundClaimAndCapacity(value, { authenticated_presenter: value.audience }),
          store.compoundClaimAndCapacity(value, { authenticated_presenter: value.audience }),
        ]);
        expect(attempts.map(({ result }) => result).sort()).toEqual([
          'claimed_with_capacity', 'exact_body_replay',
        ]);
        for (const key of bucketKeys) expect(backend.capacity.get(key)?.used).toBe(2);

        const collision = await store.compoundClaimAndCapacity({
          ...value,
          challenge_id: `${value.challenge_id}-collision`,
        }, { authenticated_presenter: value.audience });
        expect(collision.result).toBe('nonce_body_collision');
        for (const key of bucketKeys) expect(backend.capacity.get(key)?.used).toBe(2);

        const claimed = attempts.find(({ result }) => result === 'claimed_with_capacity');
        await expect(store.finalizeReservation(claimed?.reservation, {
          outcome: 'property_terminal',
        })).resolves.toMatchObject({ result: 'finalized' });
        for (const key of bucketKeys) expect(backend.capacity.get(key)?.used).toBe(1);
      },
    ), { numRuns: 100 });
  });

  it('pins authenticated presenter capacity at issuance and preserves it through finalization', async () => {
    const { backend, store } = presenterScopedFixture({ cap: 2 });
    const value = challenge('stable-presenter-capacity');
    const authenticatedPresenter = 'principal:alice';

    expect(await store.registerOutstanding(value, {
      authenticated_presenter: authenticatedPresenter,
    })).toBe(true);
    expect(backend.capacity.get(`presenter:${authenticatedPresenter}`)?.used).toBe(1);
    expect(backend.capacity.has(`presenter:${value.audience}`)).toBe(false);

    const claimed = await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: authenticatedPresenter,
    });
    expect(claimed.result).toBe('claimed_with_capacity');
    expect(backend.capacity.get(`presenter:${authenticatedPresenter}`)?.used).toBe(2);

    await expect(store.finalizeReservation(claimed.reservation, {
      outcome: 'admissible',
    })).resolves.toMatchObject({ result: 'finalized' });
    expect(backend.capacity.get(`presenter:${authenticatedPresenter}`)?.used).toBe(1);
  });

  it('supports an action-scoped reissue budget that fresh nonces cannot reset', async () => {
    const backend = createMemoryChallengeOwnerBackend({
      now: () => Date.parse('2026-07-03T12:01:00Z'),
    });
    const store = createAuthoritativeChallengeOwnerStore(
      { ...backend, durable: true },
      {
        issuerIdentity: 'https://issuer.example',
        capacityPolicy: (value, context) => {
          const scope = crypto.createHash('sha256').update(JSON.stringify([
            context.authenticated_presenter,
            value.action_profile,
            value.action_digest,
            value.policy_digest,
          ])).digest('hex');
          return [{ key: `reissue:${scope}`, limit: 2 }];
        },
        recoveryAuthorizer: () => false,
      },
    );
    const presenter = 'principal:alice';

    expect(await store.registerOutstanding(challenge('reissue-1'), {
      authenticated_presenter: presenter,
    })).toBe(true);
    expect(await store.registerOutstanding(challenge('reissue-2'), {
      authenticated_presenter: presenter,
    })).toBe(true);
    expect(await store.registerOutstanding(challenge('reissue-3'), {
      authenticated_presenter: presenter,
    })).toBe(false);

    const differentAction = {
      ...challenge('different-action'),
      action_digest: `sha256:${'12'.repeat(32)}`,
    };
    expect(await store.registerOutstanding(differentAction, {
      authenticated_presenter: presenter,
    })).toBe(true);
  });

  it('accounts safely for valid bucket names that collide with Object.prototype', async () => {
    const backend = createMemoryChallengeOwnerBackend({
      now: () => Date.parse('2026-07-03T12:01:00Z'),
    });
    const store = createAuthoritativeChallengeOwnerStore(
      { ...backend, durable: true },
      {
        issuerIdentity: 'https://issuer.example',
        capacityPolicy: () => [
          { key: 'constructor', limit: 2 },
          { key: 'toString', limit: 2 },
        ],
        recoveryAuthorizer: () => false,
      },
    );
    const value = challenge('prototype-shaped-capacity-keys');

    expect(await store.registerOutstanding(value)).toBe(true);
    const claimed = await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    });
    expect(claimed.result).toBe('claimed_with_capacity');
    await expect(store.finalizeReservation(claimed.reservation, {
      outcome: 'admissible',
    })).resolves.toMatchObject({ result: 'finalized' });
    expect(backend.capacity.get('constructor')?.used).toBe(1);
    expect(backend.capacity.get('toString')?.used).toBe(1);
  });

  it('leaves the nonce open and all counters unchanged when reservation capacity is full', async () => {
    const { backend, store } = fixture({ cap: 1 });
    const value = challenge('capacity-refusal');
    expect(await store.registerOutstanding(value)).toBe(true);
    expect((await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    })).result).toBe('capacity_refused');
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
    expect((await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    })).result).toBe('capacity_refused');
  });

  it('uses owner time for expiry and ignores any caller clock fiction', async () => {
    const { store } = fixture({ now: Date.parse('2026-07-03T12:11:00Z') });
    const value = challenge('owner-expired');
    expect(await store.registerOutstanding(value)).toBe(false);
  });

  it('rejects nonconforming wire bodies before allocating replay or capacity state', async () => {
    const mutations = [
      { present_as: ['ep-aec-v1'] },
      { required_evidence: [{ requirement_id: 'x', type: 'authorization_receipt' }] },
      {
        required_evidence: [
          { requirement_id: 'same', type: 'https://example.net/evidence/a' },
          { requirement_id: 'same', type: 'https://example.net/evidence/b' },
        ],
      },
      {
        required_evidence: [{
          requirement_id: 'x',
          type: 'https://example.net/evidence/a',
          attacker_extension: true,
        }],
      },
      { retry_timing: { not_before: '2026-07-03T12:09:59Z', jitter_sec: 2 } },
      { critical: ['experimental_extension'], experimental_extension: true },
    ];

    for (const [index, mutation] of mutations.entries()) {
      const { backend, store } = fixture();
      await expect(store.registerOutstanding({
        ...challenge(`malformed-${index}`),
        ...mutation,
      })).rejects.toThrow();
      expect(backend.records.size).toBe(0);
      expect(backend.capacity.size).toBe(0);
    }
  });

  it('detects stored body corruption before claim or evidence evaluation', async () => {
    const { backend, store } = fixture();
    const value = challenge('stored-body-corruption');
    await store.registerOutstanding(value);
    const [key, record] = [...backend.records.entries()][0];
    backend.records.set(key, {
      ...record,
      challenge: {
        ...record.challenge,
        policy_id: 'https://attacker.example/weakened-policy',
      },
    });

    await expect(store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    })).rejects.toThrow(/body binding/);
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
  });

  it('rejects non-record capacity vectors returned by the owner backend', async () => {
    const { backend, store } = fixture();
    const value = challenge('stored-vector-corruption');
    await store.registerOutstanding(value);
    const [key, record] = [...backend.records.entries()][0];
    backend.records.set(key, {
      ...record,
      units: [1] as unknown as Record<string, number>,
    });

    await expect(store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    })).rejects.toThrow(/malformed record/);
  });

  it('atomically finalizes a follow-up and keeps only the exact resulting capacity', async () => {
    const { backend, store } = fixture({ cap: 2 });
    const first = challenge('first');
    const followup = challenge('followup');
    expect(await store.registerOutstanding(first)).toBe(true);
    const claimed = await store.compoundClaimAndCapacity(first, {
      authenticated_presenter: first.audience,
    });
    expect(claimed.result).toBe('claimed_with_capacity');
    expect(await store.finalizeReservation(claimed.reservation, {
      outcome: 'missing_evidence',
      followup,
    })).toMatchObject({ result: 'finalized' });
    expect(backend.capacity.get('aggregate')?.used).toBe(2);
    expect((await store.compoundClaimAndCapacity(followup, {
      authenticated_presenter: followup.audience,
    })).result).toBe('capacity_refused');
  });

  it('refuses a follow-up that changes the owner-bound action or complete requirement set', async () => {
    const { store } = fixture({ cap: 2 });
    const first = challenge('bound-first');
    const followup = challenge('bound-followup');
    await store.registerOutstanding(first);
    const claimed = await store.compoundClaimAndCapacity(first, {
      authenticated_presenter: first.audience,
    });
    await expect(store.finalizeReservation(claimed.reservation, {
      outcome: 'missing_evidence',
      followup: { ...followup, action_digest: `sha256:${'11'.repeat(32)}` },
    })).rejects.toThrow(/changed the bound action/);
    await expect(store.finalizeReservation(claimed.reservation, {
      outcome: 'missing_evidence',
      followup: {
        ...followup,
        required_evidence: [{
          requirement_id: 'only-new-evidence',
          type: 'https://example.net/evidence/only-new-evidence',
        }],
      },
    })).rejects.toThrow(/changed the bound action/);
    await expect(store.finalizeReservation(claimed.reservation, {
      outcome: 'missing_evidence',
      followup,
    })).resolves.toMatchObject({ result: 'finalized' });
  });

  it('releases unused reservation capacity after a terminal result', async () => {
    const { backend, store } = fixture({ cap: 2 });
    const value = challenge('terminal');
    await store.registerOutstanding(value);
    const claimed = await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    });
    await store.finalizeReservation(claimed.reservation, { outcome: 'admissible' });
    expect(backend.capacity.get('aggregate')?.used).toBe(1);
  });

  it('fences a stale worker after deadline-gated recovery', async () => {
    const { clock, store } = fixture({ cap: 2 });
    const value = challenge('recovery');
    await store.registerOutstanding(value);
    const original = await store.compoundClaimAndCapacity(value, {
      authenticated_presenter: value.audience,
    });
    clock.now += 1_001;
    expect((await store.recoverReservation(value)).result).toBe('recovery_unauthorized');
    const recovered = await store.recoverReservation(value, { authorization: 'operator-approved' });
    expect(recovered.result).toBe('recovered');
    await expect(store.finalizeReservation(original.reservation, {
      outcome: 'admissible',
    })).rejects.toThrow(/ownership fence/);
    await expect(store.finalizeReservation(recovered.reservation, {
      outcome: 'recovered_refusal',
    })).resolves.toMatchObject({ result: 'finalized' });
  });
});
