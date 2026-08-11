// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
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
    policy_digest: policyDigest,
    expires_at: expiresAt,
    audience: 'https://presenter.example',
    present_as: ['ep-aec-v1'],
    required_evidence: [],
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
      followup: { ...followup, required_evidence: [{ type: 'only-new-evidence' }] },
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
