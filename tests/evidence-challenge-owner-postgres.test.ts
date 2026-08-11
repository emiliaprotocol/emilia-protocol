// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  createAuthoritativeChallengeOwnerStore,
} from '../packages/gate/challenge-store.js';
import {
  AE_CHALLENGE_OWNER_DDL,
  AE_CHALLENGE_POSTGRES_OWNER_VERSION,
  AE_CHALLENGE_POSTGRES_SQL,
  createPostgresChallengeOwnerBackend,
} from '../packages/gate/challenge-store-postgres.js';

function fakePool(
  nowMs = Date.parse('2026-07-03T12:01:00Z'),
  { reverseCapacityRows = false } = {},
) {
  const locks = new Set<string>();
  const records = new Map<string, string>();
  const capacity = new Map<string, { used: number; limit: number }>();
  let tail = Promise.resolve();
  return {
    state: { locks, records, capacity },
    async connect() {
      let unlock: (() => void) | null = null;
      let snapshots: any = null;
      return {
        async query(text, params = []) {
          if (text === AE_CHALLENGE_POSTGRES_SQL.begin) {
            const prior = tail;
            tail = new Promise<void>((resolve) => { unlock = resolve; });
            await prior;
            snapshots = {
              locks: new Set(locks),
              records: new Map(records),
              capacity: new Map([...capacity].map(([key, value]) => [key, { ...value }])),
            };
            return { rowCount: null, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.commit) {
            snapshots = null;
            unlock?.();
            unlock = null;
            return { rowCount: null, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.rollback) {
            if (snapshots) {
              locks.clear(); records.clear(); capacity.clear();
              for (const value of snapshots.locks) locks.add(value);
              for (const [key, value] of snapshots.records) records.set(key, value);
              for (const [key, value] of snapshots.capacity) capacity.set(key, value);
            }
            snapshots = null;
            unlock?.();
            unlock = null;
            return { rowCount: null, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.health) {
            return { rowCount: 1, rows: [{ locks_ready: true, records_ready: true, capacity_ready: true }] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.authoritativeNow) {
            return { rowCount: 1, rows: [{ now_ms: String(nowMs) }] };
          }
          const scoped = (owner, key) => `${owner}\u0000${key}`;
          if (text === AE_CHALLENGE_POSTGRES_SQL.ensureChallengeLock) {
            const key = scoped(params[0], params[1]);
            const fresh = !locks.has(key);
            locks.add(key);
            return { rowCount: fresh ? 1 : 0, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.lockChallenge) {
            return { rowCount: 1, rows: [{ replay_key: params[1] }] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.readChallenge) {
            const value = records.get(scoped(params[0], params[1]));
            return value === undefined
              ? { rowCount: 0, rows: [] }
              : { rowCount: 1, rows: [{ record_json: value }] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.insertChallenge) {
            const key = scoped(params[0], params[1]);
            if (records.has(key)) return { rowCount: 0, rows: [] };
            records.set(key, params[2]);
            return { rowCount: 1, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.writeChallenge) {
            const key = scoped(params[0], params[1]);
            if (!records.has(key)) return { rowCount: 0, rows: [] };
            records.set(key, params[2]);
            return { rowCount: 1, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.ensureCapacity) {
            const key = scoped(params[0], params[1]);
            if (capacity.has(key)) return { rowCount: 0, rows: [] };
            capacity.set(key, { used: 0, limit: params[2] });
            return { rowCount: 1, rows: [] };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.lockCapacity) {
            const keys = [...params[1]].sort();
            if (reverseCapacityRows) keys.reverse();
            return {
              rowCount: keys.length,
              rows: keys.map((key) => {
                const row = capacity.get(scoped(params[0], key));
                return { bucket_key: key, used_units: String(row?.used), hard_limit: String(row?.limit) };
              }),
            };
          }
          if (text === AE_CHALLENGE_POSTGRES_SQL.writeCapacity) {
            const key = scoped(params[0], params[1]);
            const row = capacity.get(key);
            if (!row || params[2] > row.limit) return { rowCount: 0, rows: [] };
            capacity.set(key, { ...row, used: params[2] });
            return { rowCount: 1, rows: [] };
          }
          throw new Error(`unexpected AE challenge PostgreSQL statement: ${text}`);
        },
        release() {
          unlock?.();
          unlock = null;
        },
      };
    },
  };
}

function value(label) {
  return {
    '@version': 'AE-CHALLENGE-v1',
    challenge_id: label,
    nonce: Buffer.from(`nonce:${label}:0123456789`).toString('base64url'),
    action_digest: `sha256:${'ab'.repeat(32)}`,
    action_profile: 'https://emiliaprotocol.ai/profiles/artifact-digest-v1',
    policy_id: 'https://issuer.example/policies/test-v1',
    policy_digest: `sha256:${'cd'.repeat(32)}`,
    expires_at: '2026-07-03T12:10:00Z',
    audience: 'https://presenter.example',
    present_as: ['https://emiliaprotocol.ai/profiles/ep-aec-v1'],
    required_evidence: [{
      requirement_id: 'authorization',
      type: 'https://emiliaprotocol.ai/ns/evidence-type/authorization_receipt',
    }],
  };
}

describe('AE-CHALLENGE PostgreSQL owner backend', () => {
  it('declares the three-table owner schema and database transaction clock', () => {
    expect(AE_CHALLENGE_OWNER_DDL.match(/CREATE TABLE/g)).toHaveLength(3);
    expect(AE_CHALLENGE_POSTGRES_SQL.authoritativeNow).toContain('transaction_timestamp()');
    expect(AE_CHALLENGE_POSTGRES_SQL.lockCapacity).toContain('FOR UPDATE');
  });

  it('reports schema readiness and executes issue, claim, and fenced finalization', async () => {
    const pool = fakePool();
    const backend = createPostgresChallengeOwnerBackend({ pool, ownerId: 'tenant-a' });
    expect(await backend.health()).toEqual({ ok: true, version: AE_CHALLENGE_POSTGRES_OWNER_VERSION });
    const store = createAuthoritativeChallengeOwnerStore(backend, {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: () => [{ key: 'aggregate', limit: 2 }],
      ownerTokenFactory: () => 'postgres-owner-token-00000000000000000000',
      recoveryAuthorizer: () => false,
    });
    const challenge = value('postgres');
    expect(await store.registerOutstanding(challenge)).toBe(true);
    const claimed = await store.compoundClaimAndCapacity(challenge, {
      authenticated_presenter: challenge.audience,
    });
    expect(claimed.result).toBe('claimed_with_capacity');
    expect(await store.finalizeReservation(claimed.reservation, {
      outcome: 'admissible',
    })).toMatchObject({ result: 'finalized' });
    expect((await store.compoundClaimAndCapacity(challenge, {
      authenticated_presenter: challenge.audience,
    })).result).toBe('exact_body_replay');
    expect(pool.state.capacity.get('tenant-a\u0000aggregate')?.used).toBe(1);
  });

  it('does not depend on JavaScript and PostgreSQL using the same collation order', async () => {
    const pool = fakePool(Date.parse('2026-07-03T12:01:00Z'), {
      reverseCapacityRows: true,
    });
    const backend = createPostgresChallengeOwnerBackend({ pool, ownerId: 'tenant-collation' });
    const store = createAuthoritativeChallengeOwnerStore(backend, {
      issuerIdentity: 'https://issuer.example',
      capacityPolicy: () => [
        { key: 'A-upper', limit: 2 },
        { key: 'a-lower', limit: 2 },
      ],
      recoveryAuthorizer: () => false,
    });
    const challenge = value('postgres-collation');

    expect(await store.registerOutstanding(challenge)).toBe(true);
    const claimed = await store.compoundClaimAndCapacity(challenge, {
      authenticated_presenter: challenge.audience,
    });
    expect(claimed.result).toBe('claimed_with_capacity');
  });
});
