// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  statusArtifactDigest,
  type StatusTarget,
  type StatusVerification,
} from '@emilia-protocol/verify/status';

import {
  PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL,
  createPostgresProposalToEffectStatusHeadStore,
  type ProposalToEffectStatusHeadPgClient,
  type ProposalToEffectStatusHeadPgPool,
} from './proposal-to-effect-status-head-store.js';

const TARGET: StatusTarget = Object.freeze({
  type: 'receipt',
  id: 'receipt:payment-release:0001',
  digest: `sha256:${'a'.repeat(64)}`,
  usage: 'authorization',
});

function status(sequence: number, previousStatusDigest: string | null) {
  return {
    '@version': 'EP-STATUS-v1',
    authority_domain: 'status.acme.example',
    revoker_authority_digest: `sha256:${'b'.repeat(64)}`,
    target: structuredClone(TARGET),
    status: 'not_revoked',
    sequence,
    previous_status_digest: previousStatusDigest,
    issued_at: `2026-07-22T12:0${sequence}:00Z`,
    next_update: '2026-07-22T12:30:00Z',
    proof: {
      algorithm: 'Ed25519',
      key_id: `ep:revoker-key:sha256:${'c'.repeat(64)}`,
      signature_b64u: 'dGVzdA',
    },
  };
}

function verified(candidate: ReturnType<typeof status>): StatusVerification {
  return {
    outcome: 'current_not_revoked',
    valid: true,
    checks: {
      structure: true,
      certificate: true,
      authority: true,
      target: true,
      scope: true,
      signature: true,
      freshness: true,
      sequence: true,
      terminal: true,
    },
    reasons: [],
    status_digest: statusArtifactDigest(candidate),
    sequence: candidate.sequence,
    next_update: candidate.next_update,
  };
}

type Handler = (
  text: string,
  params: any[] | undefined,
) => Promise<{ rowCount: number; rows?: Record<string, unknown>[] }>;

function pool(handler: Handler) {
  const calls: Array<{ text: string; params: any[] | undefined }> = [];
  let releases = 0;
  const client: ProposalToEffectStatusHeadPgClient = {
    async query(text, params) {
      calls.push({ text, params });
      return handler(text, params);
    },
    release() {
      releases += 1;
    },
  };
  const value: ProposalToEffectStatusHeadPgPool = {
    async connect() {
      return client;
    },
  };
  return {
    pool: value,
    calls,
    releases: () => releases,
  };
}

function row(
  current: ReturnType<typeof status>,
  predecessor: ReturnType<typeof status> | null,
) {
  return {
    status_digest: statusArtifactDigest(current),
    sequence: String(current.sequence),
    status_state: current.status,
    previous_status_digest: current.previous_status_digest,
    issued_at: new Date(current.issued_at).toISOString(),
    next_update: current.next_update === null
      ? null : new Date(current.next_update).toISOString(),
    status_json: JSON.stringify(current),
    predecessor_status_json: predecessor === null
      ? null : JSON.stringify(predecessor),
  };
}

test('atomically accepts the genesis status under the fixed tenant, relying party, and target', async () => {
  const candidate = status(0, null);
  const pg = pool(async (text, params) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      assert.deepEqual(params, [
        'tenant:acme',
        'rp:gate-1',
        TARGET.type,
        TARGET.id,
        TARGET.digest,
        TARGET.usage,
      ]);
      return { rowCount: 0, rows: [] };
    }
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance) {
      assert.deepEqual(params, [
        'tenant:acme',
        'rp:gate-1',
        TARGET.type,
        TARGET.id,
        TARGET.digest,
        TARGET.usage,
        null,
        statusArtifactDigest(candidate),
        0,
        'not_revoked',
        null,
        '2026-07-22T12:00:00.000Z',
        '2026-07-22T12:30:00.000Z',
        JSON.stringify(candidate),
      ]);
      return { rowCount: 1, rows: [{ accepted: true, reason: null }] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: pg.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });

  let previous: unknown = Symbol('unobserved');
  const result = await store.accept({
    target: TARGET,
    status: candidate,
    verify: (authenticatedPrevious) => {
      previous = authenticatedPrevious;
      return verified(candidate);
    },
  });

  assert.equal(previous, undefined);
  assert.equal(result.accepted, true);
  assert.equal(result.source, 'advanced');
  assert.equal(result.reason, null);
  assert.equal(result.verification.status_digest, statusArtifactDigest(candidate));
  assert.equal(pg.releases(), 1);
});

test('verifies a successor only against the server-held current head', async () => {
  const first = status(0, null);
  const next = status(1, statusArtifactDigest(first));
  const pg = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      return { rowCount: 1, rows: [row(first, null)] };
    }
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance) {
      return { rowCount: 1, rows: [{ accepted: true, reason: null }] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: pg.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });

  let observedPrevious: unknown;
  const result = await store.accept({
    target: TARGET,
    status: next,
    verify: (authenticatedPrevious) => {
      observedPrevious = authenticatedPrevious;
      return verified(next);
    },
  });

  assert.deepEqual(observedPrevious, first);
  assert.equal(result.accepted, true);
  assert.equal(result.source, 'advanced');
});

test('re-verifies an already accepted head and confirms it still wins the database comparison', async () => {
  const first = status(0, null);
  const next = status(1, statusArtifactDigest(first));
  const pg = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      return { rowCount: 1, rows: [row(next, first)] };
    }
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance) {
      return { rowCount: 1, rows: [{ accepted: true, reason: null }] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: pg.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });

  let observedPrevious: unknown;
  const result = await store.accept({
    target: TARGET,
    status: structuredClone(next),
    verify: (authenticatedPrevious) => {
      observedPrevious = authenticatedPrevious;
      return verified(next);
    },
  });

  assert.deepEqual(observedPrevious, first);
  assert.equal(result.accepted, true);
  assert.equal(result.source, 'existing');
  assert.equal(
    pg.calls.some(({ text }) => text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance),
    true,
  );
});

test('does not advance when verification fails and propagates the verifier refusal', async () => {
  const candidate = status(0, null);
  const pg = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      return { rowCount: 0, rows: [] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: pg.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });
  const invalid = {
    ...verified(candidate),
    valid: false,
    outcome: 'indeterminate' as const,
    reasons: ['invalid_status_signature'],
  };

  const result = await store.accept({
    target: TARGET,
    status: candidate,
    verify: () => invalid,
  });

  assert.deepEqual(result, {
    accepted: false,
    source: null,
    reason: 'invalid_status_signature',
    verification: invalid,
  });
});

test('fails closed on a compare-and-advance conflict and releases clients after database errors', async () => {
  const candidate = status(0, null);
  const conflict = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      return { rowCount: 0, rows: [] };
    }
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance) {
      return { rowCount: 1, rows: [{ accepted: false, reason: 'head_conflict' }] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: conflict.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });
  const refused = await store.accept({
    target: TARGET,
    status: candidate,
    verify: () => verified(candidate),
  });
  assert.equal(refused.accepted, false);
  assert.equal(refused.reason, 'status_head_conflict');

  const failed = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      throw new Error('database unavailable');
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const failingStore = createPostgresProposalToEffectStatusHeadStore({
    pool: failed.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });
  await assert.rejects(
    () => failingStore.accept({
      target: TARGET,
      status: candidate,
      verify: () => verified(candidate),
    }),
    /database unavailable/,
  );
  assert.equal(failed.calls.at(-1)?.text, PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get);
  assert.equal(failed.releases(), 1);
});

test('rejects invalid fixed scopes and malformed authenticated rows', async () => {
  assert.throws(
    () => createPostgresProposalToEffectStatusHeadStore({
      pool: pool(async () => ({ rowCount: 0 })).pool,
      tenantId: '',
      relyingPartyId: 'rp:gate-1',
    }),
    /tenantId/,
  );

  const malformed = pool(async (text) => {
    if (text === PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get) {
      return { rowCount: 1, rows: [{ status_digest: 'sha256:bad' }] };
    }
    throw new Error(`unexpected SQL: ${text}`);
  });
  const store = createPostgresProposalToEffectStatusHeadStore({
    pool: malformed.pool,
    tenantId: 'tenant:acme',
    relyingPartyId: 'rp:gate-1',
  });
  await assert.rejects(
    () => store.accept({
      target: TARGET,
      status: status(0, null),
      verify: () => verified(status(0, null)),
    }),
    /malformed PostgreSQL status head/,
  );
});
