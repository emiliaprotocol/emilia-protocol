// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  WITNESS_SEQUENCE_SQL,
  createPostgresWitnessSequenceStore,
} from './witness-postgres.js';

const DIGEST = `sha256:${'11'.repeat(32)}`;

test('advances one exact tenant, gate, and binary witness stream scope', async () => {
  const calls = [];
  const store = createPostgresWitnessSequenceStore({
    tenantId: 'tenant-a',
    gateId: 'gate-a',
    query: async (...args) => {
      calls.push(args);
      return { rowCount: 1, rows: [{ accepted: true, reason: null }] };
    },
  });
  assert.equal(store.durable, true);
  assert.deepEqual(await store.advance('witness:edge-1\0capture:grid-a', 7, DIGEST), {
    accepted: true, reason: null,
  });
  assert.equal(calls[0][0], WITNESS_SEQUENCE_SQL.advance);
  assert.equal(calls[0][1][0], 'tenant-a');
  assert.equal(calls[0][1][1], 'gate-a');
  assert.equal(Buffer.isBuffer(calls[0][1][2]), true);
  assert.equal(calls[0][1][2].toString('utf8'), 'witness:edge-1\0capture:grid-a');
  assert.equal(calls[0][1][3], 7);
  assert.equal(calls[0][1][4], DIGEST);
});

test('preserves closed replay, rollback, and equivocation reasons', async () => {
  for (const reason of ['statement_replay', 'sequence_rollback', 'sequence_equivocation']) {
    const store = createPostgresWitnessSequenceStore({
      tenantId: 'tenant-a', gateId: 'gate-a',
      query: async () => ({ rowCount: 1, rows: [{ accepted: false, reason }] }),
    });
    assert.deepEqual(await store.advance('w\0c', 1, DIGEST), { accepted: false, reason });
  }
});

test('malformed, ambiguous, and unknown database outcomes throw fail closed', async () => {
  for (const result of [
    null,
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ accepted: 'true', reason: null }] },
    { rowCount: 1, rows: [{ accepted: false, reason: 'try_again' }] },
    { rowCount: 1, rows: [{ accepted: true, reason: 'statement_replay' }] },
  ]) {
    const store = createPostgresWitnessSequenceStore({
      tenantId: 'tenant-a', gateId: 'gate-a', query: async () => result,
    });
    await assert.rejects(() => store.advance('w\0c', 1, DIGEST));
  }
});

test('invalid scopes, stream encodings, sequences, digests, and outages refuse', async () => {
  assert.throws(() => createPostgresWitnessSequenceStore({ query: async () => {}, tenantId: 'a\0b', gateId: 'g' }));
  const store = createPostgresWitnessSequenceStore({
    tenantId: 'tenant-a', gateId: 'gate-a', query: async () => { throw new Error('down'); },
  });
  await assert.rejects(() => store.advance('missing-separator', 1, DIGEST));
  await assert.rejects(() => store.advance('w\0c', -1, DIGEST));
  await assert.rejects(() => store.advance('w\0c', 1, 'sha256:bad'));
  await assert.rejects(() => store.advance('w\0c', 1, DIGEST), /down/);
});
