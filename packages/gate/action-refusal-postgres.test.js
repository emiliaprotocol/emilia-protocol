// SPDX-License-Identifier: Apache-2.0
// Generated from action-refusal-postgres.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { ACTION_REFUSAL_POSTGRES_SQL, createPostgresActionRefusalReplayStore, } from './action-refusal-postgres.js';
const DIGEST = `sha256:${'1'.repeat(64)}`;
test('consumes under one exact tenant, gate, relying-party, and nonce scope', async () => {
    const calls = [];
    const store = createPostgresActionRefusalReplayStore({
        tenantId: 'tenant-a',
        gateId: 'gate-a',
        query: async (...args) => {
            calls.push(args);
            return { rowCount: 1, rows: [{ accepted: true, reason: null }] };
        },
    });
    assert.equal(store.durable, true);
    assert.deepEqual(await store.consume('rp-a', 'nonce-a', DIGEST), {
        accepted: true, reason: null,
    });
    assert.equal(calls[0][0], ACTION_REFUSAL_POSTGRES_SQL.consume);
    assert.deepEqual(calls[0][1], ['tenant-a', 'gate-a', 'rp-a', 'nonce-a', DIGEST]);
});
test('preserves only closed replay and equivocation outcomes', async () => {
    for (const reason of ['statement_replay', 'nonce_equivocation']) {
        const store = createPostgresActionRefusalReplayStore({
            tenantId: 'tenant-a', gateId: 'gate-a',
            query: async () => ({ rowCount: 1, rows: [{ accepted: false, reason }] }),
        });
        assert.deepEqual(await store.consume('rp-a', 'nonce-a', DIGEST), {
            accepted: false, reason,
        });
    }
});
test('invalid scopes, inputs, ambiguous rows, and outages fail closed', async () => {
    assert.throws(() => createPostgresActionRefusalReplayStore({
        query: async () => ({}), tenantId: 'tenant\0a', gateId: 'gate-a',
    }));
    for (const result of [
        null,
        { rowCount: 0, rows: [] },
        { rowCount: 1, rows: [{ accepted: 'true', reason: null }] },
        { rowCount: 1, rows: [{ accepted: false, reason: 'try_again' }] },
        { rowCount: 1, rows: [{ accepted: true, reason: 'statement_replay' }] },
    ]) {
        const store = createPostgresActionRefusalReplayStore({
            tenantId: 'tenant-a', gateId: 'gate-a', query: async () => result,
        });
        await assert.rejects(() => store.consume('rp-a', 'nonce-a', DIGEST));
    }
    const unavailable = createPostgresActionRefusalReplayStore({
        tenantId: 'tenant-a', gateId: 'gate-a', query: async () => { throw new Error('down'); },
    });
    await assert.rejects(() => unavailable.consume('rp-a', 'nonce-a', DIGEST), /down/);
    await assert.rejects(() => unavailable.consume('rp-a', 'nonce-a', 'sha256:bad'));
});
