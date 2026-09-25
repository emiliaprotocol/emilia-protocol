// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-consumption-store.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { AEB_CONSUMPTION_DDL, AEB_CONSUMPTION_OPERATION_TABLE, AEB_CONSUMPTION_REPLAY_TABLE, AEB_CONSUMPTION_SQL, createPostgresAebDurableConsumptionStore, } from './aeb-consumption-store.js';
import { consequenceBoundaryActionFenceHolderKey, consequenceBoundaryRecoveryClaimKey, nativeConsequenceBoundaryReservationKey, } from './consequence-boundary.js';
/**
 * A row a recovery claim can name: every claim carries a scope, and the store
 * accepts only the key that scope derives.
 */
function nativeRow(label, reservation = 'operation') {
    const scope = {
        boundary: 'native',
        attemptId: `attempt:${label}`,
        operationId: `operation:${label}`,
        recoveryOperationKey: nativeConsequenceBoundaryReservationKey({
            relying_party_id: 'rp:store-test',
            operation_id: `operation:${label}`,
            action_digest: `sha256:${'a'.repeat(64)}`,
        }),
        reservation,
    };
    return { key: consequenceBoundaryRecoveryClaimKey(scope), scope };
}
function operationId(tenantId, relyingPartyId, operationKey) {
    return JSON.stringify([tenantId, relyingPartyId, operationKey]);
}
function replayId(tenantId, relyingPartyId, replayKey) {
    return JSON.stringify([tenantId, relyingPartyId, replayKey]);
}
function cloneState(state) {
    return {
        operations: new Map([...state.operations].map(([key, row]) => [key, { ...row }])),
        replays: new Map([...state.replays].map(([key, row]) => [key, { ...row }])),
    };
}
class DeterministicMutex {
    tail = Promise.resolve();
    async acquire() {
        let release;
        const turn = new Promise((resolve) => { release = resolve; });
        const previous = this.tail;
        this.tail = previous.then(() => turn);
        await previous;
        return release;
    }
}
function createDeterministicFakePool() {
    let committed = { operations: new Map(), replays: new Map() };
    const mutex = new DeterministicMutex();
    const failures = new Map();
    let lostCommitResponses = 0;
    const transactionLog = [];
    function failNext(statement) {
        failures.set(statement, (failures.get(statement) ?? 0) + 1);
    }
    function maybeFail(statement) {
        const remaining = failures.get(statement) ?? 0;
        if (remaining === 0)
            return;
        if (remaining === 1)
            failures.delete(statement);
        else
            failures.set(statement, remaining - 1);
        throw new Error('pg_unavailable');
    }
    function loseNextCommitResponse() {
        lostCommitResponses += 1;
    }
    return {
        async connect() {
            let transaction = null;
            let unlock = null;
            let released = false;
            return {
                async query(text, params = []) {
                    await Promise.resolve();
                    maybeFail(text);
                    if (text === 'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE') {
                        assert.equal(transaction, null, 'transaction already open');
                        unlock = await mutex.acquire();
                        transaction = cloneState(committed);
                        transactionLog.push('BEGIN');
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === 'COMMIT') {
                        assert.ok(transaction, 'no transaction to commit');
                        committed = transaction;
                        transaction = null;
                        transactionLog.push('COMMIT');
                        unlock?.();
                        unlock = null;
                        if (lostCommitResponses > 0) {
                            lostCommitResponses -= 1;
                            throw new Error('pg_commit_outcome_unknown');
                        }
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === 'ROLLBACK') {
                        // A COMMIT response can be lost after PostgreSQL made the write
                        // durable. The caller may try ROLLBACK without being able to know
                        // that the transaction has already ended.
                        if (!transaction) {
                            transactionLog.push('ROLLBACK_AFTER_COMMIT');
                            return { rowCount: 0, rows: [] };
                        }
                        transaction = null;
                        transactionLog.push('ROLLBACK');
                        unlock?.();
                        unlock = null;
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.hasReplayFence) {
                        const [tenantId, relyingPartyId, replayKey] = params;
                        const active = transaction ?? committed;
                        return {
                            rowCount: 1,
                            rows: [{ fenced: active.replays.has(replayId(tenantId, relyingPartyId, replayKey)) }],
                        };
                    }
                    if (text === AEB_CONSUMPTION_SQL.operationState) {
                        const [tenantId, relyingPartyId, operationKey] = params;
                        const active = transaction ?? committed;
                        const row = active.operations.get(operationId(tenantId, relyingPartyId, operationKey));
                        return { rowCount: 1, rows: [{ state: row?.state ?? 'AVAILABLE' }] };
                    }
                    assert.ok(transaction, 'statement executed outside a transaction');
                    if (text === AEB_CONSUMPTION_SQL.reserveOperation) {
                        const [tenantId, relyingPartyId, operationKey, ownerToken] = params;
                        const id = operationId(tenantId, relyingPartyId, operationKey);
                        if (transaction.operations.has(id))
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, {
                            tenantId,
                            relyingPartyId,
                            operationKey,
                            state: 'RESERVED',
                            ownerToken,
                        });
                        return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.reserveReplayKeys) {
                        const [tenantId, relyingPartyId, operationKey, replayKeys] = params;
                        const inserted = [];
                        for (const replayKey of replayKeys) {
                            const id = replayId(tenantId, relyingPartyId, replayKey);
                            if (transaction.replays.has(id))
                                continue;
                            transaction.replays.set(id, { tenantId, relyingPartyId, replayKey, operationKey });
                            inserted.push({ replay_key: replayKey });
                        }
                        return { rowCount: inserted.length, rows: inserted };
                    }
                    if (text === AEB_CONSUMPTION_SQL.commitOperation) {
                        const [tenantId, relyingPartyId, operationKey, ownerToken] = params;
                        const id = operationId(tenantId, relyingPartyId, operationKey);
                        const row = transaction.operations.get(id);
                        if (!row || row.state !== 'RESERVED' || row.ownerToken !== ownerToken) {
                            return { rowCount: 0, rows: [] };
                        }
                        transaction.operations.set(id, { ...row, state: 'CONSUMED', ownerToken: null });
                        return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.claimOperation) {
                        const [tenantId, relyingPartyId, operationKey, ownerToken] = params;
                        const id = operationId(tenantId, relyingPartyId, operationKey);
                        const row = transaction.operations.get(id);
                        if (!row || row.state !== 'RESERVED')
                            return { rowCount: 0, rows: [] };
                        transaction.operations.set(id, { ...row, ownerToken });
                        return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.releaseTerminalOperation) {
                        const [tenantId, relyingPartyId, operationKey, ownerToken] = params;
                        const id = operationId(tenantId, relyingPartyId, operationKey);
                        const row = transaction.operations.get(id);
                        if (!row) {
                            return { rowCount: 0, rows: [] };
                        }
                        // The RPC converges a retry after an acknowledged-unknown COMMIT.
                        // It never changes a row owned by a different live reservation.
                        if (row.state === 'RELEASED_NOT_ENTERED') {
                            return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                        }
                        if (row.state !== 'RESERVED' || row.ownerToken !== ownerToken) {
                            return { rowCount: 0, rows: [] };
                        }
                        // The row is kept and the replay fences are untouched, so the
                        // ON DELETE CASCADE never fires for a terminal non-entry.
                        transaction.operations.set(id, { ...row, state: 'RELEASED_NOT_ENTERED', ownerToken: null });
                        return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                    }
                    if (text === AEB_CONSUMPTION_SQL.releaseOperation) {
                        const [tenantId, relyingPartyId, operationKey, ownerToken] = params;
                        const id = operationId(tenantId, relyingPartyId, operationKey);
                        const row = transaction.operations.get(id);
                        if (!row || row.state !== 'RESERVED' || row.ownerToken !== ownerToken) {
                            return { rowCount: 0, rows: [] };
                        }
                        transaction.operations.delete(id);
                        for (const [id, replay] of transaction.replays) {
                            if (replay.tenantId === tenantId
                                && replay.relyingPartyId === relyingPartyId
                                && replay.operationKey === operationKey) {
                                transaction.replays.delete(id);
                            }
                        }
                        return { rowCount: 1, rows: [{ operation_key: operationKey }] };
                    }
                    throw new Error(`fake pg received unknown SQL: ${text}`);
                },
                release() {
                    assert.equal(released, false, 'client released twice');
                    assert.equal(transaction, null, 'client released with an open transaction');
                    released = true;
                },
            };
        },
        failNext,
        loseNextCommitResponse,
        operation(tenantId, relyingPartyId, operationKey) {
            return committed.operations.get(operationId(tenantId, relyingPartyId, operationKey));
        },
        replay(tenantId, relyingPartyId, replayKey) {
            return committed.replays.get(replayId(tenantId, relyingPartyId, replayKey));
        },
        transactionLog,
    };
}
function tokenFactory(prefix) {
    let sequence = 0;
    return () => `${prefix}-${String(++sequence).padStart(24, '0')}`;
}
function makeStore(pool, options = {}) {
    return createPostgresAebDurableConsumptionStore({
        pool,
        recoveryPool: { connect: () => pool.connect() },
        tenantId: options.tenantId ?? 'tenant-a',
        relyingPartyId: options.relyingPartyId ?? 'rp-a',
        ownerTokenFactory: tokenFactory(options.tokenPrefix ?? 'owner'),
        authorizeRecoveryClaim: options.authorizeRecoveryClaim ?? (async () => true),
    });
}
test('DDL creates namespaced operation and native replay tables with permanent fences', () => {
    assert.match(AEB_CONSUMPTION_DDL, new RegExp(`CREATE TABLE IF NOT EXISTS ${AEB_CONSUMPTION_OPERATION_TABLE}`));
    assert.match(AEB_CONSUMPTION_DDL, new RegExp(`CREATE TABLE IF NOT EXISTS ${AEB_CONSUMPTION_REPLAY_TABLE}`));
    assert.match(AEB_CONSUMPTION_DDL, /PRIMARY KEY \(tenant_id, relying_party_id, operation_key\)/);
    assert.match(AEB_CONSUMPTION_DDL, /PRIMARY KEY \(tenant_id, relying_party_id, replay_key\)/);
    assert.match(AEB_CONSUMPTION_DDL, /FOREIGN KEY \(tenant_id, relying_party_id, operation_key\)/);
    assert.match(AEB_CONSUMPTION_DDL, /ON DELETE CASCADE/);
    assert.match(AEB_CONSUMPTION_DDL, /state IN \('RESERVED', 'CONSUMED', 'RELEASED_NOT_ENTERED'\)/);
    assert.match(AEB_CONSUMPTION_DDL, /CREATE OR REPLACE FUNCTION ep_aeb_private\.release_terminal_operation/);
    assert.match(AEB_CONSUMPTION_DDL, /SET state = 'RELEASED_NOT_ENTERED', owner_token = NULL/);
    assert.match(AEB_CONSUMPTION_DDL, /existing\.state = 'RELEASED_NOT_ENTERED'/, 'terminal release RPC must converge after a lost commit acknowledgement');
    assert.match(AEB_CONSUMPTION_DDL, /ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ NULL/);
    assert.match(AEB_CONSUMPTION_DDL, /GRANT EXECUTE ON FUNCTION[\s\S]+release_terminal_operation\(TEXT, TEXT, TEXT, TEXT\)\n  TO ep_aeb_executor;/);
    assert.match(AEB_CONSUMPTION_DDL, /CREATE ROLE ep_aeb_executor NOLOGIN/);
    assert.match(AEB_CONSUMPTION_DDL, /CREATE ROLE ep_aeb_recovery NOLOGIN/);
    assert.match(AEB_CONSUMPTION_DDL, /CREATE ROLE ep_aeb_store_owner NOLOGIN/);
    assert.match(AEB_CONSUMPTION_DDL, /TO ep_aeb_store_owner USING \(TRUE\) WITH CHECK \(TRUE\)/);
    assert.match(AEB_CONSUMPTION_DDL, /OWNER TO ep_aeb_store_owner/);
    assert.match(AEB_CONSUMPTION_DDL, /NOBYPASSRLS/);
    assert.match(AEB_CONSUMPTION_DDL, /SECURITY DEFINER SET search_path = ''/);
    assert.match(AEB_CONSUMPTION_DDL, /REVOKE ALL ON ep_aeb_consumption_operations[\s\S]+service_role/);
    assert.doesNotMatch(AEB_CONSUMPTION_DDL, /GRANT ALL ON ep_aeb_consumption/);
});
test('constructor requires physically distinct execution and recovery pools', () => {
    const pool = createDeterministicFakePool();
    assert.throws(() => createPostgresAebDurableConsumptionStore({
        pool,
        recoveryPool: pool,
        tenantId: 'tenant-a',
        relyingPartyId: 'rp-a',
        authorizeRecoveryClaim: async () => true,
    }), /distinct ep_aeb_recovery pg pool/);
});
test('concurrent reservation collision has one winner and no partial loser state', async () => {
    const pool = createDeterministicFakePool();
    const first = makeStore(pool, { tokenPrefix: 'first' });
    const second = makeStore(pool, { tokenPrefix: 'second' });
    const results = await Promise.all([
        first.reserve('operation-1', ['native-a', 'native-b']),
        second.reserve('operation-1', ['native-a', 'native-b']),
    ]);
    assert.deepEqual(results, ['RESERVED', 'CONSUMPTION_CONFLICT']);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-1')?.state, 'RESERVED');
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-a')?.operationKey, 'operation-1');
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-b')?.operationKey, 'operation-1');
    assert.equal(pool.transactionLog.filter((event) => event === 'COMMIT').length, 1);
    assert.equal(pool.transactionLog.filter((event) => event === 'ROLLBACK').length, 1);
});
test('concurrent operations sharing a native replay key return a native replay conflict', async () => {
    const pool = createDeterministicFakePool();
    const first = makeStore(pool, { tokenPrefix: 'first' });
    const second = makeStore(pool, { tokenPrefix: 'second' });
    const results = await Promise.all([
        first.reserve('operation-first', ['native-shared']),
        second.reserve('operation-second', ['native-shared']),
    ]);
    assert.deepEqual(results, ['RESERVED', 'NATIVE_REPLAY_CONFLICT']);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-first')?.state, 'RESERVED');
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-second'), undefined);
});
test('a replay-key insert error rolls back the operation and every replay reservation', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    pool.failNext(AEB_CONSUMPTION_SQL.reserveReplayKeys);
    await assert.rejects(() => store.reserve('operation-rollback', ['native-a', 'native-b']), /pg_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-rollback'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-a'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-b'), undefined);
    assert.equal(pool.transactionLog.at(-1), 'ROLLBACK');
    assert.equal(await store.reserve('operation-rollback', ['native-a', 'native-b']), 'RESERVED');
});
test('only the current opaque-token owner can release; a stale owner cannot release a replacement', async () => {
    const pool = createDeterministicFakePool();
    const oldOwner = makeStore(pool, { tokenPrefix: 'old-owner' });
    const currentOwner = makeStore(pool, { tokenPrefix: 'current-owner' });
    assert.equal(await oldOwner.reserve('operation-stale', ['native-stale']), 'RESERVED');
    assert.equal(await currentOwner.commit('operation-stale'), false);
    assert.equal(await currentOwner.release('operation-stale'), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-stale')?.state, 'RESERVED');
    assert.equal(await oldOwner.release('operation-stale'), true);
    assert.equal(await currentOwner.reserve('operation-stale', ['native-stale']), 'RESERVED');
    assert.equal(await oldOwner.commit('operation-stale'), false);
    assert.equal(await oldOwner.release('operation-stale'), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-stale')?.ownerToken?.startsWith('current-owner-'), true);
});
test('a restarted store can recover a RESERVED operation through an authorized claim', async () => {
    const row = nativeRow('restart');
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const recoveryAuthorization = { kms_token: 'approved-token' };
    const verifierCalls = [];
    const afterRestart = makeStore(pool, {
        tokenPrefix: 'after-restart',
        authorizeRecoveryClaim: async (claim) => {
            verifierCalls.push(claim);
            return claim.authorization === recoveryAuthorization;
        },
    });
    assert.equal(await beforeRestart.reserve(row.key, ['native-restart']), 'RESERVED');
    assert.equal(await afterRestart.claimReservation(row.key, recoveryAuthorization, row.scope), true);
    assert.deepEqual(verifierCalls, [{
            authorization: recoveryAuthorization,
            tenantId: 'tenant-a',
            relyingPartyId: 'rp-a',
            operationKey: row.key,
            requiredState: 'RESERVED',
            attemptIdentity: 'native:attempt:restart',
            scope: row.scope,
        }]);
    assert.equal(await afterRestart.commit(row.key), true);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.state, 'CONSUMED');
});
test('an unauthorized restart claim is refused without rotating the stored owner token', async () => {
    const row = nativeRow('unauthorized');
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const afterRestart = makeStore(pool, {
        tokenPrefix: 'after-restart',
        authorizeRecoveryClaim: async ({ authorization }) => authorization === 'kms-valid',
    });
    assert.equal(await beforeRestart.reserve(row.key, ['native-unauthorized']), 'RESERVED');
    const tokenBeforeClaim = pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken;
    assert.equal(await afterRestart.claimReservation(row.key, 'kms-invalid', row.scope), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken, tokenBeforeClaim);
    assert.equal(await afterRestart.commit(row.key), false);
    assert.equal(await beforeRestart.release(row.key), true);
});
test('recovery verifier and PostgreSQL failures propagate without rotating ownership', async () => {
    const row = nativeRow('recovery-error');
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const verifierUnavailable = makeStore(pool, {
        tokenPrefix: 'verifier-unavailable',
        authorizeRecoveryClaim: async () => { throw new Error('kms_unavailable'); },
    });
    const databaseUnavailable = makeStore(pool, { tokenPrefix: 'database-unavailable' });
    assert.equal(await beforeRestart.reserve(row.key, ['native-recovery-error']), 'RESERVED');
    const originalToken = pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken;
    await assert.rejects(() => verifierUnavailable.claimReservation(row.key, 'kms-token', row.scope), /kms_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken, originalToken);
    pool.failNext(AEB_CONSUMPTION_SQL.claimOperation);
    await assert.rejects(() => databaseUnavailable.claimReservation(row.key, 'kms-token', row.scope), /pg_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken, originalToken);
    assert.equal(await beforeRestart.release(row.key), true);
});
test('the pre-restart owner becomes stale immediately after an authorized recovery claim', async () => {
    const row = nativeRow('claimed');
    const pool = createDeterministicFakePool();
    const staleOwner = makeStore(pool, { tokenPrefix: 'stale-owner' });
    const recoveredOwner = makeStore(pool, { tokenPrefix: 'recovered-owner' });
    assert.equal(await staleOwner.reserve(row.key, ['native-claimed']), 'RESERVED');
    assert.equal(await recoveredOwner.claimReservation(row.key, 'kms-approved', row.scope), true);
    assert.equal(await staleOwner.commit(row.key), false);
    assert.equal(await staleOwner.release(row.key), false);
    assert.equal(await recoveredOwner.commit(row.key), true);
});
test('an owning store instance cannot rotate its own token through recovery', async () => {
    const row = nativeRow('same-instance');
    const pool = createDeterministicFakePool();
    const store = makeStore(pool, { tokenPrefix: 'same-instance' });
    assert.equal(await store.reserve(row.key, ['native-same-instance']), 'RESERVED');
    const tokenBefore = pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken;
    assert.equal(await store.claimReservation(row.key, 'kms-approved', row.scope), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken, tokenBefore);
    assert.equal(await store.commit(row.key), true);
});
test('a terminal CONSUMED operation cannot be claimed after restart', async () => {
    const row = nativeRow('terminal');
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const afterRestart = makeStore(pool, { tokenPrefix: 'after-restart' });
    assert.equal(await beforeRestart.reserve(row.key, ['native-terminal']), 'RESERVED');
    assert.equal(await beforeRestart.commit(row.key), true);
    assert.equal(await afterRestart.claimReservation(row.key, 'kms-approved', row.scope), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.state, 'CONSUMED');
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.ownerToken, null);
});
test('release removes all open fences and permits a complete re-reservation', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    assert.equal(await store.reserve('operation-release', ['native-a', 'native-b']), 'RESERVED');
    assert.equal(await store.release('operation-release'), true);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-release'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-a'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-b'), undefined);
    assert.equal(await store.reserve('operation-release', ['native-a', 'native-b']), 'RESERVED');
});
test('commit permanently consumes the operation and its native replay fences', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    assert.equal(await store.reserve('operation-consumed', ['native-consumed']), 'RESERVED');
    assert.equal(await store.commit('operation-consumed'), true);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-consumed')?.state, 'CONSUMED');
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-consumed')?.ownerToken, null);
    assert.equal(await store.release('operation-consumed'), false);
    assert.equal(await store.reserve('operation-consumed', ['native-other']), 'CONSUMPTION_CONFLICT');
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-consumed')?.operationKey, 'operation-consumed');
});
test('authenticated replay lookup reports the exact tenant and relying-party fence', async () => {
    const pool = createDeterministicFakePool();
    const tenantA = makeStore(pool, { tenantId: 'tenant-a', relyingPartyId: 'rp-a' });
    const tenantB = makeStore(pool, { tenantId: 'tenant-b', relyingPartyId: 'rp-a' });
    const relyingPartyB = makeStore(pool, { tenantId: 'tenant-a', relyingPartyId: 'rp-b' });
    assert.equal(await tenantA.hasReplayFence('native-exact'), false);
    assert.equal(await tenantA.reserve('operation-exact', ['native-exact']), 'RESERVED');
    assert.equal(await tenantA.hasReplayFence('native-exact'), true);
    assert.equal(await tenantB.hasReplayFence('native-exact'), false);
    assert.equal(await relyingPartyB.hasReplayFence('native-exact'), false);
    assert.equal(await tenantA.release('operation-exact'), true);
    assert.equal(await tenantA.hasReplayFence('native-exact'), false);
});
test('replay lookup database failures propagate and malformed answers fail closed', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    pool.failNext(AEB_CONSUMPTION_SQL.hasReplayFence);
    await assert.rejects(() => store.hasReplayFence('native-error'), /pg_unavailable/);
    const malformedPool = {
        async connect() {
            return {
                async query() {
                    return { rowCount: 0, rows: [] };
                },
                release() { },
            };
        },
    };
    const malformedStore = createPostgresAebDurableConsumptionStore({
        pool: malformedPool,
        recoveryPool: { connect: () => malformedPool.connect() },
        tenantId: 'tenant-a',
        relyingPartyId: 'rp-a',
        authorizeRecoveryClaim: async () => true,
    });
    await assert.rejects(() => malformedStore.hasReplayFence('native-malformed'), /lookup replay fence: malformed PostgreSQL result/);
});
test('a consumed native replay key conflicts under a new operation without reserving that operation', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    assert.equal(await store.reserve('operation-original', ['native-replay']), 'RESERVED');
    assert.equal(await store.commit('operation-original'), true);
    assert.equal(await store.reserve('operation-new', ['native-fresh', 'native-replay']), 'NATIVE_REPLAY_CONFLICT');
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-new'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-fresh'), undefined);
    assert.equal(await store.reserve('operation-new', ['native-fresh']), 'RESERVED');
});
test('tenant and relying-party namespaces isolate identical operation and replay keys', async () => {
    const pool = createDeterministicFakePool();
    const tenantA = makeStore(pool, { tenantId: 'tenant-a', relyingPartyId: 'rp-a', tokenPrefix: 'a' });
    const tenantB = makeStore(pool, { tenantId: 'tenant-b', relyingPartyId: 'rp-a', tokenPrefix: 'b' });
    const relyingPartyB = makeStore(pool, { tenantId: 'tenant-a', relyingPartyId: 'rp-b', tokenPrefix: 'c' });
    assert.equal(await tenantA.reserve('same-operation', ['same-replay']), 'RESERVED');
    assert.equal(await tenantB.reserve('same-operation', ['same-replay']), 'RESERVED');
    assert.equal(await relyingPartyB.reserve('same-operation', ['same-replay']), 'RESERVED');
});
test('database errors propagate and never become an available or successful verdict', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    pool.failNext(AEB_CONSUMPTION_SQL.reserveOperation);
    await assert.rejects(() => store.reserve('operation-error', ['native-error']), /pg_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-error'), undefined);
    assert.equal(pool.replay('tenant-a', 'rp-a', 'native-error'), undefined);
});
test('terminal release keeps the row and its fences so the operation is never reservable again', async () => {
    const claimRow = nativeRow('op-terminal');
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    assert.equal(store.terminalRelease, true);
    assert.equal(await store.reserve(claimRow.key, ['replay-terminal']), 'RESERVED');
    assert.equal(await store.releaseTerminal(claimRow.key), true);
    const row = pool.operation('tenant-a', 'rp-a', claimRow.key);
    assert.equal(row?.state, 'RELEASED_NOT_ENTERED');
    assert.equal(row?.ownerToken, null);
    assert.ok(pool.replay('tenant-a', 'rp-a', 'replay-terminal'), 'native replay fence survives');
    // No re-reservation, no late commit, no second terminal release.
    assert.equal(await store.reserve(claimRow.key, ['replay-terminal']), 'CONSUMPTION_CONFLICT');
    assert.equal(await store.commit(claimRow.key), false);
    assert.equal(await store.releaseTerminal(claimRow.key), false);
    assert.equal(await store.release(claimRow.key), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', claimRow.key)?.state, 'RELEASED_NOT_ENTERED');
    // A restarted instance cannot claim a terminally released reservation.
    const restarted = makeStore(pool, { tokenPrefix: 'restarted' });
    assert.equal(await restarted.claimReservation(claimRow.key, 'authorized', claimRow.scope), false);
});
test('terminal release converges after PostgreSQL commits but its response is lost', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool);
    assert.equal(await store.reserve('op-terminal-lost-ack', ['replay-terminal-lost-ack']), 'RESERVED');
    pool.loseNextCommitResponse();
    await assert.rejects(() => store.releaseTerminal('op-terminal-lost-ack'), /pg_commit_outcome_unknown/);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'op-terminal-lost-ack')?.state, 'RELEASED_NOT_ENTERED');
    // The same owner still has its local capability because the first call was
    // not acknowledged. The retry observes the exact terminal row as success.
    assert.equal(await store.releaseTerminal('op-terminal-lost-ack'), true);
    assert.equal(await store.releaseTerminal('op-terminal-lost-ack'), false);
    assert.ok(pool.replay('tenant-a', 'rp-a', 'replay-terminal-lost-ack'));
});
test('a terminal release by a stale owner is refused', async () => {
    const row = nativeRow('stale-terminal');
    const pool = createDeterministicFakePool();
    const owner = makeStore(pool);
    assert.equal(await owner.reserve(row.key, []), 'RESERVED');
    const recovered = makeStore(pool, { tokenPrefix: 'recovered' });
    assert.equal(await recovered.claimReservation(row.key, 'authorized', row.scope), true);
    assert.equal(await owner.releaseTerminal(row.key), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.state, 'RESERVED');
    assert.equal(await recovered.releaseTerminal(row.key), true);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.state, 'RELEASED_NOT_ENTERED');
});
// ---------------------------------------------------------------------------
// PR #790 round 4 (S4): scope-less claims and cross-boundary attempt identity.
// ---------------------------------------------------------------------------
test('S4 PGX1: a claim without a scope is refused before the authorizer runs, with a reason', async () => {
    const pool = createDeterministicFakePool();
    const owner = makeStore(pool, { tokenPrefix: 'live-owner' });
    const authorizerCalls = [];
    // An authorizer bound only to the tenant, which the README warns against:
    // before round four it accepted a scope-less claim of a live holder.
    const recovery = makeStore(pool, {
        tokenPrefix: 'recovery',
        authorizeRecoveryClaim: async (claim) => {
            authorizerCalls.push(claim);
            return claim.tenantId === 'tenant-a';
        },
    });
    const row = nativeRow('pgx1', 'action-fence-holder');
    assert.equal(await owner.reserve(row.key, ['fence-pgx1']), 'RESERVED');
    assert.deepEqual(await recovery.claimReservationResult(row.key, 'tenant-secret'), { claimed: false, reason: 'recovery_claim_scope_required' });
    assert.equal(await recovery.claimReservation(row.key, 'tenant-secret'), false);
    assert.equal(authorizerCalls.length, 0);
    assert.equal(await recovery.release(row.key), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', row.key)?.state, 'RESERVED');
    // The live owner still holds its fence.
    assert.equal(await owner.release(row.key), true);
});
test('S4: a malformed or mismatched scope is a refusal with a reason, never a throw', async () => {
    const pool = createDeterministicFakePool();
    const owner = makeStore(pool, { tokenPrefix: 'live-owner' });
    let authorizerCalls = 0;
    const recovery = makeStore(pool, {
        tokenPrefix: 'recovery',
        authorizeRecoveryClaim: async () => { authorizerCalls += 1; return true; },
    });
    const row = nativeRow('malformed', 'action-fence-holder');
    assert.equal(await owner.reserve(row.key, []), 'RESERVED');
    const { boundary: _kind, ...kindless } = row.scope;
    const getter = { ...row.scope };
    Object.defineProperty(getter, 'attemptId', { enumerable: true, get() { throw new Error('getter ran'); } });
    for (const [label, scope, reason] of [
        ['no boundary kind', kindless, 'recovery_claim_scope_invalid'],
        ['extra member', { ...row.scope, extra: 1 }, 'recovery_claim_scope_invalid'],
        ['accessor', getter, 'recovery_claim_scope_invalid'],
        ['unknown kind', { ...row.scope, boundary: 'other' }, 'recovery_claim_scope_invalid'],
        ['null', null, 'recovery_claim_scope_invalid'],
        ['other attempt', { ...row.scope, attemptId: 'attempt:other' }, 'recovery_claim_key_mismatch'],
        ['composed kind over a native key', { ...row.scope, boundary: 'composed' }, 'recovery_claim_key_mismatch'],
    ]) {
        assert.deepEqual(await recovery.claimReservationResult(row.key, 'approved', scope), { claimed: false, reason }, label);
    }
    assert.equal(authorizerCalls, 0);
    assert.equal(await owner.release(row.key), true);
});
test('S4 PGX3: a native and a composed attempt with the same attempt ID never share a recovery credential', async () => {
    const pool = createDeterministicFakePool();
    const composedOwner = makeStore(pool, { tokenPrefix: 'composed-owner' });
    const sharedAttemptId = 'attempt:shared-T:1';
    const evaluationKey = `aeb:sha256:${'b'.repeat(64)}`;
    const composedScope = {
        boundary: 'composed',
        attemptId: sharedAttemptId,
        operationId: 'operation:composed:shared',
        recoveryOperationKey: evaluationKey,
        reservation: 'action-fence-holder',
    };
    const composedHolder = consequenceBoundaryActionFenceHolderKey({
        reservation_key: evaluationKey,
        attempt_id: sharedAttemptId,
    });
    assert.equal(consequenceBoundaryRecoveryClaimKey(composedScope), composedHolder);
    const nativeScope = {
        ...nativeRow('shared-T', 'action-fence-holder').scope,
        attemptId: sharedAttemptId,
    };
    const nativeHolder = consequenceBoundaryRecoveryClaimKey(nativeScope);
    // The operator's credential for the crashed native attempt, bound the way
    // the README says: to the attempt identity, the tenant, and the relying party.
    const seen = [];
    const recovery = makeStore(pool, {
        tokenPrefix: 'recovery',
        authorizeRecoveryClaim: async (claim) => {
            seen.push(claim.attemptIdentity);
            return claim.authorization === 'credential:native-attempt'
                && claim.attemptIdentity === `native:${sharedAttemptId}`
                && claim.tenantId === 'tenant-a'
                && claim.relyingPartyId === 'rp-a';
        },
    });
    assert.equal(await composedOwner.reserve(composedHolder, ['action-fence-shared']), 'RESERVED');
    // Presented with the composed scope, the authorizer sees the composed identity.
    assert.deepEqual(await recovery.claimReservationResult(composedHolder, 'credential:native-attempt', composedScope), { claimed: false, reason: 'recovery_claim_unauthorized' });
    // Presented with a native scope, the store derives a native row, not this one.
    assert.deepEqual(await recovery.claimReservationResult(composedHolder, 'credential:native-attempt', nativeScope), { claimed: false, reason: 'recovery_claim_key_mismatch' });
    assert.deepEqual(await recovery.claimReservationResult(composedHolder, 'credential:native-attempt', { ...composedScope, boundary: 'native' }), { claimed: false, reason: 'recovery_claim_key_mismatch' });
    assert.deepEqual(seen, [`composed:${sharedAttemptId}`]);
    assert.equal(pool.operation('tenant-a', 'rp-a', composedHolder)?.state, 'RESERVED');
    assert.equal(await composedOwner.release(composedHolder), true);
    // The same credential still recovers the native attempt's own row.
    const nativeOwner = makeStore(pool, { tokenPrefix: 'native-owner' });
    assert.equal(await nativeOwner.reserve(nativeHolder, ['action-fence-native']), 'RESERVED');
    assert.deepEqual(await recovery.claimReservationResult(nativeHolder, 'credential:native-attempt', nativeScope), { claimed: true });
    assert.equal(await recovery.release(nativeHolder), true);
});
test('S4: the composed evaluation row is claimable only while the attempt holds its holder, with a reason otherwise', async () => {
    const pool = createDeterministicFakePool();
    const owner = makeStore(pool, { tokenPrefix: 'composed-owner' });
    const recovery = makeStore(pool, { tokenPrefix: 'recovery' });
    const evaluationKey = `aeb:sha256:${'c'.repeat(64)}`;
    const scope = {
        boundary: 'composed',
        attemptId: 'attempt:marker:1',
        operationId: 'operation:composed:marker',
        recoveryOperationKey: evaluationKey,
        reservation: 'operation',
    };
    assert.equal(await owner.reserve(evaluationKey, ['fence-evaluation']), 'RESERVED');
    assert.deepEqual(await recovery.claimReservationResult(evaluationKey, 'approved', scope), { claimed: false, reason: 'recovery_claim_owner_marker_absent' });
    const holder = consequenceBoundaryActionFenceHolderKey({
        reservation_key: evaluationKey,
        attempt_id: 'attempt:marker:1',
    });
    assert.equal(await owner.reserve(holder, ['fence-action']), 'RESERVED');
    assert.deepEqual(await recovery.claimReservationResult(evaluationKey, 'approved', scope), { claimed: true });
    assert.deepEqual(await recovery.claimReservationResult(evaluationKey, 'approved', scope), { claimed: false, reason: 'recovery_claim_already_owned' });
    assert.equal(await recovery.release(evaluationKey), true);
    const fresh = makeStore(pool, { tokenPrefix: 'fresh' });
    assert.deepEqual(await fresh.claimReservationResult(evaluationKey, 'approved', scope), { claimed: false, reason: 'recovery_claim_row_not_reserved' });
});
