// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-consumption-store.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { AEB_CONSUMPTION_DDL, AEB_CONSUMPTION_OPERATION_TABLE, AEB_CONSUMPTION_REPLAY_TABLE, AEB_CONSUMPTION_SQL, createPostgresAebDurableConsumptionStore, } from './aeb-consumption-store.js';
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
                        return { rowCount: 0, rows: [] };
                    }
                    if (text === 'ROLLBACK') {
                        assert.ok(transaction, 'no transaction to roll back');
                        transaction = null;
                        transactionLog.push('ROLLBACK');
                        unlock?.();
                        unlock = null;
                        return { rowCount: 0, rows: [] };
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
    assert.match(AEB_CONSUMPTION_DDL, /state IN \('RESERVED', 'CONSUMED'\)/);
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
    assert.equal(await beforeRestart.reserve('operation-restart', ['native-restart']), 'RESERVED');
    assert.equal(await afterRestart.claimReservation('operation-restart', recoveryAuthorization), true);
    assert.deepEqual(verifierCalls, [{
            authorization: recoveryAuthorization,
            tenantId: 'tenant-a',
            relyingPartyId: 'rp-a',
            operationKey: 'operation-restart',
            requiredState: 'RESERVED',
        }]);
    assert.equal(await afterRestart.commit('operation-restart'), true);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-restart')?.state, 'CONSUMED');
});
test('an unauthorized restart claim is refused without rotating the stored owner token', async () => {
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const afterRestart = makeStore(pool, {
        tokenPrefix: 'after-restart',
        authorizeRecoveryClaim: async ({ authorization }) => authorization === 'kms-valid',
    });
    assert.equal(await beforeRestart.reserve('operation-unauthorized', ['native-unauthorized']), 'RESERVED');
    const tokenBeforeClaim = pool.operation('tenant-a', 'rp-a', 'operation-unauthorized')?.ownerToken;
    assert.equal(await afterRestart.claimReservation('operation-unauthorized', 'kms-invalid'), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-unauthorized')?.ownerToken, tokenBeforeClaim);
    assert.equal(await afterRestart.commit('operation-unauthorized'), false);
    assert.equal(await beforeRestart.release('operation-unauthorized'), true);
});
test('recovery verifier and PostgreSQL failures propagate without rotating ownership', async () => {
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const verifierUnavailable = makeStore(pool, {
        tokenPrefix: 'verifier-unavailable',
        authorizeRecoveryClaim: async () => { throw new Error('kms_unavailable'); },
    });
    const databaseUnavailable = makeStore(pool, { tokenPrefix: 'database-unavailable' });
    assert.equal(await beforeRestart.reserve('operation-recovery-error', ['native-recovery-error']), 'RESERVED');
    const originalToken = pool.operation('tenant-a', 'rp-a', 'operation-recovery-error')?.ownerToken;
    await assert.rejects(() => verifierUnavailable.claimReservation('operation-recovery-error', 'kms-token'), /kms_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-recovery-error')?.ownerToken, originalToken);
    pool.failNext(AEB_CONSUMPTION_SQL.claimOperation);
    await assert.rejects(() => databaseUnavailable.claimReservation('operation-recovery-error', 'kms-token'), /pg_unavailable/);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-recovery-error')?.ownerToken, originalToken);
    assert.equal(await beforeRestart.release('operation-recovery-error'), true);
});
test('the pre-restart owner becomes stale immediately after an authorized recovery claim', async () => {
    const pool = createDeterministicFakePool();
    const staleOwner = makeStore(pool, { tokenPrefix: 'stale-owner' });
    const recoveredOwner = makeStore(pool, { tokenPrefix: 'recovered-owner' });
    assert.equal(await staleOwner.reserve('operation-claimed', ['native-claimed']), 'RESERVED');
    assert.equal(await recoveredOwner.claimReservation('operation-claimed', 'kms-approved'), true);
    assert.equal(await staleOwner.commit('operation-claimed'), false);
    assert.equal(await staleOwner.release('operation-claimed'), false);
    assert.equal(await recoveredOwner.commit('operation-claimed'), true);
});
test('an owning store instance cannot rotate its own token through recovery', async () => {
    const pool = createDeterministicFakePool();
    const store = makeStore(pool, { tokenPrefix: 'same-instance' });
    assert.equal(await store.reserve('operation-same-instance', ['native-same-instance']), 'RESERVED');
    const tokenBefore = pool.operation('tenant-a', 'rp-a', 'operation-same-instance')?.ownerToken;
    assert.equal(await store.claimReservation('operation-same-instance', 'kms-approved'), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-same-instance')?.ownerToken, tokenBefore);
    assert.equal(await store.commit('operation-same-instance'), true);
});
test('a terminal CONSUMED operation cannot be claimed after restart', async () => {
    const pool = createDeterministicFakePool();
    const beforeRestart = makeStore(pool, { tokenPrefix: 'before-restart' });
    const afterRestart = makeStore(pool, { tokenPrefix: 'after-restart' });
    assert.equal(await beforeRestart.reserve('operation-terminal', ['native-terminal']), 'RESERVED');
    assert.equal(await beforeRestart.commit('operation-terminal'), true);
    assert.equal(await afterRestart.claimReservation('operation-terminal', 'kms-approved'), false);
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-terminal')?.state, 'CONSUMED');
    assert.equal(pool.operation('tenant-a', 'rp-a', 'operation-terminal')?.ownerToken, null);
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
