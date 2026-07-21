// SPDX-License-Identifier: Apache-2.0
// Generated from store-faults.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Fault-injection tests for EP-GATE-DURABLE-CONSUMPTION-v2.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDurableConsumptionStore, createMemoryBackend } from './store.js';
function tokens(prefix) {
    let n = 0;
    return () => `${prefix}-${String(++n).padStart(24, '0')}`;
}
test('fault: a 100-way reservation storm admits exactly one worker', async () => {
    const backend = createMemoryBackend();
    const stores = Array.from({ length: 100 }, (_, i) => createDurableConsumptionStore(backend, {
        reservationTokenFactory: tokens(`worker-${i}`),
    }));
    const results = await Promise.all(stores.map((store) => store.reserve('same-receipt')));
    assert.equal(results.filter(Boolean).length, 1);
});
test('fault: response loss after commit stays consumed', async () => {
    const durable = createMemoryBackend();
    const backend = {
        ...durable,
        async compareAndSet(...args) {
            const applied = await durable.compareAndSet(...args);
            if (applied)
                throw new Error('connection_lost_after_commit');
            return applied;
        },
    };
    const owner = createDurableConsumptionStore(backend, { reservationTokenFactory: tokens('owner') });
    assert.equal(await owner.reserve('receipt-after'), true);
    await assert.rejects(owner.commit('receipt-after'), /connection_lost_after_commit/);
    assert.equal(await durable.get('receipt-after'), 'committed:v2');
    const retry = createDurableConsumptionStore(durable, { reservationTokenFactory: tokens('retry') });
    assert.equal(await retry.reserve('receipt-after'), false, 'an unknown commit response never reopens replay');
});
test('fault: failure before commit leaves the reservation frozen', async () => {
    const durable = createMemoryBackend();
    const backend = {
        ...durable,
        async compareAndSet() { throw new Error('connection_lost_before_commit'); },
    };
    const owner = createDurableConsumptionStore(backend, { reservationTokenFactory: tokens('owner') });
    assert.equal(await owner.reserve('receipt-before'), true);
    await assert.rejects(owner.commit('receipt-before'), /connection_lost_before_commit/);
    assert.match(await durable.get('receipt-before'), /^reserved:v2:/);
    const retry = createDurableConsumptionStore(durable, { reservationTokenFactory: tokens('retry') });
    assert.equal(await retry.reserve('receipt-before'), false, 'an uncertain reservation fails closed');
});
test('fault: reservation TTL is never passed to a backend', async () => {
    const durable = createMemoryBackend();
    const calls = [];
    const backend = {
        ...durable,
        async addIfAbsent(key, value, options) {
            calls.push({ key, value, options });
            return durable.addIfAbsent(key, value, options);
        },
    };
    const store = createDurableConsumptionStore(backend, {
        ttlSeconds: 60,
        reservationTokenFactory: tokens('worker'),
    });
    await store.reserve('reserved-key');
    await store.consume('committed-key');
    assert.equal(calls[0].options, undefined, 'a crashed in-flight action cannot be reopened by TTL');
    assert.deepEqual(calls[1].options, { ttlSeconds: 60 });
});
test('fault: stale owner cannot erase or commit a replacement owner', async () => {
    const backend = createMemoryBackend();
    const stale = createDurableConsumptionStore(backend, {
        reservationTokenFactory: () => 'stale-owner-token-000001',
    });
    assert.equal(await stale.reserve('receipt-fence'), true);
    assert.equal(await backend.compareAndSet('receipt-fence', 'reserved:v2:stale-owner-token-000001', 'reserved:v2:new-owner-token-0000001'), true);
    await assert.rejects(stale.release('receipt-fence'), /ownership was lost/);
    assert.equal(await backend.get('receipt-fence'), 'reserved:v2:new-owner-token-0000001');
});
test('fault: a restarted process can neither release nor commit an abandoned reservation', async () => {
    const backend = createMemoryBackend();
    const beforeCrash = createDurableConsumptionStore(backend, { reservationTokenFactory: tokens('before-crash') });
    assert.equal(await beforeCrash.reserve('receipt-crash'), true);
    const afterRestart = createDurableConsumptionStore(backend, { reservationTokenFactory: tokens('after-restart') });
    await assert.rejects(afterRestart.commit('receipt-crash'), /does not own reservation/);
    await assert.rejects(afterRestart.release('receipt-crash'), /does not own reservation/);
    assert.equal(await afterRestart.reserve('receipt-crash'), false);
});
