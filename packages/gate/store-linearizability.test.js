// SPDX-License-Identifier: Apache-2.0
// Generated from store-linearizability.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Deterministic model-based fault schedules for EP-GATE-DURABLE-CONSUMPTION-v2.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createDurableConsumptionStore } from './store.js';
const RECEIPT = 'receipt-under-schedule';
const COMMITTED = 'committed:v2';
function prng(seed) {
    let state = seed >>> 0 || 0x9e3779b9;
    return () => {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        return (state >>> 0) / 0x100000000;
    };
}
class ReplicatedLinearizableBackend {
    constructor(replicaCount = 3) {
        this.log = [];
        this.nodes = Array.from({ length: replicaCount }, () => ({ state: new Map(), applied: 0 }));
        this.active = 0;
        this.nextFault = null;
        this.unavailable = false;
    }
    backend() {
        return {
            addIfAbsent: async (key, value) => this.#write('add', key, { value }),
            compareAndSet: async (key, expected, replacement) => this.#write('cas', key, { expected, replacement }),
            deleteIfValue: async (key, expected) => this.#write('delete', key, { expected }),
            has: async (key) => {
                const node = this.#writableNode();
                return node.state.has(key);
            },
        };
    }
    #writableNode() {
        if (this.unavailable)
            throw new Error('cluster_unavailable');
        const node = this.nodes[this.active];
        if (node.applied !== this.log.length) {
            throw new Error(`stale_replica_refused:${node.applied}<${this.log.length}`);
        }
        return node;
    }
    #write(kind, key, args) {
        const node = this.#writableNode();
        const fault = this.nextFault;
        this.nextFault = null;
        if (fault === 'before')
            throw new Error('connection_lost_before_linearization');
        const current = node.state.get(key);
        let changed = false;
        let next = current;
        if (kind === 'add' && current === undefined) {
            changed = true;
            next = args.value;
        }
        else if (kind === 'cas' && current === args.expected) {
            changed = true;
            next = args.replacement;
        }
        else if (kind === 'delete' && current === args.expected) {
            changed = true;
            next = undefined;
        }
        if (changed) {
            if (next === undefined)
                node.state.delete(key);
            else
                node.state.set(key, next);
            this.log.push({ index: this.log.length + 1, kind, key, before: current, after: next });
            node.applied = this.log.length;
        }
        if (fault === 'after' && changed)
            throw new Error('connection_lost_after_linearization');
        return changed;
    }
    replicateOne(index) {
        const node = this.nodes[index];
        if (node.applied >= this.log.length)
            return false;
        const entry = this.log[node.applied];
        if (entry.after === undefined)
            node.state.delete(entry.key);
        else
            node.state.set(entry.key, entry.after);
        node.applied += 1;
        return true;
    }
    catchUp(index) {
        while (this.replicateOne(index))
            ;
    }
    attemptPromotion(index) {
        if (this.nodes[index].applied !== this.log.length)
            return false;
        this.active = index;
        return true;
    }
    forceStaleActive(index) {
        this.active = index;
    }
    rollbackReplica(index, applied) {
        if (index === this.active)
            throw new Error('active_rollback_refused');
        const target = Math.max(0, Math.min(applied, this.log.length));
        const state = new Map();
        for (const entry of this.log.slice(0, target)) {
            if (entry.after === undefined)
                state.delete(entry.key);
            else
                state.set(entry.key, entry.after);
        }
        this.nodes[index] = { state, applied: target };
    }
    authoritativeState() {
        const state = new Map();
        for (const entry of this.log) {
            assert.equal(entry.index, state.__lastIndex === undefined ? 1 : state.__lastIndex + 1);
            if (entry.kind === 'add')
                assert.equal(state.has(entry.key), false, 'add linearized only from absent');
            if (entry.kind === 'cas')
                assert.equal(state.get(entry.key), entry.before, 'CAS linearized from its expected value');
            if (entry.kind === 'delete')
                assert.equal(state.get(entry.key), entry.before, 'delete linearized from its expected value');
            if (entry.after === undefined)
                state.delete(entry.key);
            else
                state.set(entry.key, entry.after);
            Object.defineProperty(state, '__lastIndex', { value: entry.index, configurable: true, writable: true });
        }
        return state;
    }
}
function worker(cluster, schedule, index, generation = 0) {
    let token = 0;
    return {
        index,
        generation,
        phase: 'idle',
        store: createDurableConsumptionStore(cluster.backend(), {
            reservationTokenFactory: () => `schedule-${schedule}-worker-${index}-gen-${generation}-${String(++token).padStart(8, '0')}`,
        }),
    };
}
async function tryReserve(candidate) {
    if (candidate.phase !== 'idle')
        return false;
    try {
        const won = await candidate.store.reserve(RECEIPT);
        if (won)
            candidate.phase = 'reserved';
        return won;
    }
    catch {
        return false;
    }
}
function assertScheduleInvariants(cluster, workers, effectCount, effectStarted, committedSeen) {
    const state = cluster.authoritativeState();
    const value = state.get(RECEIPT);
    assert.ok(effectCount <= 1, 'one approval caused more than one external effect');
    if (effectStarted)
        assert.ok(value !== undefined, 'an attempted effect was reopened by deleting its reservation');
    if (committedSeen)
        assert.equal(value, COMMITTED, 'committed consumption regressed');
    const liveOwners = workers.filter((candidate) => candidate.phase === 'reserved' || candidate.phase === 'effect');
    assert.ok(liveOwners.length <= 1, 'two workers simultaneously own one reservation');
    return committedSeen || value === COMMITTED;
}
async function runSchedule(schedule, steps = 32) {
    const random = prng((0x51f15e ^ schedule) >>> 0);
    const cluster = new ReplicatedLinearizableBackend();
    let workers = Array.from({ length: 4 }, (_, index) => worker(cluster, schedule, index));
    let effects = 0;
    let effectStarted = false;
    let committedSeen = false;
    // Every schedule starts with overlapping duplicate presentation.
    const initial = await Promise.all(workers.map(tryReserve));
    assert.equal(initial.filter(Boolean).length, 1);
    for (let step = 0; step < steps; step += 1) {
        const choice = Math.floor(random() * 13);
        const index = Math.floor(random() * workers.length);
        const candidate = workers[index];
        try {
            switch (choice) {
                case 0:
                    await tryReserve(candidate);
                    break;
                case 1:
                    if (candidate.phase === 'reserved') {
                        candidate.phase = 'effect';
                        effects += 1;
                        effectStarted = true;
                    }
                    break;
                case 2:
                    if (candidate.phase === 'effect') {
                        try {
                            await candidate.store.commit(RECEIPT);
                            candidate.phase = 'done';
                        }
                        catch {
                            // gate.run retries only the consumption transition, never the
                            // external effect. Before/after-response loss therefore leaves
                            // the key reserved or committed and the outcome indeterminate.
                            try {
                                await candidate.store.commit(RECEIPT);
                            }
                            catch { /* frozen is safe */ }
                            candidate.phase = 'indeterminate';
                        }
                    }
                    break;
                case 3:
                    if (candidate.phase === 'reserved') {
                        try {
                            await candidate.store.release(RECEIPT);
                            candidate.phase = 'idle';
                        }
                        catch {
                            candidate.phase = 'lost';
                        }
                    }
                    break;
                case 4:
                    workers[index] = worker(cluster, schedule, index, candidate.generation + 1);
                    break;
                case 5: {
                    const results = await Promise.all(workers.map(tryReserve));
                    assert.ok(results.filter(Boolean).length <= 1);
                    break;
                }
                case 6:
                    cluster.replicateOne(Math.floor(random() * cluster.nodes.length));
                    break;
                case 7: {
                    const target = Math.floor(random() * cluster.nodes.length);
                    const promoted = cluster.attemptPromotion(target);
                    if (!promoted)
                        assert.notEqual(cluster.active, target, 'stale promotion changed the active writer');
                    break;
                }
                case 8: {
                    const target = (cluster.active + 1) % cluster.nodes.length;
                    cluster.rollbackReplica(target, Math.max(0, cluster.log.length - 1));
                    cluster.forceStaleActive(target);
                    await assert.rejects(workers[0].store.has(RECEIPT), /stale_replica_refused/);
                    cluster.catchUp(target);
                    assert.equal(cluster.attemptPromotion(target), true);
                    break;
                }
                case 9: {
                    const target = (cluster.active + 1) % cluster.nodes.length;
                    cluster.rollbackReplica(target, Math.max(0, cluster.log.length - 1));
                    if (cluster.nodes[target].applied !== cluster.log.length)
                        assert.equal(cluster.attemptPromotion(target), false);
                    break;
                }
                case 10:
                    cluster.nextFault = 'before';
                    await tryReserve(candidate);
                    break;
                case 11:
                    cluster.nextFault = 'after';
                    if (candidate.phase === 'effect') {
                        try {
                            await candidate.store.commit(RECEIPT);
                        }
                        catch {
                            candidate.phase = 'indeterminate';
                        }
                    }
                    else {
                        await tryReserve(candidate);
                    }
                    break;
                case 12:
                    cluster.unavailable = true;
                    await assert.rejects(workers[0].store.has(RECEIPT), /cluster_unavailable/);
                    cluster.unavailable = false;
                    break;
                default:
                    throw new Error('unreachable schedule operation');
            }
        }
        finally {
            committedSeen = assertScheduleInvariants(cluster, workers, effects, effectStarted, committedSeen);
        }
    }
    if (effectStarted) {
        const retries = Array.from({ length: 8 }, (_, index) => worker(cluster, schedule, 100 + index));
        const results = await Promise.all(retries.map(tryReserve));
        assert.equal(results.filter(Boolean).length, 0, 'post-effect duplicate presentation reopened approval');
    }
    return crypto.createHash('sha256').update(JSON.stringify(cluster.log)).digest('hex');
}
test('generated model: 5000 schedules preserve linearizable at-most-once effects', async () => {
    const aggregate = crypto.createHash('sha256');
    for (let schedule = 1; schedule <= 5000; schedule += 1) {
        aggregate.update(await runSchedule(schedule));
    }
    assert.equal(aggregate.digest('hex').length, 64);
});
test('stale replica promotion and rollback attempts fail closed', async () => {
    const cluster = new ReplicatedLinearizableBackend();
    const first = worker(cluster, 'stale', 0);
    assert.equal(await first.store.reserve(RECEIPT), true);
    first.phase = 'effect';
    const stale = 1;
    assert.equal(cluster.attemptPromotion(stale), false);
    cluster.forceStaleActive(stale);
    const replay = worker(cluster, 'stale', 1);
    await assert.rejects(replay.store.reserve(RECEIPT), /stale_replica_refused/);
    assert.throws(() => cluster.rollbackReplica(stale, 0), /active_rollback_refused/);
    cluster.catchUp(stale);
    assert.equal(cluster.attemptPromotion(stale), true);
    assert.equal(await replay.store.reserve(RECEIPT), false);
});
test('response loss at reserve and commit boundaries freezes or commits without replay', async () => {
    const cluster = new ReplicatedLinearizableBackend();
    const lostReserve = worker(cluster, 'response-loss', 0);
    cluster.nextFault = 'after';
    await assert.rejects(lostReserve.store.reserve(RECEIPT), /after_linearization/);
    assert.equal(await worker(cluster, 'response-loss', 1).store.reserve(RECEIPT), false);
    const secondCluster = new ReplicatedLinearizableBackend();
    const owner = worker(secondCluster, 'commit-loss', 0);
    assert.equal(await owner.store.reserve(RECEIPT), true);
    owner.phase = 'effect';
    secondCluster.nextFault = 'after';
    await assert.rejects(owner.store.commit(RECEIPT), /after_linearization/);
    assert.equal(secondCluster.authoritativeState().get(RECEIPT), COMMITTED);
    assert.equal(await worker(secondCluster, 'commit-loss', 1).store.reserve(RECEIPT), false);
});
