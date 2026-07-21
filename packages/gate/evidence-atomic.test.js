// SPDX-License-Identifier: Apache-2.0
// Generated from evidence-atomic.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { __atomicEvidenceSecurityInternals, createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend, } from './evidence.js';
function ids(prefix = 'record') {
    let next = 0;
    return () => `${prefix}-${String(++next).padStart(16, '0')}`;
}
test('atomic evidence: concurrent replicas append one linear chain', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const recordIdFactory = ids('concurrent');
    const first = createAtomicEvidenceLog(backend, { streamId: 'shared', maxRetries: 256, recordIdFactory });
    const second = createAtomicEvidenceLog(backend, { streamId: 'shared', maxRetries: 256, recordIdFactory });
    await Promise.all(Array.from({ length: 100 }, (_, index) => ((index % 2 ? first : second).record({ type: 'decision', index }))));
    const result = await first.verify();
    assert.deepEqual(result.ok, true);
    assert.equal(result.length, 100);
    const records = await second.all();
    assert.equal(new Set(records.map((record) => record.record_id)).size, 100);
    assert.deepEqual(records.map((record) => record.seq), Array.from({ length: 100 }, (_, index) => index));
});
test('atomic evidence: a restarted writer continues the shared head', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const first = createAtomicEvidenceLog(backend, { streamId: 'restart', recordIdFactory: ids('before') });
    const one = await first.record({ type: 'decision', phase: 'before_restart' });
    const restarted = createAtomicEvidenceLog(backend, { streamId: 'restart', recordIdFactory: ids('after') });
    const two = await restarted.record({ type: 'decision', phase: 'after_restart' });
    assert.equal(two.seq, 1);
    assert.equal(two.prev_hash, one.hash);
    assert.deepEqual(await restarted.verify(), { ok: true, length: 2, head: two.hash });
});
test('atomic evidence: response loss after append recovers the same record id', async () => {
    const base = createMemoryAtomicEvidenceBackend();
    let loseResponse = true;
    const backend = {
        durable: true,
        readHead: (...args) => base.readHead(...args),
        getById: (...args) => base.getById(...args),
        readAll: (...args) => base.readAll(...args),
        async appendIfHead(...args) {
            const appended = await base.appendIfHead(...args);
            if (appended && loseResponse) {
                loseResponse = false;
                throw new Error('connection_lost_after_append');
            }
            return appended;
        },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'stable-record-id-0001' });
    const record = await log.record({ type: 'decision', allow: true });
    assert.equal(record.record_id, 'stable-record-id-0001');
    assert.equal((await base.readAll('emilia-gate')).length, 1);
});
test('atomic evidence: a backend cannot claim success without persisting the record', async () => {
    const base = createMemoryAtomicEvidenceBackend();
    const backend = {
        durable: true,
        readHead: (...args) => base.readHead(...args),
        getById: (...args) => base.getById(...args),
        readAll: (...args) => base.readAll(...args),
        async appendIfHead() {
            return true;
        },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'lying-backend-record-01' });
    await assert.rejects(log.record({ type: 'decision', allow: true }), /atomic_evidence_append_(not_observable|indeterminate)/);
    assert.equal((await base.readAll('emilia-gate')).length, 0);
});
test('atomic evidence: readback must equal the exact submitted sequence and predecessor', async () => {
    const { canonical } = __atomicEvidenceSecurityInternals;
    let persisted = null;
    const backend = {
        durable: true,
        readHead: async () => null,
        getById: async () => structuredClone(persisted),
        async appendIfHead(_streamId, _expectedHeadHash, record) {
            persisted = { ...record, seq: 7, prev_hash: 'b'.repeat(64) };
            const { hash: _discarded, ...body } = persisted;
            persisted.hash = crypto.createHash('sha256').update(canonical(body)).digest('hex');
            return true;
        },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'substituted-record-0001' });
    await assert.rejects(log.record({ type: 'decision', allow: true }), /conflicting record_id/);
});
test('atomic evidence: one record id cannot alias different content', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const fixedId = () => 'duplicate-record-id-01';
    const first = createAtomicEvidenceLog(backend, { recordIdFactory: fixedId });
    const second = createAtomicEvidenceLog(backend, { recordIdFactory: fixedId });
    await first.record({ type: 'decision', allow: false });
    await assert.rejects(second.record({ type: 'decision', allow: true }), /conflicting record_id/);
});
test('atomic evidence: altered persisted bytes fail verification', async () => {
    const base = createMemoryAtomicEvidenceBackend();
    const backend = {
        durable: true,
        readHead: (...args) => base.readHead(...args),
        getById: (...args) => base.getById(...args),
        appendIfHead: (...args) => base.appendIfHead(...args),
        async readAll(...args) {
            const records = await base.readAll(...args);
            if (records[0])
                records[0].allow = !records[0].allow;
            return records;
        },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: ids('tamper') });
    await log.record({ type: 'decision', allow: true });
    assert.deepEqual(await log.verify(), { ok: false, at: 0, reason: 'hash_mismatch' });
});
test('atomic evidence: malformed and reserved-field entries fail closed', async () => {
    const log = createAtomicEvidenceLog(createMemoryAtomicEvidenceBackend(), { recordIdFactory: ids() });
    await assert.rejects(log.record({ seq: 9, type: 'decision' }), /reserved field seq/);
    await assert.rejects(log.record({ type: 'decision', unsafe: 1.5 }), /non-safe integer/);
    const cyclic = { type: 'decision' };
    cyclic.self = cyclic;
    await assert.rejects(log.record(cyclic));
});
