// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  __atomicEvidenceSecurityInternals,
  createAtomicEvidenceLog,
  createMemoryAtomicEvidenceBackend,
} from '../packages/gate/evidence.js';

function ids(prefix = 'record') {
  let next = 0;
  return () => `${prefix}-${String(++next).padStart(16, '0')}`;
}

describe('atomic shared-head evidence log', () => {
  it('linearizes concurrent replicas and preserves restart continuity', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const recordIdFactory = ids('concurrent');
    const first = createAtomicEvidenceLog(backend, { streamId: 'shared', maxRetries: 64, recordIdFactory });
    const second = createAtomicEvidenceLog(backend, { streamId: 'shared', maxRetries: 64, recordIdFactory });

    await Promise.all(Array.from({ length: 25 }, (_, index) => (
      (index % 2 ? first : second).record({ type: 'decision', index })
    )));
    const restarted = createAtomicEvidenceLog(backend, {
      streamId: 'shared', recordIdFactory: ids('restart'),
    });
    const afterRestart = await restarted.record({ type: 'decision', phase: 'after_restart' });

    expect(afterRestart.seq).toBe(25);
    expect(await restarted.verify()).toEqual({ ok: true, length: 26, head: afterRestart.hash });
    const records = await restarted.all();
    expect(new Set(records.map((record) => record.record_id)).size).toBe(26);
    expect(records.map((record) => record.seq)).toEqual(Array.from({ length: 26 }, (_, index) => index));
  });

  it('recovers the stable record after response loss', async () => {
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

    expect(record.record_id).toBe('stable-record-id-0001');
    expect(await base.readAll('emilia-gate')).toHaveLength(1);
  });

  it('refuses a backend that claims success without persistence', async () => {
    const base = createMemoryAtomicEvidenceBackend();
    const backend = {
      durable: true,
      readHead: (...args) => base.readHead(...args),
      getById: (...args) => base.getById(...args),
      readAll: (...args) => base.readAll(...args),
      async appendIfHead() { return true; },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'lying-backend-record-01' });

    await expect(log.record({ type: 'decision', allow: true })).rejects.toThrow(/append_indeterminate/);
    expect(await base.readAll('emilia-gate')).toHaveLength(0);
  });

  it('refuses a backend that substitutes different self-consistent bytes after append', async () => {
    const { canonical } = __atomicEvidenceSecurityInternals;
    let persisted = null;
    const backend = {
      durable: true,
      readHead: async () => null,
      getById: async () => structuredClone(persisted),
      readAll: async () => persisted ? [structuredClone(persisted)] : [],
      async appendIfHead(_streamId, _expectedHeadHash, record) {
        const substituted = { ...record, seq: 7, prev_hash: 'b'.repeat(64) };
        const { hash: _discarded, ...body } = substituted;
        substituted.hash = crypto.createHash('sha256').update(canonical(body)).digest('hex');
        persisted = substituted;
        return true;
      },
    };
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'substituted-record-0001' });

    await expect(log.record({ type: 'decision', allow: true })).rejects.toThrow(/conflicting record_id/);
    expect(persisted).toMatchObject({ allow: true, seq: 7, prev_hash: 'b'.repeat(64) });
  });

  it('refuses record-id aliasing and malformed backend heads', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const fixedId = () => 'duplicate-record-id-01';
    const first = createAtomicEvidenceLog(backend, { recordIdFactory: fixedId });
    const second = createAtomicEvidenceLog(backend, { recordIdFactory: fixedId });
    await first.record({ type: 'decision', allow: false });
    await expect(second.record({ type: 'decision', allow: true })).rejects.toThrow(/conflicting record_id/);

    const malformed = createAtomicEvidenceLog({
      readHead: async () => ({ seq: -1, hash: 'bad' }),
      getById: async () => null,
      appendIfHead: async () => true,
    }, { recordIdFactory: ids('bad-head') });
    await expect(malformed.record({ type: 'decision' })).rejects.toThrow(/malformed head/);
  });

  it('detects altered records, missing history, and head rollback', async () => {
    const base = createMemoryAtomicEvidenceBackend();
    const log = createAtomicEvidenceLog(base, { recordIdFactory: ids('tamper') });
    await log.record({ type: 'decision', allow: true });
    await log.record({ type: 'decision', allow: false });

    const altered = createAtomicEvidenceLog({
      readHead: (...args) => base.readHead(...args),
      getById: (...args) => base.getById(...args),
      appendIfHead: (...args) => base.appendIfHead(...args),
      async readAll(...args) {
        const records = await base.readAll(...args);
        records[0].allow = false;
        return records;
      },
    });
    expect(await altered.verify()).toMatchObject({ ok: false, at: 0, reason: 'hash_mismatch' });

    const missing = createAtomicEvidenceLog({
      readHead: (...args) => base.readHead(...args),
      getById: (...args) => base.getById(...args),
      appendIfHead: (...args) => base.appendIfHead(...args),
      async readAll(...args) { return (await base.readAll(...args)).slice(1); },
    });
    expect(await missing.verify()).toMatchObject({ ok: false, at: 0, reason: 'sequence_or_predecessor_mismatch' });

    const rollback = createAtomicEvidenceLog({
      readHead: async () => null,
      getById: (...args) => base.getById(...args),
      appendIfHead: (...args) => base.appendIfHead(...args),
      readAll: (...args) => base.readAll(...args),
    });
    expect(await rollback.verify()).toMatchObject({ ok: false, reason: 'head_mismatch' });
  });

  it('rejects malformed entries and constructor capabilities', async () => {
    expect(() => createAtomicEvidenceLog()).toThrow(/readHead/);
    expect(() => createAtomicEvidenceLog({}, { streamId: '' })).toThrow(/readHead/);
    const log = createAtomicEvidenceLog(createMemoryAtomicEvidenceBackend(), { recordIdFactory: ids() });
    await expect(log.record({ seq: 9, type: 'decision' })).rejects.toThrow(/reserved field seq/);
    await expect(log.record({ type: 'decision', unsafe: 1.5 })).rejects.toThrow(/non-safe integer/);
    const cyclic = { type: 'decision' };
    cyclic.self = cyclic;
    await expect(log.record(cyclic)).rejects.toThrow();
  });

  it('fails closed on unavailable or malformed backend history', async () => {
    const required = {
      readHead: async () => null,
      getById: async () => null,
      appendIfHead: async () => false,
    };
    expect(await createAtomicEvidenceLog(required).verify()).toEqual({ ok: false, reason: 'read_all_unavailable' });
    await expect(createAtomicEvidenceLog(required).all()).rejects.toThrow(/readAll/);

    const malformed = createAtomicEvidenceLog({ ...required, readAll: async () => ({}) });
    expect(await malformed.verify()).toEqual({ ok: false, reason: 'malformed_history' });
    await expect(malformed.all()).rejects.toThrow(/malformed history/);

    const unavailable = createAtomicEvidenceLog({ ...required, readAll: async () => { throw new Error('down'); } });
    expect(await unavailable.verify()).toEqual({ ok: false, reason: 'backend_read_failed_or_malformed' });
  });

  it('enforces constructor, record-id, and contention boundaries', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    for (const options of [
      { streamId: '' }, { streamId: 'x'.repeat(257) },
      { maxRetries: 0 }, { maxRetries: 1025 }, { maxRetries: 1.5 },
      { recordIdFactory: true },
    ]) expect(() => createAtomicEvidenceLog(backend, options)).toThrow();

    for (const id of [null, '', '1234567890abcde', 'x'.repeat(257)]) {
      const log = createAtomicEvidenceLog(backend, { streamId: `id-${String(id).length}`, recordIdFactory: () => id });
      await expect(log.record({ type: 'decision' })).rejects.toThrow(/record id/);
    }

    const contention = createAtomicEvidenceLog({
      readHead: async () => null,
      getById: async () => null,
      appendIfHead: async () => false,
    }, { maxRetries: 1, recordIdFactory: () => 'contention-record-0001' });
    await expect(contention.record({ type: 'decision' })).rejects.toThrow(/contention_limit/);
  });
});
