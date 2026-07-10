// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  MemoryConsumptionStore,
  createDurableConsumptionStore,
  createMemoryBackend,
} from '../packages/gate/store.js';

function token(prefix = 'owner') {
  let n = 0;
  return () => `${prefix}-${String(++n).padStart(24, '0')}`;
}

describe('mutation oracles for the replay kernel', () => {
  it('memory store separates reserved and committed state', async () => {
    const store = new MemoryConsumptionStore();
    expect(await store.reserve('a')).toBe(true);
    expect(await store.reserve('a')).toBe(false);
    expect(await store.consume('a')).toBe(false);
    expect(await store.commit('a')).toBe(true);
    expect(await store.has('a')).toBe(true);
    expect(store.size).toBe(1);
    expect(await store.reserve('b')).toBe(true);
    expect(await store.release('b')).toBe(true);
    expect(await store.has('b')).toBe(false);
  });

  it('durable store requires every atomic primitive and a token source', () => {
    expect(() => createDurableConsumptionStore({})).toThrow(/addIfAbsent/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {} })).toThrow(/compareAndSet/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {}, compareAndSet() {} })).toThrow(/deleteIfValue/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {}, compareAndSet() {}, deleteIfValue() {} })).toThrow(/has/);
    expect(() => createDurableConsumptionStore(createMemoryBackend(), { reservationTokenFactory: 'not-a-function' })).toThrow(/must be a function/);
  });

  it('commits only its exact opaque reservation and then refuses replay', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, {
      ttlSeconds: 60,
      reservationTokenFactory: token(),
    });
    expect(await store.reserve('a')).toBe(true);
    expect(await backend.get('a')).toMatch(/^reserved:v2:/);
    expect(await store.commit('a')).toBe(true);
    expect(await backend.get('a')).toBe('committed:v2');
    expect(await store.reserve('a')).toBe(false);
    expect(await store.consume('a')).toBe(false);
  });

  it('a non-owner cannot commit or release an existing reservation', async () => {
    const backend = createMemoryBackend();
    const owner = createDurableConsumptionStore(backend, { reservationTokenFactory: token('owner') });
    const stranger = createDurableConsumptionStore(backend, { reservationTokenFactory: token('stranger') });
    expect(await owner.reserve('a')).toBe(true);
    await expect(stranger.commit('a')).rejects.toThrow(/does not own/);
    await expect(stranger.release('a')).rejects.toThrow(/does not own/);
    expect(await backend.has('a')).toBe(true);
  });

  it('refuses weak reservation tokens before touching shared state', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, { reservationTokenFactory: () => 'short' });
    await expect(store.reserve('a')).rejects.toThrow(/at least 16/);
    expect(await backend.has('a')).toBe(false);
  });

  it('uses a secure default owner token and exposes exact shared state', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend);
    expect(await store.reserve('a')).toBe(true);
    expect(await backend.get('a')).toMatch(/^reserved:v2:[0-9a-f-]{36}$/);
    expect(await store.has('a')).toBe(true);
    expect(await store.release('a')).toBe(true);
    expect(await store.has('a')).toBe(false);
    expect(await store.consume('b')).toBe(true);
    expect(await store.has('b')).toBe(true);
  });

  it('fails closed when reservation ownership changes after local acquisition', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, { reservationTokenFactory: token() });
    expect(await store.reserve('commit')).toBe(true);
    const commitValue = await backend.get('commit');
    expect(await backend.deleteIfValue('commit', commitValue)).toBe(true);
    expect(await backend.addIfAbsent('commit', 'reserved:v2:replacement-owner-token')).toBe(true);
    await expect(store.commit('commit')).rejects.toThrow(/ownership was lost/);
    expect(await backend.get('commit')).toBe('reserved:v2:replacement-owner-token');

    expect(await store.reserve('release')).toBe(true);
    const releaseValue = await backend.get('release');
    expect(await backend.deleteIfValue('release', releaseValue)).toBe(true);
    expect(await backend.addIfAbsent('release', 'reserved:v2:replacement-owner-token')).toBe(true);
    await expect(store.release('release')).rejects.toThrow(/ownership was lost/);
    expect(await backend.get('release')).toBe('reserved:v2:replacement-owner-token');
  });
});
