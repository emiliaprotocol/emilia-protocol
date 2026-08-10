// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { acquireJobLease, _resetJobLeasesForTesting } from '../lib/job-lease.js';
import { logger } from '../lib/logger.js';

beforeEach(() => {
  _resetJobLeasesForTesting();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('durable background-job lease', () => {
  it('rejects malformed lease names and unsafe TTLs before touching the store', async () => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');

    await expect(acquireJobLease('Anchor_Batch', 60_000)).rejects.toThrow('job lease name is malformed');
    await expect(acquireJobLease('anchor-batch', 999)).rejects.toThrow(
      'job lease TTL must be between one second and one hour',
    );
    await expect(acquireJobLease('anchor-batch', 3_600_001)).rejects.toThrow(
      'job lease TTL must be between one second and one hour',
    );
  });

  it('excludes a concurrent in-process worker and permits a successor after release', async () => {
    vi.stubEnv('NODE_ENV', 'test');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');

    const first = await acquireJobLease('anchor-batch', 60_000);
    const concurrent = await acquireJobLease('anchor-batch', 60_000);
    expect(first.ok).toBe(true);
    expect(concurrent).toEqual({ ok: false, reason: 'already_held' });

    if (first.ok) await first.release();
    const successor = await acquireJobLease('anchor-batch', 60_000);
    expect(successor.ok).toBe(true);
    if (successor.ok) await successor.release();
  });

  it('fails closed in production when the durable lease store is absent', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');

    await expect(acquireJobLease('anchor-batch', 60_000)).resolves.toEqual({
      ok: false,
      reason: 'lease_store_unavailable',
    });
  });

  it('releases Redis ownership with compare-and-delete rather than an unsafe DEL', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'test-token');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ result: 'OK' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ result: 1 }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const lease = await acquireJobLease('anchor-batch', 60_000);
    expect(lease.ok).toBe(true);
    if (lease.ok) await lease.release();

    const claim = JSON.parse(String(fetchMock.mock.calls[0][1].body));
    const release = JSON.parse(String(fetchMock.mock.calls[1][1].body));
    expect(claim.slice(0, 2)).toEqual(['SET', 'ep:job-lease:anchor-batch']);
    expect(claim).toEqual(expect.arrayContaining(['NX', 'PX', '60000']));
    expect(release[0]).toBe('EVAL');
    expect(release).toContain('ep:job-lease:anchor-batch');
    expect(release[1]).toMatch(/GET.*DEL/);
  });

  it('reports Redis contention without granting a second owner', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'test-token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: null }), { status: 200 }),
    ));

    await expect(acquireJobLease('anchor-batch', 60_000)).resolves.toEqual({
      ok: false,
      reason: 'already_held',
    });
  });

  it.each([
    ['an HTTP failure', new Response('', { status: 503 })],
    ['a Redis error', new Response(JSON.stringify({ error: 'redis unavailable' }), { status: 200 })],
    ['an unexpected result', new Response(JSON.stringify({ result: 'PONG' }), { status: 200 })],
  ])('fails closed when the lease store returns %s', async (_label, response) => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'test-token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    const log = vi.spyOn(logger, 'error').mockImplementation(() => undefined);

    await expect(acquireJobLease('anchor-batch', 60_000)).resolves.toEqual({
      ok: false,
      reason: 'lease_store_unavailable',
    });
    expect(log).toHaveBeenCalledWith('job lease store unavailable', expect.objectContaining({
      name: 'anchor-batch',
    }));
  });

  it('keeps the lease fenced by TTL when compare-and-delete cannot be confirmed', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'test-token');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ result: 'OK' }), { status: 200 }))
      .mockResolvedValueOnce(new Response('', { status: 503 }));
    vi.stubGlobal('fetch', fetchMock);
    const log = vi.spyOn(logger, 'error').mockImplementation(() => undefined);

    const lease = await acquireJobLease('anchor-batch', 60_000);
    expect(lease.ok).toBe(true);
    if (lease.ok) await expect(lease.release()).resolves.toBeUndefined();
    expect(log).toHaveBeenCalledWith('job lease release failed', expect.objectContaining({
      name: 'anchor-batch',
    }));
  });
});
