// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { acquireJobLease, _resetJobLeasesForTesting } from '../lib/job-lease.js';

beforeEach(() => {
  _resetJobLeasesForTesting();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('durable background-job lease', () => {
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
});
