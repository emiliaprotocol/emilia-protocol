// SPDX-License-Identifier: Apache-2.0
//
// Cross-instance lease for low-volume, high-consequence background jobs. A
// serverless deployment must not use an in-process mutex: two warm instances
// would both enter the irreversible section. Production therefore requires the
// same durable Redis service used by the rate limiter and operator replay gate.

import crypto from 'node:crypto';
import { getUpstashConfig, isProduction } from './env.js';
import { logger } from './logger.js';

const REDIS_TIMEOUT_MS = 3000;
const memoryLeases = new Map<string, { owner: string; expiresAt: number }>();

export type JobLease =
  | { ok: true; owner: string; release: () => Promise<void> }
  | { ok: false; reason: 'already_held' | 'lease_store_unavailable' };

function leaseKey(name: string): string {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(name)) throw new TypeError('job lease name is malformed');
  return `ep:job-lease:${name}`;
}

export async function acquireJobLease(name: string, ttlMs: number): Promise<JobLease> {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 60 * 60 * 1000) {
    throw new TypeError('job lease TTL must be between one second and one hour');
  }
  const key = leaseKey(name);
  const owner = crypto.randomUUID();
  const upstash = getUpstashConfig();

  if (!upstash) {
    if (isProduction()) return { ok: false, reason: 'lease_store_unavailable' };
    const now = Date.now();
    const current = memoryLeases.get(key);
    if (current && current.expiresAt > now) return { ok: false, reason: 'already_held' };
    memoryLeases.set(key, { owner, expiresAt: now + ttlMs });
    return {
      ok: true,
      owner,
      release: async () => {
        if (memoryLeases.get(key)?.owner === owner) memoryLeases.delete(key);
      },
    };
  }

  try {
    const response = await fetch(upstash.url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${upstash.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(['SET', key, owner, 'NX', 'PX', String(ttlMs)]),
      signal: AbortSignal.timeout(REDIS_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`lease store returned HTTP ${response.status}`);
    const data = await response.json();
    if (data?.error) throw new Error(String(data.error));
    if (data?.result === null) return { ok: false, reason: 'already_held' };
    if (data?.result !== 'OK') throw new Error('lease store returned an unexpected SET result');

    return {
      ok: true,
      owner,
      release: async () => {
        try {
          const script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end";
          const released = await fetch(upstash.url, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${upstash.token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(['EVAL', script, '1', key, owner]),
            signal: AbortSignal.timeout(REDIS_TIMEOUT_MS),
          });
          if (!released.ok) throw new Error(`lease release returned HTTP ${released.status}`);
          const result = await released.json();
          if (result?.error) throw new Error(String(result.error));
        } catch (error: any) {
          // The TTL is the final fence. A failed release delays the next batch;
          // it must never erase a successor's lease or hide the completed batch.
          logger.error('job lease release failed', { name, error: error?.message });
        }
      },
    };
  } catch (error: any) {
    logger.error('job lease store unavailable', { name, error: error?.message });
    return { ok: false, reason: 'lease_store_unavailable' };
  }
}

export function _resetJobLeasesForTesting(): void {
  memoryLeases.clear();
}
