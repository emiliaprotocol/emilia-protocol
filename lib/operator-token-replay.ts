/**
 * Single-use consumption for per-operator tokens.
 *
 * @license Apache-2.0
 *
 * An `ep_op_` token is a bearer credential: whoever holds the bytes can present
 * them. The HMAC and the timestamp prove the token was minted by a keyholder
 * and minted recently. Neither proves the presenter is the keyholder, so until
 * this module existed a token captured from a CI log or a `ps aux` line was as
 * good as the operator's secret for the remainder of its validity window, at
 * every endpoint that accepts operator auth.
 *
 * The fix is to make presentation destructive: the first request that presents
 * a token consumes it, and every later presentation of the same bytes is
 * refused. That does not stop an attacker who captures a token BEFORE its
 * legitimate use and races ahead of it, but it collapses the window from "the
 * rest of five minutes, at any endpoint" to "before the operator's own request
 * lands".
 *
 * Backends, in order of preference:
 *
 *   Upstash Redis  — cross-instance, the only correct backend for a serverless
 *                    deployment. Used whenever UPSTASH_REDIS_REST_* is set.
 *   in-process Map — single-instance only. Correct for local development, a
 *                    self-hosted single process, and tests. On a multi-instance
 *                    deployment it degrades to per-instance protection, which
 *                    is NOT replay protection: an attacker who reaches a
 *                    different instance replays successfully. Deployments that
 *                    care must configure Redis.
 *
 * A configured Redis that errors fails CLOSED (the token is refused). Operator
 * auth is a low-volume, high-value path, and the unattended cron jobs do not
 * reach this code at all — they authenticate with the shared CRON_SECRET, which
 * has no nonce to consume. So failing closed here cannot stop the schedulers.
 */

import crypto from 'crypto';
import { getUpstashConfig } from './env.js';
import { logger } from './logger.js';

const REDIS_TIMEOUT_MS = 3000;

export interface ConsumeResult {
  ok: boolean;
  reason?: 'already_consumed' | 'replay_store_unavailable';
}

/** token hmac -> epoch ms at which the entry may be dropped */
const _memory = new Map<string, number>();

/**
 * The stored key is a digest, never the token's own HMAC. A replay store that
 * held live credential material would hand an attacker with read access to it
 * exactly what the store exists to protect.
 */
function keyFor(tokenHmacHex: string): string {
  return `ep:optok:${crypto.createHash('sha256').update(tokenHmacHex).digest('hex')}`;
}

function sweepMemory(now: number): void {
  for (const [key, expiresAt] of _memory) {
    if (expiresAt <= now) _memory.delete(key);
  }
}

/**
 * Claim a token's one permitted use.
 *
 * @param tokenHmacHex - the token's HMAC segment (its unique part)
 * @param ttlSeconds - how long the record must outlive the token's own window
 * @returns ok:true if this caller claimed it; ok:false if it was already spent
 *          or the durable store could not answer.
 */
export async function consumeOperatorToken(
  tokenHmacHex: string,
  ttlSeconds: number,
): Promise<ConsumeResult> {
  const key = keyFor(tokenHmacHex);
  const upstash = getUpstashConfig();

  if (!upstash) {
    const now = Date.now();
    sweepMemory(now);
    if (_memory.has(key)) return { ok: false, reason: 'already_consumed' };
    _memory.set(key, now + ttlSeconds * 1000);
    return { ok: true };
  }

  try {
    // SET key 1 NX EX ttl — atomic claim. Returns null when the key exists,
    // which is precisely "someone already presented these bytes".
    const res = await fetch(upstash.url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${upstash.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(['SET', key, '1', 'NX', 'EX', String(Math.max(1, Math.ceil(ttlSeconds)))]),
      signal: AbortSignal.timeout(REDIS_TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`replay store returned HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data?.error) throw new Error(String(data.error));
    if (data?.result === null) {
      return { ok: false, reason: 'already_consumed' };
    }
    if (data?.result !== 'OK') {
      throw new Error('replay store returned an unexpected SET result');
    }
    return { ok: true };
  } catch (err: any) {
    logger.error('operator token replay store unavailable', { error: err?.message });
    return { ok: false, reason: 'replay_store_unavailable' };
  }
}

/** Test seam. Clears the in-process fallback between cases. */
export function _resetOperatorTokenReplayMemory(): void {
  _memory.clear();
}
