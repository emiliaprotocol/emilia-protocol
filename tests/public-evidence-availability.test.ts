// SPDX-License-Identifier: Apache-2.0
//
// Public evidence surfaces must answer, not refuse.
//
// checkRateLimit refuses a FAIL_CLOSED_CATEGORIES member outright whenever
// durableRequired is set and Upstash is not configured. That is not only an
// outage posture: it takes the category dark in EVERY such deployment. An
// earlier revision of this change listed public_verify as fail-closed, which
// made GET /api/verify/<receiptId> return "Rate limit exceeded" to every
// caller in CI and in any self-hosted production without Upstash. The explorer
// e2e caught it, because app/explorer/page.tsx renders that body and a reader
// asking about a receipt got a rate-limiter message instead of an answer.
//
// The rule these cases pin: a surface whose purpose is letting a stranger check
// a claim fails OPEN. A surface that runs attacker-chosen work fails CLOSED.

import { describe, it, expect, vi, beforeEach } from 'vitest';

function durableRequiredWithoutRedis(): void {
  vi.stubEnv('EP_REQUIRE_DURABLE_RATE_LIMIT', 'true');
  vi.stubEnv('UPSTASH_REDIS_REST_URL', '');
  vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', '');
}

describe('public evidence surfaces stay available without a durable limiter', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
  });

  it('lets a stranger verify a receipt', async () => {
    durableRequiredWithoutRedis();
    const { checkRateLimit } = await import('../lib/rate-limit.js');
    expect((await checkRateLimit('ip:203.0.113.9', 'public_verify')).allowed).toBe(true);
  });

  it('lets a README badge render', async () => {
    durableRequiredWithoutRedis();
    const { checkRateLimit } = await import('../lib/rate-limit.js');
    expect((await checkRateLimit('ip:203.0.113.9', 'public_badge')).allowed).toBe(true);
  });

  it('still refuses attacker-chosen crypto work, so the distinction is real', async () => {
    durableRequiredWithoutRedis();
    const { checkRateLimit } = await import('../lib/rate-limit.js');
    const result = await checkRateLimit('ip:203.0.113.9', 'mcp_tool_call');
    expect(result.allowed).toBe(false);
    expect(result.error).toBe('durable_rate_limit_required');
  });

  it('still refuses an unclassified mutating route', async () => {
    durableRequiredWithoutRedis();
    const { checkRateLimit } = await import('../lib/rate-limit.js');
    expect((await checkRateLimit('ip:203.0.113.9', 'unclassified_write')).allowed).toBe(false);
  });
});
