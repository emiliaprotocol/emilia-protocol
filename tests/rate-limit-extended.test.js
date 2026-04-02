/**
 * EMILIA Protocol — rate-limit.js extended coverage
 *
 * Targets: Redis/Upstash path (mocked fetch), rateLimitBackend with Redis,
 * window expiry logic, fail-closed categories, addRateLimitHeaders edge cases,
 * uncovered lines 103, 141–146, 164.
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// ── 1. Redis-enabled module instance ──────────────────────────────────────────
//
// We create a separate describe block that mocks getUpstashConfig to return
// a config, then dynamically re-imports rate-limit to get a module that
// uses Redis. Vitest module isolation ensures the regular tests still see
// the in-memory mock from rate-limit.test.js.

describe('rateLimitBackend — redis mode (isolated module)', async () => {
  // Isolate this module so we get a fresh instance with Redis config
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('rateLimitBackend returns "upstash-redis" when config is present', async () => {
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => ({
        url: 'https://fake-upstash.io',
        token: 'fake-token',
      })),
    }));
    const { rateLimitBackend } = await import('../lib/rate-limit.js');
    expect(rateLimitBackend()).toBe('upstash-redis');
  });
});

// ── 2. Redis path — checkRateLimitRedis internals ─────────────────────────────

describe('checkRateLimit — Redis path (mocked fetch)', async () => {
  let checkRateLimit;
  let addRateLimitHeaders;
  let RATE_LIMITS;
  const mockFetch = vi.fn();

  beforeEach(async () => {
    vi.resetModules();
    vi.stubGlobal('fetch', mockFetch);
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => ({
        url: 'https://fake-upstash.io',
        token: 'fake-token',
      })),
    }));
    const mod = await import('../lib/rate-limit.js');
    checkRateLimit = mod.checkRateLimit;
    addRateLimitHeaders = mod.addRateLimitHeaders;
    RATE_LIMITS = mod.RATE_LIMITS;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  function makeRedisResponse(result) {
    return Promise.resolve({
      json: () => Promise.resolve({ result }),
    });
  }

  function makeRedisError(error) {
    return Promise.resolve({
      json: () => Promise.resolve({ error }),
    });
  }

  it('allows request when count < max', async () => {
    // ZREMRANGEBYSCORE, ZCARD=0, ZADD, EXPIRE
    mockFetch
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })  // ZREMRANGEBYSCORE
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })  // ZCARD → 0 < max
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) })  // ZADD
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) }); // EXPIRE
    const result = await checkRateLimit('test-ip-redis-1', 'read');
    expect(result.allowed).toBe(true);
    expect(typeof result.remaining).toBe('number');
  });

  it('blocks request when count >= max', async () => {
    const max = RATE_LIMITS.anchor.max; // 1
    mockFetch
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })      // ZREMRANGEBYSCORE
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: max }) })    // ZCARD → max
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: ['ts', String(Math.floor(Date.now() / 1000))] }) }); // ZRANGE WITHSCORES
    const result = await checkRateLimit('test-ip-redis-2', 'anchor');
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('returns positive reset when blocked', async () => {
    mockFetch
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: ['member', String(Math.floor(Date.now() / 1000) - 100)] }) });
    const result = await checkRateLimit('test-ip-redis-3', 'anchor');
    expect(result.reset).toBeGreaterThan(0);
  });

  it('fail-closed for "submit" on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('connection refused'));
    const result = await checkRateLimit('test-ip-err', 'submit');
    expect(result.allowed).toBe(false);
    expect(result.error).toBe('rate_limit_unavailable');
  });

  it('fail-closed for "dispute_write" on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('timeout'));
    const result = await checkRateLimit('test-ip-dispute', 'dispute_write');
    expect(result.allowed).toBe(false);
    expect(result.error).toBe('rate_limit_unavailable');
  });

  it('fail-closed for "register" on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('network error'));
    const result = await checkRateLimit('test-ip-register', 'register');
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('fail-closed for "anchor" on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('ERR'));
    const result = await checkRateLimit('test-ip-anchor', 'anchor');
    expect(result.allowed).toBe(false);
  });

  it('fail-open for "read" on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('network error'));
    const result = await checkRateLimit('test-ip-read-err', 'read');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(-1);
  });

  it('fail-open for unknown category on Redis error', async () => {
    mockFetch.mockResolvedValue(makeRedisError('network error'));
    const result = await checkRateLimit('test-ip-unknown-err', 'unknown_cat');
    expect(result.allowed).toBe(true);
  });

  it('remaining calculated correctly: max - count - 1', async () => {
    const currentCount = 5;
    mockFetch
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: currentCount }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) });
    const result = await checkRateLimit('test-remaining', 'read');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(RATE_LIMITS.read.max - currentCount - 1);
  });

  it('uses read config for unknown category', async () => {
    mockFetch
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 0 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) })
      .mockResolvedValueOnce({ json: () => Promise.resolve({ result: 1 }) });
    const result = await checkRateLimit('test-unknown-cat', 'completely_unknown');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeLessThanOrEqual(RATE_LIMITS.read.max);
  });
});

// ── 3. In-memory: window expiry logic ─────────────────────────────────────────

describe('checkRateLimit (in-memory) — window expiry', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.resetModules();
  });

  it('expired entries do not count toward limit', async () => {
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => null),
    }));
    const { checkRateLimit } = await import('../lib/rate-limit.js');

    const key = `expiry-test-${Date.now()}`;

    // Exhaust the anchor limit (max 1)
    const first = await checkRateLimit(key, 'anchor');
    expect(first.allowed).toBe(true);

    const second = await checkRateLimit(key, 'anchor');
    expect(second.allowed).toBe(false);

    // Simulate time advancing past the window
    const realNow = Date.now;
    Date.now = () => realNow() + (21600 + 1) * 1000; // past anchor window

    const afterExpiry = await checkRateLimit(key, 'anchor');
    expect(afterExpiry.allowed).toBe(true);

    Date.now = realNow;
  });
});

// ── 4. Periodic cleanup (line 141–146) ────────────────────────────────────────

describe('in-memory periodic cleanup (line 141–146)', () => {
  it('setInterval is registered (implicitly via module load)', async () => {
    vi.resetModules();
    const intervalSpy = vi.spyOn(globalThis, 'setInterval');
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => null),
    }));
    await import('../lib/rate-limit.js');
    // The module registers one setInterval for cleanup
    expect(intervalSpy).toHaveBeenCalled();
    intervalSpy.mockRestore();
    vi.resetModules();
  });

  it('cleanup callback runs without error when map has entries', async () => {
    vi.resetModules();
    let capturedCallback;
    const originalSetInterval = globalThis.setInterval;
    globalThis.setInterval = (fn, delay) => {
      capturedCallback = fn;
      return originalSetInterval(fn, delay);
    };

    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => null),
    }));
    const { checkRateLimit } = await import('../lib/rate-limit.js');

    // Prime some entries
    await checkRateLimit('cleanup-key-1', 'read');
    await checkRateLimit('cleanup-key-2', 'read');

    // Run the cleanup callback — should not throw
    if (capturedCallback) {
      expect(() => capturedCallback()).not.toThrow();
    }

    globalThis.setInterval = originalSetInterval;
    vi.resetModules();
  });
});

// ── 5. addRateLimitHeaders — edge cases ──────────────────────────────────────

describe('addRateLimitHeaders — edge cases (in-memory module)', () => {
  let addRateLimitHeaders;
  let RATE_LIMITS;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => null),
    }));
    const mod = await import('../lib/rate-limit.js');
    addRateLimitHeaders = mod.addRateLimitHeaders;
    RATE_LIMITS = mod.RATE_LIMITS;
  });

  afterEach(() => vi.resetModules());

  function makeResponse() {
    const store = {};
    return {
      headers: {
        set: (k, v) => { store[k] = v; },
        get: (k) => store[k] ?? null,
        _store: store,
      },
    };
  }

  it('negative remaining is stringified (remaining=-1 from fail-open)', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: -1, reset: 60 }, 'read');
    expect(res.headers._store['X-RateLimit-Remaining']).toBe('-1');
  });

  it('zero reset time is stringified', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 5, reset: 0 }, 'read');
    expect(res.headers._store['X-RateLimit-Reset']).toBe('0');
  });

  it('cloud_read category uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 99, reset: 60 }, 'cloud_read');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.cloud_read.max));
  });

  it('cloud_write category uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 29, reset: 60 }, 'cloud_write');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.cloud_write.max));
  });

  it('cloud_admin category uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 9, reset: 60 }, 'cloud_admin');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.cloud_admin.max));
  });

  it('dispute_write uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 3, reset: 3600 }, 'dispute_write');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.dispute_write.max));
  });

  it('report_write uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 2, reset: 3600 }, 'report_write');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.report_write.max));
  });

  it('protocol_write uses correct limit', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 50, reset: 60 }, 'protocol_write');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.protocol_write.max));
  });
});

// ── 6. getClientIP — line 164 branch (x-forwarded-for present but empty) ──────

describe('getClientIP — edge cases (line 164 branch)', () => {
  let getClientIP;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('@/lib/env', () => ({
      getUpstashConfig: vi.fn(() => null),
    }));
    const mod = await import('../lib/rate-limit.js');
    getClientIP = mod.getClientIP;
  });

  afterEach(() => vi.resetModules());

  it('returns x-real-ip when x-forwarded-for is empty string', () => {
    const req = {
      headers: {
        get: (h) => {
          if (h === 'x-forwarded-for') return '';
          if (h === 'x-real-ip') return '10.0.0.5';
          return null;
        },
      },
    };
    // xff.split(',').pop().trim() on '' → '' → falsy → falls through to x-real-ip
    const ip = getClientIP(req);
    expect(ip).toBe('10.0.0.5');
  });

  it('returns "unknown" when all headers missing', () => {
    const req = { headers: { get: () => null } };
    expect(getClientIP(req)).toBe('unknown');
  });

  it('handles three-hop forwarded-for chain', () => {
    const req = {
      headers: {
        get: (h) => h === 'x-forwarded-for' ? '1.1.1.1, 2.2.2.2, 3.3.3.3' : null,
      },
    };
    expect(getClientIP(req)).toBe('3.3.3.3');
  });
});
