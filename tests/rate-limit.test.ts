/**
 * Tests for lib/rate-limit.js
 *
 * The module auto-detects Upstash vs in-memory at import time via getUpstashConfig().
 * We mock @/lib/env so all tests run against the in-memory fallback (no Redis needed).
 */

import { vi } from 'vitest';

// Must be declared before importing the module under test so the mock is in place
// when the module initialises at the top level.
vi.mock('@/lib/env', () => ({
  getUpstashConfig: vi.fn(() => null), // force in-memory mode
  getRateLimitConfig: vi.fn(() => ({ durableRequired: false })),
}));

import {
  RATE_LIMITS,
  checkRateLimit,
  getClientIP,
  addRateLimitHeaders,
  rateLimitBackend,
} from '@/lib/rate-limit.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(headers = {}) {
  return {
    headers: {
      get: (name) => headers[name.toLowerCase()] ?? null,
    },
  };
}

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

// ---------------------------------------------------------------------------
// RATE_LIMITS constant
// ---------------------------------------------------------------------------

describe('RATE_LIMITS', () => {
  it('exports a non-empty object of rate limit configs', () => {
    expect(RATE_LIMITS).toBeDefined();
    expect(typeof RATE_LIMITS).toBe('object');
    expect(Object.keys(RATE_LIMITS).length).toBeGreaterThan(0);
  });

  it('every category has window and max properties', () => {
    for (const [category, config] of Object.entries(RATE_LIMITS)) {
      expect(typeof config.window, `${category}.window`).toBe('number');
      expect(typeof config.max, `${category}.max`).toBe('number');
      expect(config.window, `${category}.window > 0`).toBeGreaterThan(0);
      expect(config.max, `${category}.max > 0`).toBeGreaterThan(0);
    }
  });

  it('register limit is 10/hour', () => {
    expect(RATE_LIMITS.register.max).toBe(10);
    expect(RATE_LIMITS.register.window).toBe(3600);
  });

  it('anchor limit is 1 per 6 hours', () => {
    expect(RATE_LIMITS.anchor.max).toBe(1);
    expect(RATE_LIMITS.anchor.window).toBe(21600);
  });

  it('read limit is more generous than register', () => {
    expect(RATE_LIMITS.read.max).toBeGreaterThan(RATE_LIMITS.register.max);
  });

  it('contains all expected categories', () => {
    const expectedCategories = [
      'register', 'submit', 'protocol_write', 'read', 'anchor',
      'waitlist', 'dispute_write', 'report_write', 'cloud_read',
      'cloud_write', 'cloud_admin',
    ];
    for (const cat of expectedCategories) {
      expect(RATE_LIMITS).toHaveProperty(cat);
    }
  });
});

// ---------------------------------------------------------------------------
// rateLimitBackend
// ---------------------------------------------------------------------------

describe('rateLimitBackend', () => {
  it('returns "in-memory" when Upstash is not configured', () => {
    expect(rateLimitBackend()).toBe('in-memory');
  });
});

// ---------------------------------------------------------------------------
// checkRateLimit (in-memory)
// ---------------------------------------------------------------------------

describe('checkRateLimit (in-memory fallback)', () => {
  it('allows a first request', async () => {
    const result = await checkRateLimit('test-ip-allow-first', 'read');
    expect(result.allowed).toBe(true);
    expect(typeof result.remaining).toBe('number');
    expect(typeof result.reset).toBe('number');
  });

  it('remaining decreases with each request', async () => {
    const key = `ip-decrement-${Date.now()}`;
    const first = await checkRateLimit(key, 'waitlist');
    const second = await checkRateLimit(key, 'waitlist');
    expect(second.remaining).toBeLessThan(first.remaining);
  });

  it('denies once the limit is exhausted', async () => {
    const key = `ip-exhaust-${Date.now()}`;
    // anchor has max:1 — easiest to exhaust
    const first = await checkRateLimit(key, 'anchor');
    expect(first.allowed).toBe(true);
    const second = await checkRateLimit(key, 'anchor');
    expect(second.allowed).toBe(false);
    expect(second.remaining).toBe(0);
  });

  it('denied result includes a positive reset time', async () => {
    const key = `ip-reset-${Date.now()}`;
    await checkRateLimit(key, 'anchor'); // consume the 1 allowed
    const denied = await checkRateLimit(key, 'anchor');
    expect(denied.reset).toBeGreaterThan(0);
  });

  it('falls back to read config for unknown category', async () => {
    const key = `ip-unknown-${Date.now()}`;
    const result = await checkRateLimit(key, 'totally_unknown_category');
    expect(result.allowed).toBe(true);
    // remaining should not exceed read.max
    expect(result.remaining).toBeLessThanOrEqual(RATE_LIMITS.read.max);
  });

  it('different keys are tracked independently', async () => {
    const keyA = `ip-a-${Date.now()}`;
    const keyB = `ip-b-${Date.now()}`;
    await checkRateLimit(keyA, 'anchor'); // exhaust keyA
    const resultB = await checkRateLimit(keyB, 'anchor');
    expect(resultB.allowed).toBe(true);
  });

  it('returns allowed:true and remaining >= 0 for a fresh key', async () => {
    const result = await checkRateLimit(`fresh-${Date.now()}`, 'cloud_admin');
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// getClientIP
// ---------------------------------------------------------------------------

describe('getClientIP', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('ignores caller-supplied forwarding headers off a trusted platform', () => {
    const req = makeRequest({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' });
    expect(getClientIP(req)).toBe('unknown');
  });

  it('does not trust a caller-supplied Vercel marker off the Vercel platform', () => {
    const req = makeRequest({
      'x-vercel-id': 'iad1::abc',
      'x-vercel-forwarded-for': '203.0.113.8',
      'x-forwarded-for': '198.51.100.9',
    });
    expect(getClientIP(req)).toBe('unknown');
  });

  it('uses the Vercel-overwritten forwarding header on the Vercel platform', () => {
    vi.stubEnv('VERCEL', '1');
    const req = makeRequest({
      'x-vercel-forwarded-for': '203.0.113.8',
      'x-forwarded-for': '198.51.100.9',
    });
    expect(getClientIP(req)).toBe('203.0.113.8');
  });

  it('returns "unknown" when no IP headers present', () => {
    const req = makeRequest({});
    expect(getClientIP(req)).toBe('unknown');
  });

  it('trims whitespace from the trusted Vercel forwarding value', () => {
    vi.stubEnv('VERCEL', '1');
    const req = makeRequest({
      'x-vercel-forwarded-for': '1.1.1.1,  2.2.2.2  ',
    });
    expect(getClientIP(req)).toBe('2.2.2.2');
  });

  it('does not accept x-real-ip without an explicit trusted platform marker', () => {
    const req = makeRequest({
      'x-forwarded-for': '9.9.9.9',
      'x-real-ip': '8.8.8.8',
    });
    expect(getClientIP(req)).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// addRateLimitHeaders
// ---------------------------------------------------------------------------

describe('addRateLimitHeaders', () => {
  it('sets X-RateLimit-Limit, Remaining, and Reset headers', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 5, reset: 60 }, 'read');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.read.max));
    expect(res.headers._store['X-RateLimit-Remaining']).toBe('5');
    expect(res.headers._store['X-RateLimit-Reset']).toBe('60');
  });

  it('uses read config for unknown categories', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 0, reset: 30 }, 'unknown_cat');
    expect(res.headers._store['X-RateLimit-Limit']).toBe(String(RATE_LIMITS.read.max));
  });

  it('returns the response object for chaining', () => {
    const res = makeResponse();
    const returned = addRateLimitHeaders(res, { remaining: 10, reset: 120 }, 'submit');
    expect(returned).toBe(res);
  });

  it('reflects the correct limit for each known category', () => {
    for (const [category, config] of Object.entries(RATE_LIMITS)) {
      const res = makeResponse();
      addRateLimitHeaders(res, { remaining: 0, reset: 1 }, category);
      expect(res.headers._store['X-RateLimit-Limit']).toBe(String(config.max));
    }
  });

  it('converts numeric remaining to string', () => {
    const res = makeResponse();
    addRateLimitHeaders(res, { remaining: 0, reset: 0 }, 'register');
    expect(typeof res.headers._store['X-RateLimit-Remaining']).toBe('string');
  });
});
