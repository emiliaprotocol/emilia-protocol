/**
 * EMILIA Protocol — Rate Limiting
 *
 * Production-grade: Uses Upstash Redis when UPSTASH_REDIS_REST_URL is set.
 * Development fallback: In-memory sliding window per serverless instance.
 *
 * Upstash Redis is globally distributed, durable, and works across all
 * Vercel serverless instances. No state lost on cold starts or scale-out.
 *
 * Setup:
 *   1. Create free Upstash Redis at https://upstash.com
 *   2. Add to Vercel env vars:
 *      - UPSTASH_REDIS_REST_URL
 *      - UPSTASH_REDIS_REST_TOKEN
 *
 * @license Apache-2.0
 */

/**
 * Rate limit configuration per endpoint category.
 */
export const RATE_LIMITS = {
  register:      { window: 3600, max: 10 },    // 10 registrations per hour per IP
  submit:        { window: 60, max: 30 },       // 30 receipt submissions per minute per key
  read:          { window: 60, max: 120 },      // 120 reads per minute per IP
  anchor:        { window: 21600, max: 1 },     // 1 anchor per 6 hours (cron only)
  waitlist:      { window: 3600, max: 5 },      // 5 waitlist signups per hour per IP
  dispute_write: { window: 3600, max: 5 },      // 5 dispute actions per hour per key — sensitive write
  report_write:  { window: 3600, max: 3 },      // 3 human reports per hour per IP — abuse prevention
};

// =============================================================================
// UPSTASH REDIS (production)
// =============================================================================

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const useRedis = !!(UPSTASH_URL && UPSTASH_TOKEN);

async function redisCommand(command, ...args) {
  const res = await fetch(`${UPSTASH_URL}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify([command, ...args]),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data.result;
}

async function checkRateLimitRedis(key, category) {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  const redisKey = `ep:rl:${category}:${key}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.window;

  try {
    // Sorted set: score = timestamp, member = unique request ID
    // Remove expired entries
    await redisCommand('ZREMRANGEBYSCORE', redisKey, '0', String(windowStart));

    // Count current entries
    const count = await redisCommand('ZCARD', redisKey);

    if (count >= config.max) {
      // Get oldest active entry to compute reset time
      const oldest = await redisCommand('ZRANGE', redisKey, '0', '0', 'WITHSCORES');
      const resetAt = oldest && oldest[1] ? parseInt(oldest[1]) + config.window - now : config.window;
      return { allowed: false, remaining: 0, reset: Math.max(1, resetAt) };
    }

    // Add this request
    const member = `${now}:${Math.random().toString(36).slice(2, 8)}`;
    await redisCommand('ZADD', redisKey, String(now), member);
    await redisCommand('EXPIRE', redisKey, String(config.window + 60));

    return {
      allowed: true,
      remaining: config.max - count - 1,
      reset: config.window,
    };
  } catch (err) {
    console.error('Upstash rate limit error:', err.message);
    // Sensitive write categories fail-closed on Redis error to prevent abuse
    // during infrastructure outages. Read endpoints fail-open for availability.
    const FAIL_CLOSED_CATEGORIES = new Set(['submit', 'dispute_write', 'register', 'anchor']);
    if (FAIL_CLOSED_CATEGORIES.has(category)) {
      return { allowed: false, remaining: 0, reset: 60, error: 'rate_limit_unavailable' };
    }
    return { allowed: true, remaining: -1, reset: config.window };
  }
}

// =============================================================================
// IN-MEMORY FALLBACK (development / when Upstash not configured)
// =============================================================================

const windows = new Map();

function checkRateLimitMemory(key, category) {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  const windowKey = `${category}:${key}`;
  const now = Date.now();
  const windowStart = now - config.window * 1000;

  let entries = windows.get(windowKey);
  if (!entries) {
    entries = [];
    windows.set(windowKey, entries);
  }

  const active = entries.filter(t => t > windowStart);
  windows.set(windowKey, active);

  if (active.length >= config.max) {
    const oldestActive = active[0];
    const resetMs = oldestActive + config.window * 1000 - now;
    return { allowed: false, remaining: 0, reset: Math.ceil(resetMs / 1000) };
  }

  active.push(now);
  return { allowed: true, remaining: config.max - active.length, reset: config.window };
}

// Periodic cleanup (in-memory only)
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = Date.now();
    const maxWindow = 21600 * 1000;
    for (const [key, entries] of windows) {
      const active = entries.filter(t => t > now - maxWindow);
      if (active.length === 0) windows.delete(key);
      else windows.set(key, active);
    }
  }, 5 * 60 * 1000);
}

// =============================================================================
// PUBLIC API — auto-selects Redis or memory
// =============================================================================

/**
 * Check rate limit. Uses Upstash Redis in production, in-memory in dev.
 *
 * @param {string} key - Identifier (IP address or API key prefix)
 * @param {string} category - One of: register, submit, read, anchor, waitlist
 * @returns {Promise<{ allowed: boolean, remaining: number, reset: number }>}
 */
export async function checkRateLimit(key, category) {
  if (useRedis) {
    return checkRateLimitRedis(key, category);
  }
  return checkRateLimitMemory(key, category);
}

/**
 * Get the client IP from a Next.js request.
 */
export function getClientIP(request) {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

/**
 * Add rate limit headers to a response.
 */
export function addRateLimitHeaders(response, result, category) {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  response.headers.set('X-RateLimit-Limit', String(config.max));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.reset));
  return response;
}

/**
 * Report which backend is active (for diagnostics).
 */
export function rateLimitBackend() {
  return useRedis ? 'upstash-redis' : 'in-memory';
}
