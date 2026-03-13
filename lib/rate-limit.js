/**
 * EMILIA Protocol — Rate Limiting
 *
 * Simple rate limiter for Vercel serverless.
 * Uses in-memory Map per instance + Supabase for persistence.
 *
 * Upgrade path: swap to @upstash/ratelimit for production scale.
 *
 * @license Apache-2.0
 */

// In-memory sliding window (per serverless instance — not globally shared)
// This provides fast first-line defense. Supabase provides durable enforcement.
const windows = new Map();

/**
 * Rate limit configuration per endpoint category.
 */
export const RATE_LIMITS = {
  register: { window: 3600, max: 10 },      // 10 registrations per hour per IP
  submit:   { window: 60, max: 30 },         // 30 receipt submissions per minute per key
  read:     { window: 60, max: 120 },        // 120 reads per minute per IP
  anchor:   { window: 21600, max: 1 },       // 1 anchor per 6 hours (cron only)
  waitlist: { window: 3600, max: 5 },        // 5 waitlist signups per hour per IP
};

/**
 * Check rate limit (in-memory, fast path).
 *
 * @param {string} key - Identifier (IP address or API key prefix)
 * @param {string} category - One of: register, submit, read, anchor, waitlist
 * @returns {{ allowed: boolean, remaining: number, reset: number }}
 */
export function checkRateLimit(key, category) {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  const windowKey = `${category}:${key}`;
  const now = Date.now();
  const windowStart = now - config.window * 1000;

  // Get or create window
  let entries = windows.get(windowKey);
  if (!entries) {
    entries = [];
    windows.set(windowKey, entries);
  }

  // Prune expired entries
  const active = entries.filter(t => t > windowStart);
  windows.set(windowKey, active);

  if (active.length >= config.max) {
    const oldestActive = active[0];
    const resetMs = oldestActive + config.window * 1000 - now;
    return {
      allowed: false,
      remaining: 0,
      reset: Math.ceil(resetMs / 1000),
    };
  }

  // Record this request
  active.push(now);

  return {
    allowed: true,
    remaining: config.max - active.length,
    reset: config.window,
  };
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

// Periodic cleanup of stale windows (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, entries] of windows) {
    const maxWindow = 21600 * 1000; // max window = 6 hours
    const active = entries.filter(t => t > now - maxWindow);
    if (active.length === 0) {
      windows.delete(key);
    } else {
      windows.set(key, active);
    }
  }
}, 5 * 60 * 1000);
