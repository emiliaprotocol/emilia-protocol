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

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  reset: number;
  error?: string;
}

/**
 * Rate limit configuration per endpoint category.
 */
export const RATE_LIMITS: Record<string, { window: number; max: number }> = {
  register:      { window: 3600, max: 10 },    // 10 registrations per hour per IP
  submit:        { window: 60, max: 30 },       // 30 receipt submissions per minute per key
  protocol_write: { window: 60, max: 60 },      // 60 handshake/signoff writes per minute per key
  protocol_read:  { window: 60, max: 120 },     // 120 protocol reads per minute per IP
  read:          { window: 60, max: 120 },      // 120 reads per minute per IP
  anchor:        { window: 21600, max: 1 },     // 1 anchor per 6 hours (cron only)
  waitlist:      { window: 3600, max: 5 },      // 5 waitlist signups per hour per IP
  dispute_write: { window: 3600, max: 5 },      // 5 dispute actions per hour per key — sensitive write
  report_write:  { window: 3600, max: 3 },      // 3 human reports per hour per IP — abuse prevention
  cloud_read:    { window: 60, max: 100 },      // 100 cloud dashboard reads per minute per key
  cloud_write:   { window: 60, max: 30 },       // 30 cloud writes per minute per key
  cloud_admin:   { window: 60, max: 10 },       // 10 cloud admin actions per minute per key
  mobile_pairing: { window: 60, max: 10 },      // 10 native pairing attempts per minute per IP
  mobile_runtime_ip: { window: 60, max: 120 },  // Bound unauthenticated work before token lookup
  mobile_write: { window: 60, max: 60 },        // Bound ceremonies/attestation per paired session
  // Every mutating route is expected to be named in middleware's ROUTE_POLICIES
  // (tests/route-rate-limit-coverage.test.ts fails CI if one is not). This tier
  // is what an unnamed one gets in the window between shipping and noticing:
  // tight enough to blunt a volumetric attack on an endpoint nobody classified,
  // loose enough that a legitimate new route degrades rather than bricks.
  unclassified_write: { window: 60, max: 10 },
  // Hosted MCP tool calls. Each one runs real asymmetric crypto (Ed25519 or
  // P-256) plus canonicalization over caller-supplied JSON, so it does not
  // belong in the same bucket as a cheap database read.
  mcp_tool_call: { window: 60, max: 60 },
  // Unauthenticated public receipt verification. Its own bucket so a burst of
  // verification cannot spend the same allowance as cheap reads.
  //
  // Deliberately NOT in FAIL_CLOSED_CATEGORIES, unlike mcp_tool_call, and the
  // difference matters because the two look alike. mcp_tool_call runs Ed25519
  // over a caller-supplied document of up to 256 KB under a caller-supplied
  // key: the attacker chooses the work. This route takes a receipt id, reads a
  // row the server already holds, and checks a bounded Merkle proof over it.
  // The attacker chooses neither the payload nor its size.
  //
  // There is also no oracle here to protect. The verifier is this repository's
  // published npm package, so anyone wanting unlimited verification runs it
  // locally at full speed. Failing this closed buys nothing and costs the whole
  // point of the endpoint: a receipt nobody can check is worthless, so
  // availability IS the security property on this surface.
  public_verify: { window: 60, max: 60 },
  // Public capability badges. Cheap to serve (an SVG and one projection read)
  // and embedded in READMEs and docs, where an image proxy collapses many
  // readers onto a few source addresses. Deliberately generous: throttling this
  // by IP degrades honest embedders long before it inconveniences anyone else.
  public_badge: { window: 60, max: 240 },
};

import { getRateLimitConfig, getUpstashConfig } from '@/lib/env';
import { logger } from './logger.js';

// =============================================================================
// UPSTASH REDIS (production)
// =============================================================================

const _upstash = getUpstashConfig();
const UPSTASH_URL = _upstash?.url;
const UPSTASH_TOKEN = _upstash?.token;
const useRedis = !!_upstash;
const durableRequired = getRateLimitConfig().durableRequired;

const REDIS_TIMEOUT_MS = 3000; // 3s hard timeout — never block API responses waiting for Redis
const FAIL_CLOSED_CATEGORIES = new Set([
  'submit',
  'protocol_write',
  'dispute_write',
  'report_write',
  'register',
  'anchor',
  'cloud_write',
  'cloud_admin',
  'mobile_pairing',
  'mobile_runtime_ip',
  'mobile_write',
  // An unclassified mutating route is unreviewed by definition; a rate-limiter
  // outage must not be the moment it runs unthrottled.
  'unclassified_write',
  // Unauthenticated CPU work. Failing open here during a Redis outage hands an
  // attacker free signature verification at whatever rate they can dial.
  'mcp_tool_call',
  // public_verify and public_badge are deliberately absent. Membership here is
  // not only an outage posture: checkRateLimit below refuses a fail-closed
  // category outright whenever durableRequired is set and Upstash is not
  // configured, so listing a public evidence surface here takes it dark in
  // every such deployment, not merely during a Redis incident. See the note on
  // those two tiers above for why that trade is wrong for them and right for
  // mcp_tool_call.
]);

async function redisCommand(command: string, ...args: string[]): Promise<any> {
  const res = await fetch(`${UPSTASH_URL}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify([command, ...args]),
    signal: AbortSignal.timeout(REDIS_TIMEOUT_MS),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data.result;
}

async function checkRateLimitRedis(key: string, category: string): Promise<RateLimitResult> {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  const redisKey = `ep:rl:${category}:${key}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.window;
  const member = `${now}:${Math.random().toString(36).slice(2, 10)}`;

  try {
    // One Redis script makes the sliding-window check+insert atomic under
    // concurrent serverless invocations. Multi-command ZCARD/ZADD can overrun.
    const result = await redisCommand('EVAL', RATE_LIMIT_LUA, '1',
      redisKey,
      String(windowStart),
      String(config.max),
      String(config.window),
      String(now),
      member,
    );
    const [allowed, remaining, reset] = Array.isArray(result) ? result.map(Number) : [0, 0, 60];
    return {
      allowed: allowed === 1,
      remaining: Number.isFinite(remaining) ? remaining : 0,
      reset: Math.max(1, Number.isFinite(reset) ? reset : config.window),
    };
  } catch (err: any) {
    logger.error('Upstash rate limit error:', err.message);
    // Sensitive write/admin categories fail-closed on Redis error to prevent abuse
    // during infrastructure outages. Read endpoints fail-open for availability.
    if (FAIL_CLOSED_CATEGORIES.has(category)) {
      return { allowed: false, remaining: 0, reset: 60, error: 'rate_limit_unavailable' };
    }
    return { allowed: true, remaining: -1, reset: config.window };
  }
}

const RATE_LIMIT_LUA = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '0', ARGV[1])
local count = redis.call('ZCARD', KEYS[1])
local max = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
if count >= max then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local reset = window
  if oldest[2] then
    reset = tonumber(oldest[2]) + window - now
    if reset < 1 then reset = 1 end
  end
  return {0, 0, reset}
end
redis.call('ZADD', KEYS[1], ARGV[4], ARGV[5])
redis.call('EXPIRE', KEYS[1], window + 60)
return {1, max - count - 1, window}
`;

// =============================================================================
// IN-MEMORY FALLBACK (development / when Upstash not configured)
// =============================================================================

const windows = new Map<string, number[]>();

function checkRateLimitMemory(key: string, category: string): RateLimitResult {
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
 * @returns {Promise<{ allowed: boolean, remaining: number, reset: number, error?: string }>}
 */
export async function checkRateLimit(key: string, category: string): Promise<RateLimitResult> {
  if (useRedis) {
    return checkRateLimitRedis(key, category);
  }
  if (durableRequired && FAIL_CLOSED_CATEGORIES.has(category)) {
    return { allowed: false, remaining: 0, reset: 60, error: 'durable_rate_limit_required' };
  }
  return checkRateLimitMemory(key, category);
}

/**
 * Get the client IP from a Next.js request.
 */
export function getClientIP(request: Request): string {
  // Use the LAST value in x-forwarded-for (rightmost is closest to the server
  // and hardest to spoof without a trusted proxy chain).
  const xff = request.headers.get('x-forwarded-for');
  const ip = xff ? xff.split(',').pop()!.trim() : null;
  return (
    ip ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

/**
 * Add rate limit headers to a response.
 */
export function addRateLimitHeaders<T extends { headers: Headers }>(response: T, result: RateLimitResult, category: string): T {
  const config = RATE_LIMITS[category] || RATE_LIMITS.read;
  response.headers.set('X-RateLimit-Limit', String(config.max));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.reset));
  return response;
}

/**
 * Report which backend is active (for diagnostics).
 */
export function rateLimitBackend(): 'upstash-redis' | 'in-memory' {
  return useRedis ? 'upstash-redis' : 'in-memory';
}
