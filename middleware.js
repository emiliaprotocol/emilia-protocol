import { NextResponse } from 'next/server';
import { checkRateLimit, getClientIP, RATE_LIMITS } from '@/lib/rate-limit';

/**
 * EMILIA Protocol — API Rate Limiting Middleware
 *
 * Write routes: throttled by API key prefix + IP (identity-aware)
 * Read routes:  throttled by IP only
 * Register:     throttled by IP only (no API key yet)
 */

const WRITE_CATEGORIES = ['submit', 'anchor', 'dispute_write', 'report_write'];

function getCategory(pathname) {
  if (pathname.startsWith('/api/entities/register')) return 'register';
  if (pathname.startsWith('/api/receipts/submit')) return 'submit';
  if (pathname.startsWith('/api/needs/') && pathname.endsWith('/rate')) return 'submit';
  if (pathname.startsWith('/api/needs/broadcast')) return 'submit';
  if (pathname.startsWith('/api/blockchain/anchor')) return 'anchor';
  if (pathname.startsWith('/api/disputes/report')) return 'report_write';
  if (pathname.startsWith('/api/disputes/file')) return 'dispute_write';
  if (pathname.startsWith('/api/disputes/respond')) return 'dispute_write';
  if (pathname.startsWith('/api/disputes/resolve')) return 'dispute_write';
  if (pathname.startsWith('/api/waitlist')) return 'waitlist';
  if (pathname.startsWith('/api/')) return 'read';
  return null;
}

function getApiKeyPrefix(request) {
  const auth = request.headers.get('authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  // API keys are like ep_live_abc123... — use first 16 chars as identity
  return token ? token.slice(0, 16) : null;
}

export async function middleware(request) {
  const { pathname } = request.nextUrl;

  const category = getCategory(pathname);
  if (!category) return NextResponse.next();

  const ip = getClientIP(request);

  // For write routes with auth, use API key prefix + IP as rate limit key
  // This prevents shared NATs from being over-punished while still
  // throttling per-identity on authenticated writes
  let rateLimitKey = ip;
  if (WRITE_CATEGORIES.includes(category)) {
    const keyPrefix = getApiKeyPrefix(request);
    if (keyPrefix) {
      rateLimitKey = `${keyPrefix}:${ip}`;
    }
  }

  const result = await checkRateLimit(rateLimitKey, category);

  if (!result.allowed) {
    const config = RATE_LIMITS[category];
    const res = NextResponse.json(
      {
        error: 'Rate limit exceeded',
        limit: config.max,
        window_seconds: config.window,
        retry_after: result.reset,
      },
      { status: 429 }
    );
    res.headers.set('X-RateLimit-Limit', String(config.max));
    res.headers.set('X-RateLimit-Remaining', '0');
    res.headers.set('X-RateLimit-Reset', String(result.reset));
    res.headers.set('Retry-After', String(result.reset));
    return res;
  }

  const response = NextResponse.next();
  response.headers.set('X-RateLimit-Limit', String(RATE_LIMITS[category].max));
  response.headers.set('X-RateLimit-Remaining', String(result.remaining));
  response.headers.set('X-RateLimit-Reset', String(result.reset));
  return response;
}

export const config = {
  matcher: '/api/:path*',
};
