import { NextResponse } from 'next/server';
import { checkRateLimit, getClientIP, RATE_LIMITS } from '@/lib/rate-limit';

/**
 * EMILIA Protocol — API Rate Limiting Middleware
 *
 * Applies per-IP rate limits to all /api/* routes.
 * Categories:
 *   - register:  /api/entities/register
 *   - submit:    /api/receipts/submit
 *   - anchor:    /api/blockchain/anchor
 *   - waitlist:  /api/waitlist
 *   - read:      everything else under /api/
 */

function getCategory(pathname) {
  if (pathname.startsWith('/api/entities/register')) return 'register';
  if (pathname.startsWith('/api/receipts/submit')) return 'submit';
  if (pathname.startsWith('/api/blockchain/anchor')) return 'anchor';
  if (pathname.startsWith('/api/waitlist')) return 'waitlist';
  if (pathname.startsWith('/api/')) return 'read';
  return null;
}

export async function middleware(request) {
  const { pathname } = request.nextUrl;

  // Only rate-limit API routes
  const category = getCategory(pathname);
  if (!category) return NextResponse.next();

  const ip = getClientIP(request);
  const result = await checkRateLimit(ip, category);

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
