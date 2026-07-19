/**
 * GET /internal/trust-desk/auth?token=...
 *
 * @license Apache-2.0
 *
 * Minimal cookie-based gate for the internal reviewer dashboard. Validates the
 * supplied token (timing-safe) against TRUST_DESK_INTERNAL_TOKEN and, on match,
 * sets an httpOnly, SameSite=Strict cookie, then redirects to the dashboard.
 *
 * This is an internal-ops gate, not end-user auth — it keeps the dashboard
 * (which shows customer company names + escalation reasons) off the open web.
 * For multi-operator access, put this route behind your IdP instead.
 */

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import {
  consumeTrustDeskBootstrap,
  issueTrustDeskSession,
  TRUST_DESK_SESSION_COOKIE,
} from '@/lib/trust-desk/auth';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  const expected = process.env.TRUST_DESK_INTERNAL_TOKEN;
  const url = new URL(request.url);
  const provided = url.searchParams.get('token') || '';

  if (!expected) {
    return NextResponse.json(
      { error: 'TRUST_DESK_INTERNAL_TOKEN is not configured on the server' },
      { status: 503 },
    );
  }
  if (!timingSafeEqual(provided, expected)) {
    return NextResponse.json({ error: 'invalid token' }, { status: 401 });
  }

  const bootstrap = await consumeTrustDeskBootstrap(provided);
  if (!bootstrap.ok) {
    if (bootstrap.reason === 'bootstrap_replayed') {
      return NextResponse.json({ error: 'bootstrap token already used; rotate TRUST_DESK_INTERNAL_TOKEN' }, { status: 401 });
    }
    return NextResponse.json({ error: 'trust desk bootstrap store unavailable' }, { status: 503 });
  }

  const session = issueTrustDeskSession();
  const res = NextResponse.redirect(new URL('/internal/trust-desk', request.url));
  res.headers.set('Referrer-Policy', 'no-referrer');
  res.cookies.set(TRUST_DESK_SESSION_COOKIE, session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/internal/trust-desk',
    maxAge: 60 * 60 * 8, // 8 hours
  });
  return res;
}

/** Constant-time string compare that tolerates length differences. */
function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // Still do a comparison to avoid early-exit timing leak.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}
