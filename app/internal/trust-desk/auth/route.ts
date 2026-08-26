/**
 * Trust Desk reviewer bootstrap exchange.
 *
 * GET renders a no-store password form at a clean URL. POST accepts the
 * one-time bootstrap secret only in a bounded same-origin form body, consumes
 * it atomically, and exchanges it for an httpOnly reviewer session. Query
 * credentials are never parsed or accepted.
 *
 * @license Apache-2.0
 */

import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import {
  consumeTrustDeskBootstrap,
  issueTrustDeskSession,
  TRUST_DESK_SESSION_COOKIE,
} from '@/lib/trust-desk/auth';
import { readLimitedText } from '@/lib/http/body-limit';
import { getTrustDeskAuthConfig } from '@/lib/env';

export const dynamic = 'force-dynamic';

const MAX_BOOTSTRAP_BODY_BYTES = 4 * 1024;
const FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded';

const SIGN_IN_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Trust Desk reviewer sign-in</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f5f4; color: #1c1917; }
    main { width: min(92vw, 28rem); box-sizing: border-box; padding: 2rem; border: 1px solid #d6d3d1; border-radius: 0.75rem; background: #fff; }
    h1 { margin: 0 0 0.75rem; font-size: 1.4rem; }
    p { margin: 0 0 1.25rem; color: #57534e; line-height: 1.5; }
    label { display: block; margin-bottom: 0.45rem; font-weight: 650; }
    input { width: 100%; box-sizing: border-box; padding: 0.75rem; border: 1px solid #a8a29e; border-radius: 0.4rem; font: inherit; }
    button { width: 100%; margin-top: 1rem; padding: 0.75rem; border: 0; border-radius: 0.4rem; background: #1c1917; color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
  </style>
</head>
<body>
  <main>
    <h1>Trust Desk reviewer sign-in</h1>
    <p>Enter the one-time reviewer bootstrap secret. It is submitted in the request body and is never placed in the URL.</p>
    <form method="post" action="/internal/trust-desk/auth" autocomplete="off">
      <label for="bootstrap_token">Bootstrap secret</label>
      <input id="bootstrap_token" name="bootstrap_token" type="password" required maxlength="2048" autocomplete="one-time-code">
      <button type="submit">Open reviewer queue</button>
    </form>
  </main>
</body>
</html>`;

export async function GET(request: NextRequest): Promise<Response> {
  const url = new URL(request.url);
  if (url.search) {
    url.search = '';
    url.hash = '';
    return harden(NextResponse.redirect(url, 303));
  }

  return harden(new NextResponse(SIGN_IN_HTML, {
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  }));
}

export async function POST(request: NextRequest): Promise<Response> {
  const expected = getTrustDeskAuthConfig().bootstrapToken;
  if (!expected) {
    return problem(503, 'Trust Desk reviewer access is not configured');
  }

  if (!isSameOrigin(request)) {
    return problem(403, 'Cross-origin bootstrap submission refused');
  }

  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== FORM_CONTENT_TYPE) {
    return problem(415, 'Bootstrap requires a form-encoded request body');
  }

  const read = await readLimitedText(request, MAX_BOOTSTRAP_BODY_BYTES);
  if (!read.ok) {
    return problem(read.status, read.detail);
  }

  const form = new URLSearchParams(read.text);
  const tokens = form.getAll('bootstrap_token');
  const hasUnexpectedField = Array.from(form.keys()).some((key) => key !== 'bootstrap_token');
  if (tokens.length !== 1 || hasUnexpectedField || !timingSafeEqual(tokens[0], expected)) {
    return problem(401, 'Invalid bootstrap credentials');
  }

  const session = issueTrustDeskSession();
  if (!session) {
    return problem(503, 'Trust Desk reviewer identity is not configured');
  }

  const bootstrap = await consumeTrustDeskBootstrap(tokens[0]);
  if (!bootstrap.ok) {
    if (bootstrap.reason === 'bootstrap_replayed') {
      return problem(401, 'Bootstrap secret already used; rotate TRUST_DESK_INTERNAL_TOKEN');
    }
    return problem(503, 'Trust Desk bootstrap store unavailable');
  }

  const res = NextResponse.redirect(new URL('/internal/trust-desk', request.url), 303);
  res.cookies.set(TRUST_DESK_SESSION_COOKIE, session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    // The same host-only session authenticates the dashboard and its review
    // API. Scope it to this host, not only the dashboard path.
    path: '/',
    maxAge: 60 * 60 * 8,
  });
  return harden(res);
}

function isSameOrigin(request: NextRequest): boolean {
  const suppliedOrigin = request.headers.get('origin');
  if (!suppliedOrigin) return false;
  try {
    return new URL(suppliedOrigin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // Compare equal-length data on the mismatch path to avoid an early exit.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function problem(status: number, error: string): Response {
  return harden(NextResponse.json({ error }, { status }));
}

function harden<T extends Response>(response: T): T {
  response.headers.set('Cache-Control', 'no-store, max-age=0');
  response.headers.set('Pragma', 'no-cache');
  response.headers.set('Referrer-Policy', 'no-referrer');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return response;
}
