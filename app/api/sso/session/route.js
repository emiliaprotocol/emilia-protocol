// SPDX-License-Identifier: Apache-2.0
// /api/sso/session — the current EP session.
//   GET    → the verified session claims (who is logged in), or 401
//   DELETE → logout: server-side revoke this session's jti + clear the cookie
//   POST   → logout-all-devices: stamp a subject-wide cutoff so every existing
//            session for this identity stops verifying

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import {
  readSessionFromRequest,
  revokeSession,
  revokeAllSessionsForSubject,
  SESSION_COOKIE,
} from '@/lib/sso/session';
import { epProblem } from '@/lib/errors';

export async function GET(request) {
  const session = await readSessionFromRequest(request);
  if (!session) return epProblem(401, 'no_session', 'No valid EP session');
  return Response.json({
    authenticated: true,
    subject: session.sub,
    tenant: session.tenant,
    email: session.email,
    protocol: session.protocol,
    directory: session.directory,
    expires_at: new Date(session.exp * 1000).toISOString(),
  });
}

export async function DELETE(request) {
  // Server-side revoke so the token can't be replayed after logout (it stays
  // signature-valid until exp otherwise). Best-effort: also clear the cookie.
  const session = await readSessionFromRequest(request);
  if (session?.jti) {
    await revokeSession(session.jti, {
      subject: session.sub,
      tenant: session.tenant,
      expiresAt: session.exp ? new Date(session.exp * 1000).toISOString() : null,
    });
  }
  const res = NextResponse.json({ logged_out: true });
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
  return res;
}

export async function POST(request) {
  // Logout-all-devices / compromised-account containment for the CURRENT
  // identity. Requires a valid session (the caller proves they are the subject).
  const session = await readSessionFromRequest(request);
  if (!session) return epProblem(401, 'no_session', 'No valid EP session');
  const ok = await revokeAllSessionsForSubject(session.sub, session.tenant);
  const res = NextResponse.json({ revoked_all: ok, subject: session.sub });
  // Also clear THIS device's cookie.
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
  return res;
}
