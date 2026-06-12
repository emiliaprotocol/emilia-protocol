// SPDX-License-Identifier: Apache-2.0
// /api/sso/session — the current EP session.
//   GET    → the verified session claims (who is logged in), or 401
//   DELETE → logout (clears the session cookie)

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import { readSessionFromRequest, SESSION_COOKIE } from '@/lib/sso/session';
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

export async function DELETE() {
  const res = NextResponse.json({ logged_out: true });
  res.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
  return res;
}
