// SPDX-License-Identifier: Apache-2.0
import type { NextResponse } from 'next/server';

import {
  AgentAdoptionServiceError,
  authorizeAgentAdoptionSession,
} from '@/lib/agent-adoption/service';

const COOKIE_NAME = '__Secure-emilia-adoption-session';
const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_TOKEN = /^eaa1_[0-9a-f]{64}$/;

function cookieValue(headers: Headers, name: string): string | null {
  const raw = headers.get('cookie');
  if (!raw) return null;
  for (const item of raw.split(';')) {
    const [key, ...value] = item.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return null;
}

function recoveredAuthorization(
  request: Pick<Request, 'headers' | 'method' | 'url'>,
  sessionId: string,
) {
  if (request.headers.get('authorization')) return request;
  const value = cookieValue(request.headers, COOKIE_NAME);
  if (!value) return request;
  if (request.method.toUpperCase() !== 'GET') {
    let expectedOrigin = '';
    try {
      expectedOrigin = new URL(request.url).origin;
    } catch {
      expectedOrigin = '';
    }
    if (!expectedOrigin || request.headers.get('origin') !== expectedOrigin) {
      throw new AgentAdoptionServiceError(
        401,
        'agent_adoption_cookie_origin_denied',
        'Recovered Agent Adoption mutations require an exact same-origin request.',
      );
    }
  }
  const separator = value.indexOf('.');
  const cookieSessionId = value.slice(0, separator);
  const sessionToken = value.slice(separator + 1);
  if (separator < 1
      || cookieSessionId !== sessionId
      || !SESSION_ID.test(cookieSessionId)
      || !SESSION_TOKEN.test(sessionToken)) {
    return request;
  }
  const headers = new Headers(request.headers);
  headers.set('authorization', `Bearer ${sessionToken}`);
  return { headers };
}

export function authorizeAgentAdoptionRequest({
  request,
  sessionId,
}: {
  request: Pick<Request, 'headers' | 'method' | 'url'>;
  sessionId: string;
}) {
  return authorizeAgentAdoptionSession({
    request: recoveredAuthorization(request, sessionId),
    sessionId,
  });
}

export function setAgentAdoptionSessionCookie(
  response: NextResponse,
  session: { session_id: string; session_token: string; expires_at: string },
) {
  if (!SESSION_ID.test(session.session_id) || !SESSION_TOKEN.test(session.session_token)) return;
  const expiresAt = Date.parse(session.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return;
  response.cookies.set({
    name: COOKIE_NAME,
    value: `${session.session_id}.${session.session_token}`,
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/api/adopt/',
    expires: new Date(expiresAt),
  });
}

export function clearAgentAdoptionSessionCookie(response: NextResponse) {
  response.cookies.set({
    name: COOKIE_NAME,
    value: '',
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/api/adopt/',
    expires: new Date(0),
    maxAge: 0,
  });
}
