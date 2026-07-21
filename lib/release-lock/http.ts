// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import {
  CloudAuthorizationError,
  requirePermission,
} from '../cloud/authorize.js';
import { epProblem } from '../errors.js';
import { readLimitedJson } from '../http/body-limit.js';
import { authenticateRequest, authEntityId, type AuthResult } from '../supabase.js';
import { resolveAuthorizedOrg } from '../tenant-binding.js';
import {
  RELEASE_LOCK_COOKIE,
  RELEASE_LOCK_ID_PATTERN,
  RELEASE_LOCK_MAX_BODY_BYTES,
} from './constants.js';
import {
  isReleaseLockError,
  releaseLockRefusal,
} from './errors.js';
import { validRawToken } from './crypto.js';

export function protectReleaseLockResponse(response: NextResponse): NextResponse {
  response.headers.set('cache-control', 'no-store');
  response.headers.set('pragma', 'no-cache');
  response.headers.set('referrer-policy', 'no-referrer');
  response.headers.set('x-content-type-options', 'nosniff');
  return response;
}

export function releaseLockJson(value: unknown, status: number = 200): NextResponse {
  return protectReleaseLockResponse(NextResponse.json(value, { status }));
}

export function releaseLockProblem(error: unknown): NextResponse {
  if (isReleaseLockError(error)) {
    return protectReleaseLockResponse(epProblem(
      error.status,
      error.code,
      error.expose
        ? error.detail
        : 'The Release Lock service is temporarily unavailable.',
    ));
  }
  return protectReleaseLockResponse(epProblem(
    500,
    'release_lock_internal_error',
    'The Release Lock request failed due to a server-side error.',
  ));
}

export async function readReleaseLockJson(request: Request): Promise<Record<string, unknown>> {
  const parsed = await readLimitedJson(request, RELEASE_LOCK_MAX_BODY_BYTES);
  if (!parsed.ok) {
    throw releaseLockRefusal(parsed.status, parsed.code, parsed.detail);
  }
  if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) {
    throw releaseLockRefusal(400, 'invalid_request', 'Request body must be a JSON object.');
  }
  return parsed.value;
}

export function releaseLockId(value: unknown): string {
  if (typeof value !== 'string' || !RELEASE_LOCK_ID_PATTERN.test(value)) {
    throw releaseLockRefusal(400, 'invalid_release_lock_id', 'Release Lock identifier is invalid.');
  }
  return value;
}

export function releaseLockRound(value: unknown): 'CO_ACCEPTED' | 'DRAW_RELEASE' {
  if (value === 'co-accepted' || value === 'CO_ACCEPTED') return 'CO_ACCEPTED';
  if (value === 'draw-release' || value === 'DRAW_RELEASE') return 'DRAW_RELEASE';
  throw releaseLockRefusal(400, 'invalid_release_lock_round', 'Release Lock round is invalid.');
}

export function requireReleaseLockSameOrigin(request: Request): void {
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  let requestOrigin: string;
  let presentedOrigin: string;
  try {
    requestOrigin = new URL(request.url).origin;
    presentedOrigin = new URL(origin as string).origin;
  } catch {
    throw releaseLockRefusal(
      403,
      'release_lock_origin_denied',
      'Release Lock browser mutations require a same-origin request.',
    );
  }
  if (presentedOrigin !== requestOrigin
      || (fetchSite && fetchSite !== 'same-origin')) {
    throw releaseLockRefusal(
      403,
      'release_lock_origin_denied',
      'Release Lock browser mutations require a same-origin request.',
    );
  }
}

export function releaseLockCookieName(lockId: string): string {
  return `${RELEASE_LOCK_COOKIE}_${releaseLockId(lockId)}`;
}

export function releaseLockSessionCookie(request: Request, lockId: string): string {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method.toUpperCase())) {
    requireReleaseLockSameOrigin(request);
  }
  const cookieName = releaseLockCookieName(lockId);
  const header = request.headers.get('cookie') || '';
  const matches = header.split(';').map((part) => part.trim()).filter(
    (part) => {
      const separator = part.indexOf('=');
      return separator > 0 && part.slice(0, separator) === cookieName;
    },
  );
  if (matches.length !== 1) {
    throw releaseLockRefusal(401, 'session_invalid', 'Release Lock session is invalid.');
  }
  const value = matches[0].slice(cookieName.length + 1);
  if (!validRawToken(value)) {
    throw releaseLockRefusal(401, 'session_invalid', 'Release Lock session is invalid.');
  }
  return value;
}

export function setReleaseLockSessionCookie(
  response: NextResponse,
  token: string,
  expiresAt: string | number | Date,
  lockId: string,
): NextResponse {
  if (!validRawToken(token)) throw new Error('Release Lock session token is invalid');
  response.cookies.set(releaseLockCookieName(lockId), token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    expires: new Date(expiresAt),
  });
  return response;
}

export interface AuthenticateReleaseLockOrgOptions {
  requiredPermission?: 'read' | 'write' | 'admin';
}

export interface AuthenticatedReleaseLockCaller {
  auth: AuthResult;
  organizationId: string;
  entityId: string;
}

export async function authenticateReleaseLockOrg(
  request: Request,
  bodyOrganizationId?: string,
  { requiredPermission = 'read' }: AuthenticateReleaseLockOrgOptions = {},
): Promise<AuthenticatedReleaseLockCaller> {
  const auth = await authenticateRequest(request);
  if (auth.error) {
    throw releaseLockRefusal(
      auth.status || 401,
      auth.code || 'unauthorized',
      auth.error,
    );
  }
  try {
    // requirePermission() only reads .permissions at runtime; its JSDoc type
    // is written for the cloud control-plane auth context, which AuthResult
    // structurally isn't (see lib/tenant-binding.ts and
    // app/api/v1/grace/curtailment/actions/route.ts for the same cast).
    requirePermission(auth as unknown as { tenantId: string; environment: string; permissions: string[] }, requiredPermission);
  } catch (error) {
    if (error instanceof CloudAuthorizationError) {
      throw releaseLockRefusal(
        403,
        'insufficient_permissions',
        `Release Lock requires ${requiredPermission} permission.`,
      );
    }
    throw error;
  }
  const resolved = resolveAuthorizedOrg(auth, bodyOrganizationId, { requireBound: true });
  if (resolved.error) {
    throw releaseLockRefusal(
      resolved.error.status,
      resolved.error.code,
      resolved.error.detail,
    );
  }
  const entityId = authEntityId(auth);
  if (!entityId) {
    throw releaseLockRefusal(403, 'authenticated_entity_invalid', 'Authenticated entity is invalid.');
  }
  return Object.freeze({
    auth,
    // resolveAuthorizedOrg() always sets organizationId when error is absent
    // (see lib/tenant-binding.ts); the compiler can't see that invariant
    // across the non-discriminated return shape.
    organizationId: resolved.organizationId as string,
    entityId,
  });
}
