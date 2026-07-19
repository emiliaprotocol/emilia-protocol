// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import {
  CloudAuthorizationError,
  requirePermission,
} from '../cloud/authorize.js';
import { epProblem } from '../errors.js';
import { readLimitedJson } from '../http/body-limit.js';
import { authenticateRequest, authEntityId } from '../supabase.js';
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

export function protectReleaseLockResponse(response) {
  response.headers.set('cache-control', 'no-store');
  response.headers.set('pragma', 'no-cache');
  response.headers.set('referrer-policy', 'no-referrer');
  response.headers.set('x-content-type-options', 'nosniff');
  return response;
}

export function releaseLockJson(value, status = 200) {
  return protectReleaseLockResponse(NextResponse.json(value, { status }));
}

export function releaseLockProblem(error) {
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

export async function readReleaseLockJson(request) {
  const parsed = await readLimitedJson(request, RELEASE_LOCK_MAX_BODY_BYTES);
  if (!parsed.ok) {
    throw releaseLockRefusal(parsed.status, parsed.code, parsed.detail);
  }
  if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) {
    throw releaseLockRefusal(400, 'invalid_request', 'Request body must be a JSON object.');
  }
  return parsed.value;
}

export function releaseLockId(value) {
  if (typeof value !== 'string' || !RELEASE_LOCK_ID_PATTERN.test(value)) {
    throw releaseLockRefusal(400, 'invalid_release_lock_id', 'Release Lock identifier is invalid.');
  }
  return value;
}

export function releaseLockRound(value) {
  if (value === 'co-accepted' || value === 'CO_ACCEPTED') return 'CO_ACCEPTED';
  if (value === 'draw-release' || value === 'DRAW_RELEASE') return 'DRAW_RELEASE';
  throw releaseLockRefusal(400, 'invalid_release_lock_round', 'Release Lock round is invalid.');
}

export function requireReleaseLockSameOrigin(request) {
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  let requestOrigin;
  let presentedOrigin;
  try {
    requestOrigin = new URL(request.url).origin;
    presentedOrigin = new URL(origin).origin;
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

export function releaseLockCookieName(lockId) {
  return `${RELEASE_LOCK_COOKIE}_${releaseLockId(lockId)}`;
}

export function releaseLockSessionCookie(request, lockId) {
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

export function setReleaseLockSessionCookie(response, token, expiresAt, lockId) {
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

export async function authenticateReleaseLockOrg(
  request,
  bodyOrganizationId,
  { requiredPermission = 'read' } = {},
) {
  const auth = await authenticateRequest(request);
  if (auth.error) {
    throw releaseLockRefusal(
      auth.status || 401,
      auth.code || 'unauthorized',
      auth.error,
    );
  }
  try {
    requirePermission(auth, requiredPermission);
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
    organizationId: resolved.organizationId,
    entityId,
  });
}
