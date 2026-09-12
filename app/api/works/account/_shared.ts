// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { AccountServiceError, type WorksSessionActor } from '@/lib/works/account-service';
import { isWorksV0Enabled } from '@/lib/works/env';
import { assertWorksSameOrigin, WorksSessionUnavailableError } from '@/lib/works/session';

export const ACCOUNT_BODY_BYTES = 4096;
export const ACCOUNT_HEADERS = Object.freeze({
  'cache-control': 'private, no-store, max-age=0',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  vary: 'Cookie',
});

export function accountEnabled(): boolean {
  return isWorksV0Enabled();
}

export function accountNotFound(): NextResponse {
  return accountPrivate(epProblem(404, 'not_found', 'Not found'));
}

export function accountPrivate(response: NextResponse): NextResponse {
  for (const [name, value] of Object.entries(ACCOUNT_HEADERS)) response.headers.set(name, value);
  return response;
}

export function accountMutationAllowed(request: Request): NextResponse | null {
  if (!assertWorksSameOrigin(request)) {
    return accountPrivate(epProblem(403, 'account_origin_refused', 'This account request did not come from the configured Works site.'));
  }
  if (!/^application\/json(?:\s*;|\s*$)/i.test(request.headers.get('content-type') || '')) {
    return accountPrivate(epProblem(415, 'json_required', 'Send this account request as JSON.'));
  }
  return null;
}

export function publicAccount(actor: WorksSessionActor) {
  return {
    displayName: actor.displayName,
    claimsVerified: false as const,
    emailNotifications: actor.emailNotifications,
  };
}

export function accountJson(value: unknown, status = 200): NextResponse {
  return NextResponse.json(value, { status, headers: ACCOUNT_HEADERS });
}

export function accountObject(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null
    ? value as Record<string, unknown>
    : null;
}

export function accountInvalidBody(): NextResponse {
  return accountPrivate(epProblem(400, 'account_request_invalid', 'Send one account request object.'));
}

export function accountFailure(error: unknown): NextResponse {
  if (error instanceof AccountServiceError) {
    return accountPrivate(epProblem(error.status, error.code, error.message));
  }
  if (error instanceof WorksSessionUnavailableError) {
    return accountPrivate(epProblem(503, 'account_service_unavailable', 'Account sign-in is unavailable.'));
  }
  return accountPrivate(epProblem(503, 'account_service_unavailable', 'Account sign-in is unavailable.'));
}

export function accountSecret(): string {
  return process.env.WORKS_ACCOUNT_HMAC_SECRET || '';
}
