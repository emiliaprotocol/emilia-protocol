/**
 * Shared guards for the OrcaRouter provider settings API.
 *
 * @license Apache-2.0
 *
 * These endpoints can replace the credential this deployment uses for model
 * inference. Every one of them therefore requires an authenticated internal
 * administrator session, not merely a feature flag; ORCAROUTER_PROVIDER_ADMIN
 * only decides whether the surface exists at all. Mutations additionally
 * require an explicit same-origin Origin header. Responses never include a
 * credential.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getOrcaRouterEnv } from '@/lib/env';
import {
  authenticateTrustDeskReviewer,
  TRUST_DESK_SESSION_COOKIE,
} from '@/lib/trust-desk/auth';

export const MAX_PROVIDER_BODY_BYTES = 64 * 1024;

export function providerAdminDisabled(): NextResponse | null {
  if (getOrcaRouterEnv().settingsSurfaceEnabled) return null;
  return epProblem(404, 'not_found', 'OrcaRouter provider settings are not enabled on this deployment');
}

export interface OrcaRouterAdmin {
  reviewerId: string;
}

export type OrcaRouterAdminGuard =
  | { ok: true; admin: OrcaRouterAdmin }
  | { ok: false; response: NextResponse };

/**
 * Authenticate the caller against the repository's signed internal Trust Desk
 * session. The session cookie carries an HMAC-signed reviewer identity issued
 * by the existing exchange endpoint; the feature flag is not an identity.
 */
export function requireOrcaRouterAdmin(request: NextRequest): OrcaRouterAdminGuard {
  const disabled = providerAdminDisabled();
  if (disabled) return { ok: false, response: disabled };
  const session = authenticateTrustDeskReviewer(
    request.cookies.get(TRUST_DESK_SESSION_COOKIE)?.value,
  );
  if (!session) {
    return {
      ok: false,
      response: epProblem(401, 'unauthorized', 'An authenticated internal administrator session is required'),
    };
  }
  return { ok: true, admin: { reviewerId: session.reviewerId } };
}

/**
 * Same-origin check for mutations. Because these routes are authenticated by a
 * cookie, an absent Origin is not treated as same-origin: require an explicit
 * Origin and match it to the Host. Sec-Fetch-Site, when present, must not say
 * cross-site. This is defence in depth on top of the signed session.
 */
export function crossOriginRefused(request: NextRequest): NextResponse | null {
  const origin = request.headers.get('origin');
  if (!origin) {
    return epProblem(403, 'origin_required', 'OrcaRouter provider changes require an explicit Origin header');
  }
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return epProblem(403, 'cross_origin_denied', 'Malformed Origin header');
  }
  const host = request.headers.get('host');
  if (!host || parsed.host !== host) {
    return epProblem(403, 'cross_origin_denied', 'OrcaRouter provider changes require a same-origin request');
  }
  const site = request.headers.get('sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'same-site' && site !== 'none') {
    return epProblem(403, 'cross_origin_denied', 'Cross-site provider changes are refused');
  }
  return null;
}

export async function readJsonBody(
  request: NextRequest,
): Promise<{ ok: true; value: any } | { ok: false; response: NextResponse }> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return { ok: false, response: epProblem(415, 'unsupported_media_type', 'Expected an application/json body') };
  }
  const declared = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(declared) && declared > MAX_PROVIDER_BODY_BYTES) {
    return { ok: false, response: epProblem(413, 'body_too_large', 'Request body is too large') };
  }
  let text: string;
  try {
    text = await request.text();
  } catch {
    return { ok: false, response: epProblem(400, 'invalid_body', 'Request body could not be read') };
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_PROVIDER_BODY_BYTES) {
    return { ok: false, response: epProblem(413, 'body_too_large', 'Request body is too large') };
  }
  try {
    const value = text ? JSON.parse(text) : {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ok: false, response: epProblem(400, 'invalid_body', 'Request body must be a JSON object') };
    }
    return { ok: true, value };
  } catch {
    return { ok: false, response: epProblem(400, 'invalid_body', 'Request body must be valid JSON') };
  }
}

export const NO_STORE = { 'Cache-Control': 'no-store' };
