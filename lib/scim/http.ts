/**
 * SCIM HTTP helpers — JSON responses with the SCIM media type and auth gate.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { authenticateScim, type ScimAuthSuccess } from './auth.js';
import { scimError } from './core.js';
import { readLimitedJson } from '../http/body-limit.js';

const SCIM_CONTENT_TYPE = 'application/scim+json';
const DEFAULT_SCIM_BODY_LIMIT_BYTES = 1024 * 1024;

export interface ScimJsonOptions {
  status?: number;
  etag?: string;
}

/** A SCIM JSON response with the correct content type + optional ETag. */
export function scimJson(body: unknown, { status = 200, etag }: ScimJsonOptions = {}): NextResponse {
  const headers: Record<string, string> = { 'Content-Type': SCIM_CONTENT_TYPE };
  if (etag) headers.ETag = etag;
  return NextResponse.json(body, { status, headers });
}

/** A SCIM error response (RFC 7644 §3.12). */
export function scimErrorResponse(status: number, detail: string, scimType?: string): NextResponse {
  return scimJson(scimError(status, detail, scimType), { status });
}

export type ReadScimJsonResult =
  | { ok: true; value: any }
  | { ok: false; response: NextResponse };

export async function readScimJson(
  request: Request,
  maxBytes: number = DEFAULT_SCIM_BODY_LIMIT_BYTES,
): Promise<ReadScimJsonResult> {
  const parsed = await readLimitedJson(request, maxBytes);
  if (!parsed.ok) {
    return {
      ok: false,
      response: scimErrorResponse(
        parsed.status,
        parsed.detail,
        parsed.code === 'invalid_json' ? 'invalidSyntax' : undefined,
      ),
    };
  }
  return { ok: true, value: parsed.value };
}

export type RequireScimAuthResult = ScimAuthSuccess | { response: NextResponse };

/** Resolve SCIM auth or return a ready 401/503 response. */
export async function requireScimAuth(request: Request): Promise<RequireScimAuthResult> {
  const auth = await authenticateScim(request);
  if ('error' in auth) {
    return { response: scimErrorResponse(auth.status, auth.error) };
  }
  return { tenantId: auth.tenantId, organizationId: auth.organizationId, tokenId: auth.tokenId };
}

/** Base URL for `meta.location` links. */
export function scimBaseUrl(request: Request): string {
  try {
    const url = new URL(request.url);
    return `${url.protocol}//${url.host}/api/scim/v2`;
  } catch {
    return '/api/scim/v2';
  }
}
