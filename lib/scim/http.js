/**
 * SCIM HTTP helpers — JSON responses with the SCIM media type and auth gate.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { authenticateScim } from './auth.js';
import { scimError } from './core.js';
import { readLimitedJson } from '../http/body-limit.js';

const SCIM_CONTENT_TYPE = 'application/scim+json';
const DEFAULT_SCIM_BODY_LIMIT_BYTES = 1024 * 1024;

/**
 * A SCIM JSON response with the correct content type + optional ETag.
 * @param {any} body
 * @param {{ status?: number, etag?: string }} [options]
 */
export function scimJson(body, { status = 200, etag } = {}) {
  const headers = { 'Content-Type': SCIM_CONTENT_TYPE };
  if (etag) headers.ETag = etag;
  return NextResponse.json(body, { status, headers });
}

/** A SCIM error response (RFC 7644 §3.12). */
export function scimErrorResponse(status, detail, scimType) {
  return scimJson(scimError(status, detail, scimType), { status });
}

export async function readScimJson(request, maxBytes = DEFAULT_SCIM_BODY_LIMIT_BYTES) {
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

/**
 * Resolve SCIM auth or return a ready 401/503 response.
 * @returns {Promise<{ tenantId: string, organizationId?: string, tokenId: string } | { response: NextResponse }>}
 */
export async function requireScimAuth(request) {
  const auth = /** @type {{ tenantId: string, organizationId?: string, tokenId: string } | { error: string, status: number }} */ (
    await authenticateScim(request)
  );
  if ('error' in auth) {
    return { response: scimErrorResponse(auth.status, auth.error) };
  }
  return { tenantId: auth.tenantId, organizationId: auth.organizationId, tokenId: auth.tokenId };
}

/** Base URL for `meta.location` links. */
export function scimBaseUrl(request) {
  try {
    const url = new URL(request.url);
    return `${url.protocol}//${url.host}/api/scim/v2`;
  } catch {
    return '/api/scim/v2';
  }
}
