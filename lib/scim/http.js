/**
 * SCIM HTTP helpers — JSON responses with the SCIM media type and auth gate.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { authenticateScim } from './auth.js';
import { scimError } from './core.js';

const SCIM_CONTENT_TYPE = 'application/scim+json';

/** A SCIM JSON response with the correct content type + optional ETag. */
export function scimJson(body, { status = 200, etag } = {}) {
  const headers = { 'Content-Type': SCIM_CONTENT_TYPE };
  if (etag) headers.ETag = etag;
  return NextResponse.json(body, { status, headers });
}

/** A SCIM error response (RFC 7644 §3.12). */
export function scimErrorResponse(status, detail, scimType) {
  return scimJson(scimError(status, detail, scimType), { status });
}

/**
 * Resolve SCIM auth or return a ready 401/503 response.
 * @returns {Promise<{ tenantId: string } | { response: NextResponse }>}
 */
export async function requireScimAuth(request) {
  const auth = await authenticateScim(request);
  if (auth.error) {
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
