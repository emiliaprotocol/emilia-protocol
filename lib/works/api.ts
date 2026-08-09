// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — shared API-route plumbing.
//
// Keeps the /api/works/* route files thin: feature-flag gating (404 when
// WORKS_V0 is off, so the surface is indistinguishable from absent), cloud
// API-key authentication for create/edit (the same authenticateCloudRequest
// gate the cloud control plane uses), and a single mapping from typed store
// error codes to RFC 7807 problem responses.

import { NextResponse } from 'next/server';
import { epProblem } from '../errors.js';
import { isWorksV0Enabled } from './env.js';
import type { StoreError } from './store.js';

/** 404 problem used whenever the flag is off — never reveals the surface. */
export function worksDisabledProblem(): NextResponse {
  return epProblem(404, 'not_found', 'Not found');
}

export function worksEnabled(): boolean {
  return isWorksV0Enabled();
}

// Store/model error code -> HTTP status. Anything unmapped is a 400
// validation problem: unknown failure shapes fail closed as client errors
// with a typed body, never as unhandled throws.
const CODE_STATUS: Record<string, number> = {
  invalid_collection: 404,
  not_found: 404,
  forbidden_not_owner: 403,
  seed_immutable: 403,
  already_exists: 409,
  owner_required: 401,
  store_unavailable: 503,
};

export function worksProblem(error: StoreError): NextResponse {
  const status = CODE_STATUS[error.code] ?? 400;
  return epProblem(status, error.code, error.detail);
}

export function worksUnauthorized(): NextResponse {
  return epProblem(401, 'unauthorized', 'A valid Cloud API key is required');
}

/** Response headers for Works reads: public directory data, never cached. */
export const WORKS_READ_HEADERS = { 'cache-control': 'no-store' };
