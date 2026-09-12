// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';
import { epProblem } from '../errors.js';
import type { WorksWorkflowError } from './workflow-store.js';

const STATUS: Record<string, number> = {
  invalid_actor: 401,
  forbidden: 403,
  not_found: 404,
  revision_conflict: 409,
  idempotency_conflict: 409,
  invalid_transition: 409,
  store_unavailable: 503,
  store_invalid: 503,
};

export const WORKS_PRIVATE_HEADERS = Object.freeze({
  'cache-control': 'private, no-store',
  vary: 'Authorization, Cookie',
});

export function worksWorkflowProblem(error: WorksWorkflowError): NextResponse {
  return epProblem(STATUS[error.code] ?? 400, error.code, error.detail);
}

export function privateWorksResponse(response: NextResponse): NextResponse {
  for (const [name, value] of Object.entries(WORKS_PRIVATE_HEADERS)) response.headers.set(name, value);
  return response;
}
