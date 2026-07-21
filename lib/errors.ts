/**
 * EP Standardized Error Responses
 *
 * Every API route should use these instead of ad-hoc error JSON.
 * Consistent shape means clients can parse errors reliably.
 *
 * Shape (RFC 7807 Problem Details):
 *   { type: string, title: string, status: number, detail: string, ...extras }
 *
 * Backward compatibility:
 *   The response still carries `status` (number) and human-readable `detail`,
 *   matching the fields clients already rely on. The RFC 7807 envelope adds
 *   `type` and `title` without breaking existing integrations.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { logger } from './logger.js';

/**
 * Canonical EP error response — RFC 7807 Problem Details.
 * Every route MUST use this for error responses.
 */
export function epProblem(
  status: number,
  code: string,
  detail?: string | null,
  extras: Record<string, unknown> = {},
): NextResponse {
  return NextResponse.json({
    type: `https://emiliaprotocol.ai/errors/${code}`,
    title: code.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    status,
    detail,
    ...extras,
  }, { status });
}

/**
 * Error response for a failed datastore operation.
 *
 * The raw error (e.g. a Postgres/PostgREST error, which can carry table names,
 * column names, constraint identifiers, and internal SQL detail) is logged
 * server-side ONLY. The client receives a stable, opaque code + generic detail
 * — never the underlying `error.message`. Echoing raw DB errors is an
 * information-disclosure vector (LOW audit finding); this closes it in one
 * reviewed place so every read/query route scrubs identically.
 *
 * @param status HTTP status (typically 500)
 * @param code stable machine code (e.g. 'audit_query_failed')
 * @param error the raw error object to log (NOT returned to the client)
 * @param logContext a route/operation tag for the server log line
 */
export function epDbError(
  status: number,
  code: string,
  error: unknown,
  logContext?: string | null,
): NextResponse {
  const err = error as { message?: string; detail?: string; code?: string } | null | undefined;
  logger.error(`[${logContext || code}] datastore error`, {
    code,
    message: err?.message ?? String(error),
    detail: err?.detail ?? null,
    dbCode: err?.code ?? null,
  });
  return epProblem(status, code, 'The request could not be completed due to a server-side error.');
}

// Common errors — now backed by epProblem
export const EP_ERRORS = {
  NOT_FOUND: (what = 'Entity'): NextResponse => epProblem(404, 'not_found', `${what} not found`),
  UNAUTHORIZED: (): NextResponse => epProblem(401, 'unauthorized', 'Missing or invalid API key. Provide a valid key in the Authorization header. See the API reference for details.'),
  FORBIDDEN: (reason?: string | null): NextResponse => epProblem(403, 'forbidden', reason || 'Forbidden'),
  BAD_REQUEST: (reason?: string | null): NextResponse => epProblem(400, 'bad_request', reason),
  CONFLICT: (reason?: string | null, details?: unknown): NextResponse => epProblem(409, 'conflict', reason, details ? { details } : {}),
  RATE_LIMITED: (): NextResponse => epProblem(429, 'rate_limited', 'Rate limit exceeded. Try again later.'),
  INTERNAL: (): NextResponse => epProblem(500, 'internal_error', 'Internal server error'),
  GONE: (reason?: string | null): NextResponse => epProblem(410, 'gone', reason),
};

// ── Trust-critical error classes ─────────────────────────────────────────────
// These are thrown (not returned) when trust-bearing operations fail.
// Trust-critical paths MUST fail closed — never degrade gracefully.

/**
 * Thrown when a trust-bearing write operation fails.
 * Covers: receipt creation, commit storage, dispute filing/resolution,
 * trust profile materialization, delegation creation.
 */
export class ProtocolWriteError extends Error {
  status: number;
  code: string;

  constructor(
    message: string,
    { status = 500, code = 'PROTOCOL_WRITE_FAILED', cause = null }: { status?: number; code?: string; cause?: unknown } = {},
  ) {
    super(message);
    this.name = 'ProtocolWriteError';
    this.status = status;
    this.code = code;
    if (cause) this.cause = cause;
  }
}

/**
 * Thrown when a canonical trust evaluation fails in a context where
 * it must not be skipped (e.g. commit issuance, policy gating).
 * Covers: establishment lookup failure, score recomputation failure,
 * continuity lookup failure when trust decision depends on it.
 */
export class TrustEvaluationError extends Error {
  status: number;
  code: string;

  constructor(
    message: string,
    { status = 500, code = 'TRUST_EVALUATION_FAILED', cause = null }: { status?: number; code?: string; cause?: unknown } = {},
  ) {
    super(message);
    this.name = 'TrustEvaluationError';
    this.status = status;
    this.code = code;
    if (cause) this.cause = cause;
  }
}
