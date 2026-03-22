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

/**
 * Canonical EP error response — RFC 7807 Problem Details.
 * Every route MUST use this for error responses.
 */
export function epProblem(status, code, detail, extras = {}) {
  return NextResponse.json({
    type: `https://emiliaprotocol.ai/errors/${code}`,
    title: code.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    status,
    detail,
    ...extras,
  }, { status });
}

// Common errors — now backed by epProblem
export const EP_ERRORS = {
  NOT_FOUND: (what = 'Entity') => epProblem(404, 'not_found', `${what} not found`),
  UNAUTHORIZED: () => epProblem(401, 'unauthorized', 'Missing or invalid API key. Use: Authorization: Bearer ep_live_...'),
  FORBIDDEN: (reason) => epProblem(403, 'forbidden', reason || 'Forbidden'),
  BAD_REQUEST: (reason) => epProblem(400, 'bad_request', reason),
  CONFLICT: (reason, details) => epProblem(409, 'conflict', reason, details ? { details } : {}),
  RATE_LIMITED: () => epProblem(429, 'rate_limited', 'Rate limit exceeded. Try again later.'),
  INTERNAL: () => epProblem(500, 'internal_error', 'Internal server error'),
  GONE: (reason) => epProblem(410, 'gone', reason),
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
  constructor(message, { status = 500, code = 'PROTOCOL_WRITE_FAILED', cause = null } = {}) {
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
  constructor(message, { status = 500, code = 'TRUST_EVALUATION_FAILED', cause = null } = {}) {
    super(message);
    this.name = 'TrustEvaluationError';
    this.status = status;
    this.code = code;
    if (cause) this.cause = cause;
  }
}
