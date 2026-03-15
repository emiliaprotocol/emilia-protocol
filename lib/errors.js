/**
 * EP Standardized Error Responses
 * 
 * Every API route should use these instead of ad-hoc error JSON.
 * Consistent shape means clients can parse errors reliably.
 * 
 * Shape: { error: string, code: string, status: number, details?: any }
 * 
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';

export function epError(message, code, status, details = null) {
  const body = { error: message, code, status };
  if (details) body.details = details;
  return NextResponse.json(body, { status });
}

// Common errors
export const EP_ERRORS = {
  NOT_FOUND: (what = 'Entity') => epError(`${what} not found`, 'NOT_FOUND', 404),
  UNAUTHORIZED: () => epError('Missing or invalid API key. Use: Authorization: Bearer ep_live_...', 'UNAUTHORIZED', 401),
  FORBIDDEN: (reason) => epError(reason || 'Forbidden', 'FORBIDDEN', 403),
  BAD_REQUEST: (reason) => epError(reason, 'BAD_REQUEST', 400),
  CONFLICT: (reason, details) => epError(reason, 'CONFLICT', 409, details),
  RATE_LIMITED: () => epError('Rate limit exceeded. Try again later.', 'RATE_LIMITED', 429),
  INTERNAL: () => epError('Internal server error', 'INTERNAL_ERROR', 500),
  GONE: (reason) => epError(reason, 'GONE', 410),
};
