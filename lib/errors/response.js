/**
 * EP Standardized Error Response Builder
 *
 * Builds RFC 7807 Problem Details responses from the unified error taxonomy.
 * Routes should import `epError` from here and pass a code from EP_ERROR_CODES
 * instead of constructing ad-hoc error payloads.
 *
 * Shape emitted:
 *   {
 *     error: {
 *       code:      "EP-3001",
 *       message:   "Handshake not found",
 *       detail:    "No handshake with id abc-123",  // optional
 *       timestamp: "2025-05-01T12:00:00.000Z"
 *     }
 *   }
 *
 * The outer `error` envelope matches common API conventions and makes it easy
 * for clients to distinguish success from failure at the top level.
 *
 * Backward compatibility:
 *   The previous `epProblem()` function in lib/errors.js is still available
 *   for routes that have not migrated. New code should use this builder.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';

/**
 * Build a standardized EP error response.
 *
 * @param {Object} errorCode  An entry from EP_ERROR_CODES (must have code, status, message).
 * @param {string|null} detail  Optional human-readable detail for this specific occurrence.
 * @param {Object|null} extras  Optional additional fields merged into the error body
 *                              (e.g. { field: 'entity_id' } for validation errors).
 * @returns {NextResponse}
 */
export function epError(errorCode, detail = null, extras = null) {
  return NextResponse.json({
    error: {
      code: errorCode.code,
      message: errorCode.message,
      ...(detail && { detail }),
      ...(extras && extras),
      timestamp: new Date().toISOString(),
    },
  }, { status: errorCode.status });
}

/**
 * Build an EP error response for a missing required field.
 * Convenience wrapper that fills in the field name as detail.
 *
 * @param {string} fieldName  The name of the missing field.
 * @returns {NextResponse}
 */
export function epMissingField(fieldName) {
  // Re-uses EP-2002 MISSING_REQUIRED with specific detail
  return epError(
    { code: 'EP-2002', status: 400, message: 'Missing required field' },
    `Missing required field: ${fieldName}`,
    { field: fieldName },
  );
}
