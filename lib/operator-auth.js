/**
 * EP Operator Authentication — Per-Operator Signed Tokens
 *
 * Replaces the shared CRON_SECRET with per-operator HMAC-SHA256 tokens.
 * Each operator gets its own signing key. Tokens are short-lived (5 min).
 *
 * Token format: ep_op_<operator_id>.<timestamp_hex>.<hmac_hex>
 *
 * Backward compatible: still accepts legacy CRON_SECRET during migration.
 *
 * Environment:
 *   EP_OPERATOR_KEYS — JSON map: { "operator_id": "hex_secret", ... }
 *   CRON_SECRET — Legacy shared secret (deprecated, still accepted)
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getOperatorKeys, getCronSecret } from './env.js';

const TOKEN_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const TOKEN_PREFIX = 'ep_op_';

/**
 * Generate an operator token.
 *
 * @param {string} operatorId - The operator's identifier
 * @param {string} secretHex - The operator's HMAC secret (hex)
 * @returns {string} Signed token
 */
export function generateOperatorToken(operatorId, secretHex) {
  const timestamp = Date.now().toString(16);
  const message = `${operatorId}.${timestamp}`;
  const hmac = crypto.createHmac('sha256', Buffer.from(secretHex, 'hex'))
    .update(message)
    .digest('hex');

  return `${TOKEN_PREFIX}${message}.${hmac}`;
}

/**
 * Verify an operator token or legacy CRON_SECRET.
 *
 * @param {string} token - The token from Authorization header or query param
 * @returns {{ valid: boolean, operator_id?: string, error?: string }}
 */
export function verifyOperatorAuth(token) {
  if (!token) {
    return { valid: false, error: 'No token provided' };
  }

  // === Path 1: Per-operator token (ep_op_<id>.<ts>.<hmac>) ===
  if (token.startsWith(TOKEN_PREFIX)) {
    const body = token.slice(TOKEN_PREFIX.length);
    const parts = body.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Malformed operator token' };
    }

    const [operatorId, timestampHex, providedHmac] = parts;

    // Check timestamp (replay window)
    const timestamp = parseInt(timestampHex, 16);
    if (!Number.isFinite(timestamp)) {
      return { valid: false, error: 'Invalid timestamp' };
    }
    const age = Date.now() - timestamp;
    if (age < 0 || age > TOKEN_MAX_AGE_MS) {
      return { valid: false, error: 'Token expired or from the future' };
    }

    // Look up operator's key (loaded from lib/env.js so all EP_ env reads
    // remain centralized — see scripts/check-protocol-discipline.js).
    const keys = getOperatorKeys();
    const secret = keys.get(operatorId);
    if (!secret) {
      return { valid: false, error: 'Unknown operator' };
    }

    // Verify HMAC (timing-safe)
    const message = `${operatorId}.${timestampHex}`;
    const expectedHmac = crypto.createHmac('sha256', secret)
      .update(message)
      .digest('hex');

    const a = Buffer.from(providedHmac, 'utf8');
    const b = Buffer.from(expectedHmac, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { valid: false, error: 'Invalid signature' };
    }

    return { valid: true, operator_id: operatorId };
  }

  // === Path 2: Legacy CRON_SECRET (deprecated, backward compatible) ===
  const cronSecret = getCronSecret();
  if (cronSecret) {
    const a = Buffer.from(token, 'utf8');
    const b = Buffer.from(cronSecret, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { valid: true, operator_id: '_legacy_cron' };
    }
  }

  return { valid: false, error: 'Authentication failed' };
}

/**
 * Express/Next.js middleware-compatible auth check.
 * Extracts token from Authorization header (Bearer) or x-cron-secret header.
 *
 * @param {Request} request
 * @returns {{ valid: boolean, operator_id?: string, error?: string }}
 */
export function authenticateOperator(request) {
  // Try Authorization: Bearer <token> first
  const auth = request.headers.get('authorization') || '';
  const bearer = auth.replace(/^Bearer\s+/i, '').trim();
  if (bearer) {
    return verifyOperatorAuth(bearer);
  }

  // Fallback: x-cron-secret header (legacy)
  const cronHeader = request.headers.get('x-cron-secret') || '';
  if (cronHeader) {
    return verifyOperatorAuth(cronHeader);
  }

  return { valid: false, error: 'No credentials provided' };
}
