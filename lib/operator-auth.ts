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
 * Each per-operator token authorizes exactly ONE request: the first
 * presentation consumes it (see lib/operator-token-replay.ts). Callers that
 * need to hit several endpoints must mint a token per endpoint.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { getOperatorKeys, getOperatorRoles, getCronSecret } from './env.js';
import { consumeOperatorToken } from './operator-token-replay.js';

const TOKEN_MAX_AGE_MS = 5 * 60 * 1000; // 5 minutes
const TOKEN_PREFIX = 'ep_op_';

export interface OperatorAuthOptions {
  /**
   * Whether this route demands a NAMED operator. Defaults to true: a route
   * that says nothing gets the identity requirement, and only a route that
   * explicitly declares itself an unattended job opts out. The previous
   * default was false, so a new sensitive route that simply forgot to pass
   * the flag silently accepted the anonymous shared cron secret.
   */
  requireOperatorIdentity?: boolean;
}

export interface OperatorAuthResult {
  valid: boolean;
  operator_id?: string;
  role?: string | null;
  error?: string;
}

/**
 * Generate an operator token.
 *
 * @param {string} operatorId - The operator's identifier
 * @param {string} secretHex - The operator's HMAC secret (hex)
 * @returns {string} Signed token
 */
export function generateOperatorToken(operatorId: string, secretHex: string): string {
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
 * Async because a valid per-operator token must also be CLAIMED before it
 * authorizes anything — see lib/operator-token-replay.ts.
 *
 * @param {string} token - The token from Authorization header or query param
 * @returns {Promise<{ valid: boolean, operator_id?: string, role?: string|null, error?: string }>}
 */
export async function verifyOperatorAuth(token: string | null | undefined, opts: OperatorAuthOptions = {}): Promise<OperatorAuthResult> {
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

    // Genuine bytes, minted recently, by a keyholder. None of that establishes
    // that the PRESENTER is the keyholder, so the token has to be spent: claim
    // its single use before it authorizes anything. The TTL outlives the
    // token's own window so a record can never expire while the token it
    // guards is still inside the age check above.
    const claim = await consumeOperatorToken(providedHmac, TOKEN_MAX_AGE_MS / 1000 + 60);
    if (!claim.ok) {
      return {
        valid: false,
        error: claim.reason === 'already_consumed'
          ? 'Operator token already used; mint a fresh token per request'
          : 'Operator token replay protection unavailable',
      };
    }

    const role = getOperatorRoles().get(operatorId) || null;
    return { valid: true, operator_id: operatorId, role };
  }

  // === Path 2: Legacy CRON_SECRET (deprecated, backward compatible) ===
  // Every trust-changing action must tie to a NAMED operator in the audit
  // trail. The shared cron secret is anonymous by construction (operator_id
  // '_legacy_cron'), so it is refused on identity-required routes
  // UNCONDITIONALLY — not just once per-operator keys are configured. Making
  // the refusal contingent on getOperatorKeys().size > 0 meant that in a
  // deployment that had not yet provisioned EP_OPERATOR_KEYS, a leaked
  // CRON_SECRET could resolve disputes, adjudicate appeals, and revoke commit
  // signing keys with the full 'operator' role.
  //
  // The requirement is now the DEFAULT rather than something a route has to
  // remember to ask for. Only the unattended schedulers (expire /
  // collusion-scan / trust-desk-monitor / anchor) opt out, each explicitly and
  // in one line at the call site, so the declaration is visible in review. A
  // new route that says nothing about identity is protected by silence.
  if (opts.requireOperatorIdentity !== false) {
    return { valid: false, error: 'This action requires a per-operator token, not the shared secret' };
  }
  const cronSecret = getCronSecret();
  if (cronSecret) {
    const a = Buffer.from(token, 'utf8');
    const b = Buffer.from(cronSecret, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      // role null, not 'operator'. Nothing consumes this role today — every
      // hasPermission() caller is on an identity-required route the shared
      // secret can no longer reach — but naming the anonymous credential after
      // the most privileged role in OPERATOR_ROLES is a trap set for whoever
      // next writes `if (hasPermission(auth.role, ...))` on a cron route.
      return { valid: true, operator_id: '_legacy_cron', role: null };
    }
  }

  return { valid: false, error: 'Authentication failed' };
}

/**
 * Express/Next.js middleware-compatible auth check.
 * Extracts token from Authorization header (Bearer) or x-cron-secret header.
 *
 * @param {Request} request
 * @returns {Promise<{ valid: boolean, operator_id?: string, error?: string }>}
 */
export async function authenticateOperator(request: Request, opts: OperatorAuthOptions = {}): Promise<OperatorAuthResult> {
  // Try Authorization: Bearer <token> first
  const auth = request.headers.get('authorization') || '';
  const bearer = auth.replace(/^Bearer\s+/i, '').trim();
  if (bearer) {
    return verifyOperatorAuth(bearer, opts);
  }

  // Fallback: x-cron-secret header (legacy)
  const cronHeader = request.headers.get('x-cron-secret') || '';
  if (cronHeader) {
    return verifyOperatorAuth(cronHeader, opts);
  }

  return { valid: false, error: 'No credentials provided' };
}
