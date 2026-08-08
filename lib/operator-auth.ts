/**
 * EP Operator Authentication — Per-Operator Signed Tokens
 *
 * Replaces the shared CRON_SECRET with per-operator HMAC-SHA256 tokens.
 * Each operator gets its own signing key. Tokens are short-lived (5 min).
 *
 * Request-bound token format:
 *   ep_op2_<operator_id_b64u>.<timestamp_hex>.<nonce_b64u>.<method>
 *     .<target_b64u>.<body_sha256_hex>.<hmac_hex>
 *
 * Scheduler compatibility: explicitly opted-in cron routes still accept the
 * legacy CRON_SECRET. Unbound ep_op_ tokens are refused on HTTP requests.
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
const TOKEN_V2_PREFIX = 'ep_op2_';
const MAX_OPERATOR_REQUEST_BYTES = 1024 * 1024;

export interface OperatorTokenBinding {
  method: string;
  target: string;
  body?: string | Uint8Array;
}

interface NormalizedOperatorRequestBinding {
  method: string;
  target: string;
  bodyDigest: string;
}

export interface OperatorAuthOptions {
  /**
   * Whether this route demands a NAMED operator. Defaults to true: a route
   * that says nothing gets the identity requirement, and only a route that
   * explicitly declares itself an unattended job opts out. The previous
   * default was false, so a new sensitive route that simply forgot to pass
   * the flag silently accepted the anonymous shared cron secret.
   */
  requireOperatorIdentity?: boolean;
  /** Internal verification seam populated by authenticateOperator(). */
  requestBinding?: NormalizedOperatorRequestBinding;
  /** Reject legacy ep_op_ tokens that carry no request binding. */
  requireRequestBinding?: boolean;
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
function bodyDigest(body: string | Uint8Array = ''): string {
  return crypto.createHash('sha256').update(body).digest('hex');
}

function normalizeMethod(method: string): string {
  const normalized = typeof method === 'string' ? method.trim().toUpperCase() : '';
  if (!/^[A-Z]{3,16}$/.test(normalized)) throw new TypeError('operator token method is malformed');
  return normalized;
}

function normalizeTarget(target: string): string {
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) {
    throw new TypeError('operator token target must be an absolute-path reference');
  }
  const parsed = new URL(target, 'https://operator.invalid');
  if (parsed.origin !== 'https://operator.invalid' || parsed.hash) {
    throw new TypeError('operator token target is malformed');
  }
  return `${parsed.pathname}${parsed.search}`;
}

function normalizeBinding(binding: OperatorTokenBinding): NormalizedOperatorRequestBinding {
  if (!binding || typeof binding !== 'object') throw new TypeError('operator token request binding is required');
  return {
    method: normalizeMethod(binding.method),
    target: normalizeTarget(binding.target),
    bodyDigest: bodyDigest(binding.body),
  };
}

export function generateOperatorToken(
  operatorId: string,
  secretHex: string,
  binding: OperatorTokenBinding,
): string {
  const timestamp = Date.now().toString(16);
  const normalized = normalizeBinding(binding);
  const operatorIdEncoded = Buffer.from(operatorId, 'utf8').toString('base64url');
  const targetEncoded = Buffer.from(normalized.target, 'utf8').toString('base64url');
  const nonce = crypto.randomBytes(16).toString('base64url');
  const message = [
    operatorIdEncoded,
    timestamp,
    nonce,
    normalized.method,
    targetEncoded,
    normalized.bodyDigest,
  ].join('.');
  const hmac = crypto.createHmac('sha256', Buffer.from(secretHex, 'hex'))
    .update(message)
    .digest('hex');
  return `${TOKEN_V2_PREFIX}${message}.${hmac}`;
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

  // === Path 1: Request-bound per-operator token ===
  if (token.startsWith(TOKEN_V2_PREFIX)) {
    const body = token.slice(TOKEN_V2_PREFIX.length);
    const parts = body.split('.');
    if (parts.length !== 7) return { valid: false, error: 'Malformed operator token' };
    const [operatorIdEncoded, timestampHex, nonce, method, targetEncoded, boundBodyDigest, providedHmac] = parts;
    if (!/^[A-Za-z0-9_-]{1,171}$/.test(operatorIdEncoded)
        || !/^[0-9a-f]{11,16}$/.test(timestampHex)
        || !/^[A-Za-z0-9_-]{20,32}$/.test(nonce)
        || !/^[A-Z]{3,16}$/.test(method)
        || !/^[A-Za-z0-9_-]+$/.test(targetEncoded)
        || !/^[0-9a-f]{64}$/.test(boundBodyDigest)
        || !/^[0-9a-f]{64}$/.test(providedHmac)) {
      return { valid: false, error: 'Malformed operator token' };
    }

    let operatorId: string;
    let target: string;
    try {
      operatorId = Buffer.from(operatorIdEncoded, 'base64url').toString('utf8');
      target = Buffer.from(targetEncoded, 'base64url').toString('utf8');
      if (!operatorId || Buffer.from(operatorId, 'utf8').toString('base64url') !== operatorIdEncoded
          || Buffer.from(target, 'utf8').toString('base64url') !== targetEncoded
          || normalizeTarget(target) !== target) {
        return { valid: false, error: 'Malformed operator token' };
      }
    } catch {
      return { valid: false, error: 'Malformed operator token' };
    }

    const timestamp = parseInt(timestampHex, 16);
    const age = Date.now() - timestamp;
    if (!Number.isFinite(timestamp) || age < 0 || age > TOKEN_MAX_AGE_MS) {
      return { valid: false, error: 'Token expired or from the future' };
    }

    const secret = getOperatorKeys().get(operatorId);
    if (!secret) return { valid: false, error: 'Unknown operator' };
    const message = parts.slice(0, -1).join('.');
    const expectedHmac = crypto.createHmac('sha256', secret).update(message).digest('hex');
    const supplied = Buffer.from(providedHmac, 'utf8');
    const expected = Buffer.from(expectedHmac, 'utf8');
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      return { valid: false, error: 'Invalid signature' };
    }

    const requestBinding = opts.requestBinding;
    if (!requestBinding
        || requestBinding.method !== method
        || requestBinding.target !== target
        || requestBinding.bodyDigest !== boundBodyDigest) {
      return { valid: false, error: 'Operator token request binding mismatch' };
    }

    const claim = await consumeOperatorToken(providedHmac, TOKEN_MAX_AGE_MS / 1000 + 60);
    if (!claim.ok) {
      return {
        valid: false,
        error: claim.reason === 'already_consumed'
          ? 'Operator token already used; mint a fresh token per request'
          : 'Operator token replay protection unavailable',
      };
    }
    return {
      valid: true,
      operator_id: operatorId,
      role: getOperatorRoles().get(operatorId) || null,
    };
  }

  // === Path 1b: Legacy unbound per-operator token (verification-only) ===
  if (token.startsWith(TOKEN_PREFIX)) {
    if (opts.requireRequestBinding === true) {
      return { valid: false, error: 'Legacy operator token has no request binding' };
    }
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
    if (bearer.startsWith(TOKEN_V2_PREFIX)) {
      let bytes: Uint8Array;
      try {
        const raw = new Uint8Array(await request.clone().arrayBuffer());
        if (raw.byteLength > MAX_OPERATOR_REQUEST_BYTES) {
          return { valid: false, error: 'Operator request body exceeds authentication limit' };
        }
        bytes = raw;
      } catch {
        return { valid: false, error: 'Operator request body could not be bound' };
      }
      const url = new URL(request.url);
      return verifyOperatorAuth(bearer, {
        ...opts,
        requireRequestBinding: true,
        requestBinding: {
          method: normalizeMethod(request.method),
          target: `${url.pathname}${url.search}`,
          bodyDigest: bodyDigest(bytes),
        },
      });
    }
    return verifyOperatorAuth(bearer, { ...opts, requireRequestBinding: true });
  }

  // Fallback: x-cron-secret header (legacy)
  const cronHeader = request.headers.get('x-cron-secret') || '';
  if (cronHeader) {
    return verifyOperatorAuth(cronHeader, opts);
  }

  return { valid: false, error: 'No credentials provided' };
}
