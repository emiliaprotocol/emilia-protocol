/**
 * SSO transient state — an HMAC-signed, short-lived token that carries the
 * login round-trip's state/nonce/PKCE-verifier from the redirect to the
 * callback in an httpOnly cookie. No database row for in-flight logins.
 *
 * The signing secret is a stable per-deployment value (SSO_STATE_SECRET, or
 * derived from the service-role key) so a token issued by one serverless
 * instance verifies on another.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import { strictJsonGate } from '../strict-json.js';

export const SSO_STATE_COOKIE = 'ep_sso_state';
const DEFAULT_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes
const MAX_STATE_TOKEN_CHARS = 32 * 1024;
const MAX_CLOCK_SKEW_MS = 60 * 1000;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function decodeBase64url(value, maxBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length > 0 && bytes.length <= maxBytes && bytes.toString('base64url') === value ? bytes : null;
  } catch {
    return null;
  }
}

function stateSecret() {
  const explicit = process.env.SSO_STATE_SECRET;
  if (explicit) return explicit;
  // Fail closed in production: never sign OIDC state/nonce/PKCE round-trips with
  // the predictable 'ep-sso-dev-secret' fallback (would allow state/nonce
  // forgery). Same posture as lib/sso/session.js and lib/crypto/secret-box.js.
  if (process.env.NODE_ENV === 'production') {
    throw new Error('sso/state: SSO_STATE_SECRET is required in production — refusing to sign SSO state with a derived/predictable key.');
  }
  // Dev-only: derive a stable secret from a value every deployment already has.
  const base = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || 'ep-sso-dev-secret';
  return crypto.createHash('sha256').update(`ep-sso:${base}`).digest('hex');
}

/** Sign a state payload → a compact `<b64url(json)>.<hmac>` token. */
export function signState(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() }), 'utf8').toString('base64url');
  const mac = crypto.createHmac('sha256', stateSecret()).update(body).digest('base64url');
  return `${body}.${mac}`;
}

/**
 * Verify + decode a state token. Returns the payload, or null if the signature
 * is invalid or the token is older than maxAgeMs.
 */
export function verifyState(token, maxAgeMs = DEFAULT_MAX_AGE_MS) {
  if (!token || typeof token !== 'string' || token.length > MAX_STATE_TOKEN_CHARS
      || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, mac] = parts;
  if (!body || !mac) return null;

  const suppliedMac = decodeBase64url(mac, 32);
  const bodyBytes = decodeBase64url(body, 16 * 1024);
  if (!suppliedMac || suppliedMac.length !== 32 || !bodyBytes) return null;
  const expected = crypto.createHmac('sha256', stateSecret()).update(body).digest();
  if (!crypto.timingSafeEqual(suppliedMac, expected)) return null;

  let payload;
  try {
    const text = UTF8_DECODER.decode(bodyBytes);
    if (!strictJsonGate(text).ok) return null;
    payload = JSON.parse(text);
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || !Number.isSafeInteger(payload.iat)) return null;
  const age = Date.now() - payload.iat;
  if (age < -MAX_CLOCK_SKEW_MS || age > maxAgeMs) return null;
  return payload;
}
