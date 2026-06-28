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

export const SSO_STATE_COOKIE = 'ep_sso_state';
const DEFAULT_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes

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
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;

  const expected = crypto.createHmac('sha256', stateSecret()).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload?.iat || Date.now() - payload.iat > maxAgeMs) return null;
  return payload;
}
