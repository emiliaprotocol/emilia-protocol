/**
 * EP session — what "logged in via SSO" means.
 *
 * On a successful SAML ACS or OIDC callback, EP mints a signed session token
 * (HS256 JWT via jose) carrying the verified identity, the tenant, the
 * protocol that authenticated it, and the SCIM-directory verdict. It is set as
 * an httpOnly cookie; /api/sso/session reads it back and DELETE logs out.
 *
 * The session asserts WHO authenticated. It deliberately does NOT grant
 * signing authority — Class-A signoff still requires the approver's enrolled
 * passkey ceremony per action. directory.active gates whether this human is a
 * currently-provisioned approver.
 *
 * Secret: SSO_SESSION_SECRET, falling back to a derivation every deployment
 * already has (same posture as lib/sso/state.js).
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import * as jose from 'jose';

export const SESSION_COOKIE = 'ep_session';
const SESSION_TTL = '8h';
const ISSUER = 'ep:sso';

function sessionKey() {
  const explicit = process.env.SSO_SESSION_SECRET;
  const base = explicit
    || `ep-sso-session:${process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || 'ep-sso-dev'}`;
  return new TextEncoder().encode(crypto.createHash('sha256').update(base, 'utf8').digest('hex'));
}

/**
 * Mint an EP session JWT for a verified SSO identity.
 * @param {{ tenant:string, subject:string, email?:string, protocol:'saml'|'oidc',
 *           directory?:{matched:boolean, active:boolean, user_id?:string} }} identity
 * @returns {Promise<string>} compact JWS
 */
export async function mintSession(identity) {
  if (!identity?.tenant || !identity?.subject) throw new Error('mintSession requires tenant and subject');
  return new jose.SignJWT({
    tenant: identity.tenant,
    email: identity.email,
    protocol: identity.protocol,
    directory: identity.directory || { matched: false, active: false },
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(ISSUER)
    .setSubject(identity.subject)
    .setIssuedAt()
    .setExpirationTime(SESSION_TTL)
    .sign(sessionKey());
}

/**
 * Verify a session token. Returns the claims or null (expired/tampered/absent).
 */
export async function verifySession(token) {
  if (!token) return null;
  try {
    const { payload } = await jose.jwtVerify(token, sessionKey(), { issuer: ISSUER });
    return payload;
  } catch {
    return null;
  }
}

/** Read + verify the session from a Request's Cookie header. */
export async function readSessionFromRequest(request) {
  const cookieHeader = request.headers.get('cookie') || '';
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`));
  return verifySession(match ? decodeURIComponent(match[1]) : null);
}

/** Cookie options for the session (8h, httpOnly, secure). */
export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
  maxAge: 8 * 60 * 60,
};
