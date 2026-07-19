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
 * Secret: SSO_SESSION_SECRET in production. Development uses a separate
 * process-local random fallback; it never derives a session key from a shared
 * deployment credential or a source-predictable literal.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import * as jose from 'jose';
import { getSsoConfig } from '../env.js';

export const SESSION_COOKIE = 'ep_session';
const SESSION_TTL = '8h';
const ISSUER = 'ep:sso';
const DEVELOPMENT_SESSION_SECRET = crypto.randomBytes(32).toString('base64url');

function sessionKey() {
  const { sessionSecret: explicit, isProduction } = getSsoConfig();
  // Fail closed in production: a missing SSO_SESSION_SECRET must NOT silently
  // degrade to the predictable 'ep-sso-dev' fallback, which would let anyone who
  // reads the source forge a session for any tenant. Same posture as
  // lib/crypto/secret-box.js. Development fallback is process-local random.
  if (!explicit && isProduction) {
    throw new Error('sso/session: SSO_SESSION_SECRET is required in production — refusing to sign sessions without an explicit secret.');
  }
  const base = explicit || DEVELOPMENT_SESSION_SECRET;
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
    // jti uniquely identifies this session so a future server-side revocation
    // list (logout-all-devices / compromised-account containment) can target a
    // single token instead of rotating the global secret.
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(SESSION_TTL)
    .sign(sessionKey());
}

/**
 * Verify a session token. Returns the claims or null (expired/tampered/absent/
 * revoked).
 *
 * Beyond signature + expiry, this consults the server-side revocation store:
 *   • per-session jti (single logout / compromised-token containment), and
 *   • a subject-wide cutoff (logout-all-devices / incident kill) that rejects
 *     any token issued before the cutoff.
 * Revocation is mandatory. If the store is unavailable, verification fails
 * closed so a revoked or cutoff session never survives a control-plane outage.
 */
export async function verifySession(token) {
  if (!token) return null;
  let payload;
  try {
    ({ payload } = await jose.jwtVerify(token, sessionKey(), { issuer: ISSUER }));
  } catch {
    return null;
  }
  try {
    if (await isSessionRevoked(payload)) return null;
  } catch {
    return null;
  }
  return payload;
}

async function isSessionRevoked(payload) {
  if (!payload?.jti && !payload?.sub) return false;
  const { getServiceClient } = await import('@/lib/supabase');
  const supabase = getServiceClient();

  // Single-session revocation (logout / stolen token).
  if (payload.jti) {
    const { data, error } = await supabase
      .from('revoked_sessions')
      .select('jti')
      .eq('jti', payload.jti)
      .maybeSingle();
    if (error) throw new Error(`revoked_sessions lookup failed: ${error.message || error}`);
    if (data) return true;
  }

  // Subject-wide cutoff (logout-all-devices / admin incident kill): reject any
  // token issued before not_before.
  if (payload.sub && payload.iat) {
    const { data, error } = await supabase
      .from('session_cutoffs')
      .select('not_before')
      .eq('subject', payload.sub)
      .eq('tenant', payload.tenant || '')
      .maybeSingle();
    if (error) throw new Error(`session_cutoffs lookup failed: ${error.message || error}`);
    if (data?.not_before) {
      const cutoff = Math.floor(new Date(data.not_before).getTime() / 1000);
      if (payload.iat < cutoff) return true;
    }
  }
  return false;
}

/**
 * Revoke a single session by jti (logout / token compromise). Returns true on
 * success, false if the store is unavailable (best-effort, logged by caller).
 */
export async function revokeSession(jti, { subject = null, tenant = null, expiresAt = null } = {}) {
  if (!jti) return false;
  try {
    const { getServiceClient } = await import('@/lib/supabase');
    const supabase = getServiceClient();
    const { error } = await supabase.from('revoked_sessions').upsert(
      {
        jti,
        subject,
        tenant,
        expires_at: expiresAt || new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
      },
      { onConflict: 'jti' },
    );
    return !error;
  } catch {
    return false;
  }
}

/**
 * Revoke EVERY existing session for a subject (logout-all-devices / incident
 * containment) by stamping a not_before cutoff = now. Tokens minted after this
 * call (later iat) remain valid.
 */
export async function revokeAllSessionsForSubject(subject, tenant) {
  if (!subject) return false;
  try {
    const { getServiceClient } = await import('@/lib/supabase');
    const supabase = getServiceClient();
    const { error } = await supabase.from('session_cutoffs').upsert(
      { subject, tenant: tenant || '', not_before: new Date().toISOString() },
      { onConflict: 'subject,tenant' },
    );
    return !error;
  } catch {
    return false;
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
