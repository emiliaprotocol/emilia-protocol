/**
 * OIDC Relying Party — discovery, authorize redirect (PKCE), token exchange,
 * and ID-token validation.
 *
 * Works with any compliant OpenID provider (Okta, Entra ID, Google, Ping,
 * Auth0, Keycloak). ID-token signature verification uses `jose` (pure JS, no
 * native deps) against the provider's published JWKS — never a hand-rolled JWT
 * check.
 *
 * Functions are config-injected (no global state, injectable fetch) so the
 * validation core is unit-testable against a fixture provider without a live
 * IdP. The live round-trip needs the provider's client_id/secret.
 *
 * @license Apache-2.0
 */

import crypto from 'node:crypto';
import * as jose from 'jose';
import { validateSsoProviderUrl } from './url-policy.js';

// ── PKCE + state/nonce ───────────────────────────────────────────────────────

export function randomUrlToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** PKCE S256 challenge for a verifier (RFC 7636). */
export function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
}

// ── Discovery ────────────────────────────────────────────────────────────────

/**
 * Fetch an OIDC provider's discovery document.
 * @returns {Promise<{issuer, authorization_endpoint, token_endpoint, jwks_uri, ...}>}
 */
export async function discover(issuer, fetchImpl = fetch) {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  // SSRF: refuse server-followed redirects. The issuer host was validated, but a
  // redirect (3xx) can hop the discovery fetch to localhost/link-local/cloud
  // metadata; `redirect: 'error'` makes that throw instead of following.
  const res = await fetchImpl(url, { redirect: 'error' });
  if (!res.ok) throw new Error(`OIDC discovery failed: HTTP ${res.status}`);
  const doc = await res.json();
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('OIDC discovery document is missing required endpoints');
  }
  return doc;
}

/**
 * SSRF gate for discovery-returned endpoints. `validateSsoProviderUrl` only
 * vets the *issuer*; the discovery document then names token/jwks/authorize
 * endpoints that are fetched server-side (token POST ships the client secret;
 * jwks fetch happens inside `createRemoteJWKSet`). A hostile issuer can return
 * `token_endpoint: http://169.254.169.254/...` etc., so every endpoint the
 * server will dereference must pass the same public-host/https policy. Note:
 * endpoints are NOT required to share the issuer's host — real IdPs (e.g.
 * Google) serve token/jwks from sibling domains.
 *
 * @param {object} doc - the discovery document
 * @param {object} [opts]
 * @param {string[]} [opts.fields] - which endpoint fields to validate
 * @param {Function} [opts.lookup] - injectable DNS lookup (for tests)
 * @returns {Promise<{valid:boolean, field?:string, error?:string}>}
 */
export async function assertSafeDiscoveryEndpoints(
  doc,
  { fields = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'], lookup } = {},
) {
  for (const field of fields) {
    const v = await validateSsoProviderUrl(
      doc?.[field],
      `oidc_${field}`,
      lookup ? { lookup } : undefined,
    );
    if (!v.valid) return { valid: false, field, error: v.error };
  }
  return { valid: true };
}

// ── Authorize redirect ───────────────────────────────────────────────────────

/**
 * Build the authorization-request URL (Authorization Code + PKCE).
 */
export function buildAuthorizeUrl({
  authorizationEndpoint, clientId, redirectUri, scope = 'openid email profile',
  state, nonce, codeChallenge,
}) {
  if (!authorizationEndpoint || !clientId || !redirectUri) {
    throw new Error('buildAuthorizeUrl requires authorizationEndpoint, clientId, redirectUri');
  }
  const u = new URL(authorizationEndpoint);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('scope', scope);
  if (state) u.searchParams.set('state', state);
  if (nonce) u.searchParams.set('nonce', nonce);
  if (codeChallenge) {
    u.searchParams.set('code_challenge', codeChallenge);
    u.searchParams.set('code_challenge_method', 'S256');
  }
  return u.toString();
}

// ── Token exchange ───────────────────────────────────────────────────────────

export async function exchangeCode({
  tokenEndpoint, clientId, clientSecret, code, redirectUri, codeVerifier, fetchImpl = fetch,
}) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code, redirect_uri: redirectUri, client_id: clientId,
  });
  if (codeVerifier) body.set('code_verifier', codeVerifier);
  if (clientSecret) body.set('client_secret', clientSecret);

  const res = await fetchImpl(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: body.toString(),
    // SSRF: never follow a redirect on the secret-bearing token POST.
    redirect: 'error',
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Token exchange failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  }
  return res.json();
}

// ── ID-token validation ──────────────────────────────────────────────────────

/**
 * Validate an OIDC ID token: signature (against the provider JWKS), issuer,
 * audience, expiry (jose), and nonce binding (RFC — checked here since jose does
 * not check nonce).
 *
 * @param {string} idToken - the compact JWS ID token
 * @param {object} opts
 * @param {string} opts.issuer - expected `iss`
 * @param {string} opts.clientId - expected `aud`
 * @param {object} [opts.jwks] - a JWKS object (local verification, for tests)
 * @param {string} [opts.jwksUri] - the provider JWKS URI (remote verification)
 * @param {string} [opts.nonce] - the nonce that MUST match the token's claim
 * @returns {Promise<{ valid:boolean, claims?:object, error?:string }>}
 */
export async function validateIdToken(idToken, opts = {}) {
  const { issuer, clientId, jwks, jwksUri, nonce } = opts;
  if (!idToken) return { valid: false, error: 'Missing ID token' };
  if (!issuer || !clientId) return { valid: false, error: 'validateIdToken requires issuer and clientId' };

  let keySet;
  try {
    if (jwks) keySet = jose.createLocalJWKSet(jwks);
    else if (jwksUri) keySet = jose.createRemoteJWKSet(new URL(jwksUri));
    else return { valid: false, error: 'validateIdToken requires jwks or jwksUri' };
  } catch (e) {
    return { valid: false, error: `JWKS error: ${e.message}` };
  }

  try {
    const { payload } = await jose.jwtVerify(idToken, keySet, {
      issuer,
      audience: clientId,
    });

    // Nonce binding (replay/association). jose verifies sig/iss/aud/exp; nonce is
    // an OIDC-specific claim we must check ourselves.
    if (nonce !== undefined && payload.nonce !== nonce) {
      return { valid: false, error: 'Nonce mismatch' };
    }

    return {
      valid: true,
      claims: payload,
      subject: payload.sub,
      email: payload.email,
    };
  } catch (e) {
    return { valid: false, error: `ID token validation failed: ${e.code || e.message}` };
  }
}
