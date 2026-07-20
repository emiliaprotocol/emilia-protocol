// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/oidc/callback — exchange the code, validate the ID token against
// the provider JWKS, and resolve the identity against the SCIM directory.

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { discover, exchangeCode, validateIdToken, assertSafeDiscoveryEndpoints } from '@/lib/sso/oidc';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { validateOidcRedirectUri, validateSsoProviderUrl } from '@/lib/sso/url-policy';
import { verifyState, SSO_STATE_COOKIE } from '@/lib/sso/state';
import { mintSession, SESSION_COOKIE, SESSION_COOKIE_OPTIONS } from '@/lib/sso/session';
import { normalizeUserName } from '@/lib/scim/core';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function GET(request) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  const idpError = url.searchParams.get('error');
  if (idpError) return epProblem(401, 'oidc_idp_error', `Provider returned: ${idpError}`);
  if (!code) return epProblem(400, 'missing_code', 'Authorization code is required');

  // CSRF / association: the signed cookie must verify and match the returned state.
  const cookie = request.cookies.get(SSO_STATE_COOKIE)?.value;
  const stateData = verifyState(cookie);
  if (!stateData) return epProblem(400, 'invalid_state', 'Missing or expired login state');
  if (stateData.state !== returnedState) return epProblem(400, 'state_mismatch', 'State does not match');

  const { tenant, nonce, codeVerifier, redirectUri } = stateData;
  const redirect = validateOidcRedirectUri(redirectUri, spOrigin(request));
  if (!redirect.valid) return epProblem(400, 'unsafe_oidc_redirect_uri', 'Login state carried an unsafe redirect URI');
  const safeRedirectUri = redirect.url;
  const { connection, error } = await loadConnection(tenant, 'oidc');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.oidc_issuer) return epProblem(404, 'sso_not_configured', 'OIDC connection not found');
  const issuer = await validateSsoProviderUrl(connection.oidc_issuer, 'oidc_issuer');
  if (!issuer.valid) return epProblem(400, 'unsafe_sso_url', 'Configured OIDC issuer is not allowed');

  let doc;
  try {
    // `issuer.valid` was checked above (return on !valid), which guarantees
    // `issuer.url` is set — TS widens the literal `valid` flag to `boolean`
    // across validateSsoProviderUrl's branches, so it can't see that guard.
    doc = await discover(/** @type {string} */ (issuer.url));
  } catch {
    return epProblem(502, 'oidc_discovery_failed', 'Could not reach the OIDC provider');
  }

  // SSRF: the discovery doc names the token_endpoint (secret-bearing POST) and
  // jwks_uri (fetched in validateIdToken). A hostile issuer can point these at
  // internal/metadata hosts, so each must pass the same public-host policy.
  const safeEndpoints = await assertSafeDiscoveryEndpoints(doc);
  if (!safeEndpoints.valid) {
    return epProblem(400, 'unsafe_sso_url', `OIDC ${safeEndpoints.field} is not allowed`);
  }

  let tokens;
  try {
    tokens = await exchangeCode({
      tokenEndpoint: doc.token_endpoint,
      clientId: connection.oidc_client_id,
      clientSecret: connection.oidc_client_secret,
      code, redirectUri: safeRedirectUri, codeVerifier,
    });
  } catch (err) {
    logger.warn('[sso/oidc/callback] token exchange failed:', err.message);
    return epProblem(401, 'token_exchange_failed', 'Authorization code exchange failed');
  }

  const verdict = await validateIdToken(tokens.id_token, {
    issuer: doc.issuer || issuer.url,
    clientId: connection.oidc_client_id,
    jwksUri: doc.jwks_uri,
    nonce,
  });
  if (!verdict.valid) {
    logger.warn('[sso/oidc/callback] id_token invalid:', verdict.error);
    return epProblem(401, 'id_token_invalid', verdict.error || 'ID token did not validate');
  }

  const directory = await resolveDirectory(tenant, verdict.email || verdict.subject);
  if (!directory.matched || !directory.active) {
    return epProblem(403, 'sso_identity_not_provisioned', 'The asserted identity is not active in this tenant directory');
  }

  // Mint the EP session — this is what "logged in" means. The session asserts
  // the verified identity; signing authority still requires the enrolled
  // passkey ceremony per action.
  const token = await mintSession({
    tenant,
    // `verdict.valid` was checked above (return on !valid), and validateIdToken
    // only sets `valid: true` after confirming `payload.sub` is present, so
    // `subject` is guaranteed here — same `boolean`-widening gap as above.
    subject: /** @type {string} */ (verdict.subject),
    email: verdict.email,
    protocol: 'oidc',
    directory,
  });
  const res = NextResponse.json({
    authenticated: true,
    protocol: 'oidc',
    tenant,
    identity: { subject: verdict.subject, email: verdict.email },
    directory,
    session: 'set',
  });
  res.cookies.set(SESSION_COOKIE, token, /** @type {Partial<import('next/dist/compiled/@edge-runtime/cookies').ResponseCookie>} */ (SESSION_COOKIE_OPTIONS));
  // The one-shot login state has served its purpose.
  res.cookies.delete(SSO_STATE_COOKIE);
  return res;
}

async function resolveDirectory(tenant, userName) {
  try {
    const supabase = getGuardedClient();
    const { data } = await supabase
      .from('scim_users')
      .select('id, active')
      .eq('tenant_id', tenant)
      .eq('user_name', normalizeUserName(userName))
      .maybeSingle();
    if (!data) return { matched: false, active: false };
    return { matched: true, active: data.active !== false, user_id: data.id };
  } catch {
    return { matched: false, active: false, error: 'directory_lookup_failed' };
  }
}
