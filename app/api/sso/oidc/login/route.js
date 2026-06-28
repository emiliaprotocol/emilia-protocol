// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/oidc/login?tenant=<id> — OIDC Authorization Code + PKCE.
// Discovers the provider, builds the authorize URL, stashes state/nonce/verifier
// in a signed httpOnly cookie, and 302-redirects to the IdP.

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import { discover, buildAuthorizeUrl, randomUrlToken, pkceChallenge } from '@/lib/sso/oidc';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { validateSsoProviderUrl } from '@/lib/sso/url-policy';
import { signState, SSO_STATE_COOKIE } from '@/lib/sso/state';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function GET(request) {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  if (!tenant) return epProblem(400, 'missing_tenant', 'tenant query parameter is required');

  const { connection, error } = await loadConnection(tenant, 'oidc');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.oidc_issuer || !connection?.oidc_client_id) {
    return epProblem(404, 'sso_not_configured', `No OIDC connection configured for tenant ${tenant}`);
  }
  const issuer = validateSsoProviderUrl(connection.oidc_issuer, 'oidc_issuer');
  if (!issuer.valid) return epProblem(400, 'unsafe_sso_url', 'Configured OIDC issuer is not allowed');

  const origin = spOrigin(request);
  const redirectUri = connection.oidc_redirect_uri || `${origin}/api/sso/oidc/callback`;

  let doc;
  try {
    doc = await discover(issuer.url);
  } catch (err) {
    logger.error('[sso/oidc/login] discovery failed:', err);
    return epProblem(502, 'oidc_discovery_failed', 'Could not reach the OIDC provider');
  }

  const state = randomUrlToken();
  const nonce = randomUrlToken();
  const codeVerifier = randomUrlToken();
  const authorizeUrl = buildAuthorizeUrl({
    authorizationEndpoint: doc.authorization_endpoint,
    clientId: connection.oidc_client_id,
    redirectUri,
    state, nonce,
    codeChallenge: pkceChallenge(codeVerifier),
  });

  const res = NextResponse.redirect(authorizeUrl, 302);
  res.cookies.set(SSO_STATE_COOKIE, signState({ tenant, state, nonce, codeVerifier, redirectUri }), {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/api/sso/oidc', maxAge: 600,
  });
  return res;
}
