// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/oidc/callback — exchange the code, validate the ID token against
// the provider JWKS, and resolve the identity against the SCIM directory.

export const runtime = 'nodejs';

import { getGuardedClient } from '@/lib/write-guard';
import { discover, exchangeCode, validateIdToken } from '@/lib/sso/oidc';
import { loadConnection } from '@/lib/sso/config';
import { verifyState, SSO_STATE_COOKIE } from '@/lib/sso/state';
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
  const { connection, error } = await loadConnection(tenant, 'oidc');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.oidc_issuer) return epProblem(404, 'sso_not_configured', 'OIDC connection not found');

  let doc;
  try {
    doc = await discover(connection.oidc_issuer);
  } catch {
    return epProblem(502, 'oidc_discovery_failed', 'Could not reach the OIDC provider');
  }

  let tokens;
  try {
    tokens = await exchangeCode({
      tokenEndpoint: doc.token_endpoint,
      clientId: connection.oidc_client_id,
      clientSecret: connection.oidc_client_secret,
      code, redirectUri, codeVerifier,
    });
  } catch (err) {
    logger.warn('[sso/oidc/callback] token exchange failed:', err.message);
    return epProblem(401, 'token_exchange_failed', 'Authorization code exchange failed');
  }

  const verdict = await validateIdToken(tokens.id_token, {
    issuer: doc.issuer || connection.oidc_issuer,
    clientId: connection.oidc_client_id,
    jwksUri: doc.jwks_uri,
    nonce,
  });
  if (!verdict.valid) {
    logger.warn('[sso/oidc/callback] id_token invalid:', verdict.error);
    return epProblem(401, 'id_token_invalid', verdict.error || 'ID token did not validate');
  }

  const directory = await resolveDirectory(tenant, verdict.email || verdict.subject);
  return Response.json({
    authenticated: true,
    protocol: 'oidc',
    tenant,
    identity: { subject: verdict.subject, email: verdict.email },
    directory,
  });
}

async function resolveDirectory(tenant, userName) {
  try {
    const supabase = getGuardedClient();
    const { data } = await supabase
      .from('scim_users')
      .select('id, active')
      .eq('tenant_id', tenant)
      .eq('user_name', userName)
      .maybeSingle();
    if (!data) return { matched: false, active: false };
    return { matched: true, active: data.active !== false, user_id: data.id };
  } catch {
    return { matched: false, active: false, error: 'directory_lookup_failed' };
  }
}
