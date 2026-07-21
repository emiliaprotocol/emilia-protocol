// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/saml/login?tenant=<id> — SP-initiated SAML login.
// Builds the AuthnRequest and 302-redirects to the tenant's IdP, carrying the
// tenant in RelayState so the ACS can pick the right connection.

export const runtime = 'nodejs';

import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { buildSamlSp, buildLoginUrl } from '@/lib/sso/saml';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { validateSsoProviderUrl } from '@/lib/sso/url-policy';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { signState, SAML_STATE_COOKIE } from '@/lib/sso/state';

export async function GET(request: NextRequest): Promise<NextResponse> {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  if (!tenant) return epProblem(400, 'missing_tenant', 'tenant query parameter is required');

  const { connection, error } = await loadConnection(tenant, 'saml');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.saml_idp_entry_point || !connection?.saml_idp_cert) {
    return epProblem(404, 'sso_not_configured', `No SAML connection configured for tenant ${tenant}`);
  }
  const entryPoint = await validateSsoProviderUrl(connection.saml_idp_entry_point, 'saml_idp_entry_point');
  if (!entryPoint.valid) return epProblem(400, 'unsafe_sso_url', 'Configured SAML IdP URL is not allowed');

  const origin = spOrigin(request);
  const sp = buildSamlSp({
    // entryPoint.valid was checked above (line 28) and guarantees entryPoint.url
    // is a string; the compiler can't see that discriminated-union guarantee.
    idpEntryPoint: entryPoint.url as string,
    idpCert: connection.saml_idp_cert,
    spEntityId: `${origin}/api/sso/saml/metadata`,
    acsUrl: `${origin}/api/sso/saml/acs`,
    audience: connection.saml_audience || `${origin}/api/sso/saml/metadata`,
  });

  try {
    // RelayState is a transport value, not an authorization input. Bind it to
    // an HMAC-signed, browser-bound server state so ACS cannot be pointed at a
    // different tenant by replacing the form field or query parameter.
    const relayState = signState({
      tenant,
      nonce: crypto.randomBytes(16).toString('base64url'),
    });
    const redirectUrl = await buildLoginUrl(sp, { relayState });
    const res = NextResponse.redirect(redirectUrl, 302);
    // The IdP returns the assertion as a cross-site POST to ACS. SameSite=Lax
    // suppresses this state cookie on that request, turning a valid signed
    // RelayState into an unusable/ambiguous session. None is safe here because
    // the value is HttpOnly, Secure, short-lived, and HMAC-bound to the flow.
    res.cookies.set(SAML_STATE_COOKIE, relayState, {
      httpOnly: true, secure: true, sameSite: 'none', path: '/api/sso/saml', maxAge: 600,
    });
    return res;
  } catch (err) {
    logger.error('[sso/saml/login] build failed:', err);
    return epProblem(500, 'authn_request_failed', 'Could not build the SAML AuthnRequest');
  }
}
