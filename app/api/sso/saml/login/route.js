// SPDX-License-Identifier: Apache-2.0
// GET /api/sso/saml/login?tenant=<id> — SP-initiated SAML login.
// Builds the AuthnRequest and 302-redirects to the tenant's IdP, carrying the
// tenant in RelayState so the ACS can pick the right connection.

export const runtime = 'nodejs';

import { NextResponse } from 'next/server';
import { buildSamlSp, buildLoginUrl } from '@/lib/sso/saml';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { validateSsoProviderUrl } from '@/lib/sso/url-policy';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function GET(request) {
  const url = new URL(request.url);
  const tenant = url.searchParams.get('tenant');
  if (!tenant) return epProblem(400, 'missing_tenant', 'tenant query parameter is required');

  const { connection, error } = await loadConnection(tenant, 'saml');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.saml_idp_entry_point || !connection?.saml_idp_cert) {
    return epProblem(404, 'sso_not_configured', `No SAML connection configured for tenant ${tenant}`);
  }
  const entryPoint = validateSsoProviderUrl(connection.saml_idp_entry_point, 'saml_idp_entry_point');
  if (!entryPoint.valid) return epProblem(400, 'unsafe_sso_url', 'Configured SAML IdP URL is not allowed');

  const origin = spOrigin(request);
  const sp = buildSamlSp({
    idpEntryPoint: entryPoint.url,
    idpCert: connection.saml_idp_cert,
    spEntityId: `${origin}/api/sso/saml/metadata`,
    acsUrl: `${origin}/api/sso/saml/acs`,
    audience: connection.saml_audience || `${origin}/api/sso/saml/metadata`,
  });

  try {
    const redirectUrl = await buildLoginUrl(sp, { relayState: tenant });
    return NextResponse.redirect(redirectUrl, 302);
  } catch (err) {
    logger.error('[sso/saml/login] build failed:', err);
    return epProblem(500, 'authn_request_failed', 'Could not build the SAML AuthnRequest');
  }
}
