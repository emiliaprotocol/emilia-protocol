// SPDX-License-Identifier: Apache-2.0
// POST /api/sso/saml/acs — Assertion Consumer Service.
// Validates the signed SAML Response against the tenant's configured IdP cert,
// then resolves the asserted identity against the SCIM-provisioned directory.
// The signature/conditions/audience checks are done by node-saml (xml-crypto).

export const runtime = 'nodejs';

import { getGuardedClient } from '@/lib/write-guard';
import { buildSamlSp, validateSamlResponse } from '@/lib/sso/saml';
import { loadConnection, spOrigin } from '@/lib/sso/config';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function POST(request) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return epProblem(400, 'invalid_acs_post', 'Expected an application/x-www-form-urlencoded SAML POST');
  }
  const samlResponse = form.get('SAMLResponse');
  const tenant = form.get('RelayState') || new URL(request.url).searchParams.get('tenant');
  if (!samlResponse) return epProblem(400, 'missing_saml_response', 'SAMLResponse is required');
  if (!tenant) return epProblem(400, 'missing_tenant', 'RelayState (tenant) is required');

  const { connection, error } = await loadConnection(tenant, 'saml');
  if (error) return epProblem(503, 'config_unavailable', 'Could not load SSO config');
  if (!connection?.saml_idp_cert) {
    return epProblem(404, 'sso_not_configured', `No SAML connection configured for tenant ${tenant}`);
  }

  const origin = spOrigin(request);
  const sp = buildSamlSp({
    idpEntryPoint: connection.saml_idp_entry_point,
    idpCert: connection.saml_idp_cert,
    spEntityId: `${origin}/api/sso/saml/metadata`,
    acsUrl: `${origin}/api/sso/saml/acs`,
    audience: connection.saml_audience || `${origin}/api/sso/saml/metadata`,
  });

  const result = await validateSamlResponse(sp, String(samlResponse));
  if (!result.valid) {
    // A failed signature/conditions/audience check MUST NOT authenticate.
    logger.warn('[sso/saml/acs] rejected:', result.error);
    return epProblem(401, 'saml_validation_failed', result.error || 'SAML assertion did not validate');
  }

  const identity = await resolveDirectory(tenant, result.profile);
  return Response.json({
    authenticated: true,
    protocol: 'saml',
    tenant,
    identity: { nameID: result.profile.nameID, email: result.profile.email },
    directory: identity,
  });
}

// Link the asserted identity to the SCIM-provisioned directory: is this a known,
// currently-active approver? (No JIT write — a deactivated/absent user is
// surfaced, not silently created.)
async function resolveDirectory(tenant, profile) {
  try {
    const supabase = getGuardedClient();
    const { data } = await supabase
      .from('scim_users')
      .select('id, active, display_name')
      .eq('tenant_id', tenant)
      .eq('user_name', profile.email || profile.nameID)
      .maybeSingle();
    if (!data) return { matched: false, active: false };
    return { matched: true, active: data.active !== false, user_id: data.id };
  } catch {
    return { matched: false, active: false, error: 'directory_lookup_failed' };
  }
}
