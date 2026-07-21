// SPDX-License-Identifier: Apache-2.0
// /api/sso/connections — configure (POST) or list (GET) a tenant's SSO.
// Gated by the customer's EP API key; tenant = the authenticated entity.

export const runtime = 'nodejs';

import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { upsertConnection, listConnections, spOrigin } from '@/lib/sso/config';
import { validateOidcRedirectUri, validateSsoProviderUrl } from '@/lib/sso/url-policy';
import { seal } from '@/lib/crypto/secret-box';
import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';
import { refuseObserveScope } from '@/lib/auth/observe-scope';
import { hasApiPermission } from '@/lib/auth-permissions.js';

const MAX_BODY_BYTES = 256 * 1024;

export async function POST(request: NextRequest): Promise<Response> {
  const auth = await authenticateRequest(request);
  if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
  { const denied = refuseObserveScope(auth, epProblem); if (denied) return denied; }
  if (!hasApiPermission(auth, 'sso.manage')) {
    return epProblem(403, 'insufficient_permissions', 'SSO configuration requires sso.manage or admin permission');
  }
  const tenant = authEntityId(auth as any);

  // readEpJson's own return type is presently inferred (its source module has
  // not been given explicit type annotations yet), which loses the
  // `ok`-discriminated union shape its JSDoc has always documented. Pin the
  // real, unchanged contract here so this call site narrows correctly.
  const parsed = (await readEpJson(request, MAX_BODY_BYTES, undefined)) as
    | { ok: false; response: NextResponse; error: any }
    | { ok: true; value: any };
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const protocol = body.protocol;
  if (!['saml', 'oidc'].includes(protocol)) {
    return epProblem(400, 'invalid_protocol', "protocol must be 'saml' or 'oidc'");
  }

  let fields;
  if (protocol === 'saml') {
    if (!body.saml_idp_entry_point || !body.saml_idp_cert) {
      return epProblem(400, 'missing_saml_fields', 'saml_idp_entry_point and saml_idp_cert are required');
    }
    const entryPoint = await validateSsoProviderUrl(body.saml_idp_entry_point, 'saml_idp_entry_point');
    if (!entryPoint.valid) {
      return epProblem(400, 'unsafe_sso_url', entryPoint.error);
    }
    fields = {
      saml_idp_entry_point: entryPoint.url,
      saml_idp_cert: normalizeCert(body.saml_idp_cert),
      saml_audience: body.saml_audience || null,
      enabled: body.enabled !== false,
    };
  } else {
    if (!body.oidc_issuer || !body.oidc_client_id) {
      return epProblem(400, 'missing_oidc_fields', 'oidc_issuer and oidc_client_id are required');
    }
    const issuer = await validateSsoProviderUrl(body.oidc_issuer, 'oidc_issuer');
    if (!issuer.valid) {
      return epProblem(400, 'unsafe_sso_url', issuer.error);
    }
    const redirectUri = validateOidcRedirectUri(body.oidc_redirect_uri, spOrigin(request));
    if (!redirectUri.valid) {
      return epProblem(400, 'unsafe_oidc_redirect_uri', redirectUri.error);
    }
    fields = {
      oidc_issuer: issuer.url,
      oidc_client_id: body.oidc_client_id,
      // Sealed at rest (AES-256-GCM, lib/crypto/secret-box); decrypted only at
      // token-exchange time in loadConnection.
      oidc_client_secret: body.oidc_client_secret ? seal(body.oidc_client_secret) : null,
      oidc_redirect_uri: redirectUri.url,
      enabled: body.enabled !== false,
    };
  }

  const { connection, error } = await upsertConnection(tenant, protocol, fields);
  if (error) {
    logger.error('[sso/connections] upsert failed:', error);
    return epProblem(503, 'config_write_failed', 'Could not save SSO connection');
  }
  return Response.json({ connection }, { status: 201 });
}

export async function GET(request: NextRequest): Promise<Response> {
  const auth = await authenticateRequest(request);
  if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
  { const denied = refuseObserveScope(auth, epProblem); if (denied) return denied; }
  if (!hasApiPermission(auth, 'sso.read') && !hasApiPermission(auth, 'sso.manage')) {
    return epProblem(403, 'insufficient_permissions', 'SSO configuration requires sso.read, sso.manage, or admin permission');
  }
  const tenant = authEntityId(auth as any);
  const { connections, error } = await listConnections(tenant);
  if (error) return epProblem(503, 'config_read_failed', 'Could not list SSO connections');
  return Response.json({ connections });
}

// Accept a cert with or without PEM armor / whitespace; store the bare body.
function normalizeCert(cert: any): string {
  return String(cert).replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
}
