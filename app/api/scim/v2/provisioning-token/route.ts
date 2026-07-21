// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/provisioning-token — mint/list the bearer token an IdP uses to
// reach EP's SCIM endpoints. Authenticated with the customer's EP API key; the
// token is scoped to that entity as the SCIM tenant.

import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId, authEntityOrganizationId } from '@/lib/auth-projections.js';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { generateScimToken, hashScimToken } from '@/lib/scim/auth';
import { readEpJson } from '@/lib/http/route-body';
import { refuseObserveScope } from '@/lib/auth/observe-scope';
import { hasApiPermission } from '@/lib/auth-permissions.js';

const BASE = 'https://www.emiliaprotocol.ai';
const MAX_BODY_BYTES = 32 * 1024;

// readEpJson's inferred return type doesn't discriminate cleanly on `ok`
// (lib/http/route-body.js is still untyped) — pin the real contract here and
// cast at the call site rather than fighting the widened inference.
type ReadEpJsonResult =
  | { ok: true; value: any }
  | { ok: false; response: NextResponse; error?: any };

export async function POST(request: NextRequest): Promise<Response> {
  const auth = await authenticateRequest(request);
  if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
  { const denied = refuseObserveScope(auth, epProblem); if (denied) return denied; }
  if (!hasApiPermission(auth, 'scim.manage')) {
    return epProblem(403, 'insufficient_permissions', 'SCIM token management requires scim.manage or admin permission');
  }
  const tenantId = authEntityId(auth);
  // Confirmed tenant -> protocol-org mapping (#6): the SCIM token provisions into
  // the minting entity's organization. Approvers enroll under this same org, so
  // deprovision revokes exactly this tenant's credentials. (Falls back to
  // tenant_id at revoke time when the entity is not yet org-bound.)
  const organizationId = authEntityOrganizationId(auth);

  const parsed = (await readEpJson(request, MAX_BODY_BYTES, { invalidValue: {} })) as ReadEpJsonResult;
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;
  const label = (body.label || 'IdP provisioning token').toString().slice(0, 120);

  const token = generateScimToken();
  const tokenHash = hashScimToken(token);
  const supabase = getGuardedClient();

  try {
    const { data, error } = await supabase
      .from('scim_provisioning_tokens')
      .insert({ tenant_id: tenantId, organization_id: organizationId, token_hash: tokenHash, token_prefix: token.slice(0, 16), label })
      .select('id, created_at')
      .single();
    if (error || !data) {
      logger.error('[scim/token] mint failed:', error);
      return epProblem(503, 'mint_failed', 'Could not issue provisioning token');
    }

    return Response.json({
      token_id: data.id,
      token, // shown once — never stored in plaintext
      tenant_id: tenantId,
      note: 'Store this token now; it is not retrievable. Configure it as the SCIM bearer token in your IdP.',
      scim_base_url: `${BASE}/api/scim/v2`,
      idp_setup: {
        base_url: `${BASE}/api/scim/v2`,
        authentication: 'OAuth Bearer Token',
        service_provider_config: `${BASE}/api/scim/v2/ServiceProviderConfig`,
        supported: ['Users (CRUD + PATCH)', 'Groups (CRUD + PATCH)', 'filter: eq', 'deprovision via active=false'],
      },
    }, { status: 201 });
  } catch (err) {
    logger.error('[scim/token] mint error:', err);
    return epProblem(500, 'internal_error', 'Could not issue provisioning token');
  }
}

export async function GET(request: NextRequest): Promise<Response> {
  const auth = await authenticateRequest(request);
  if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
  { const denied = refuseObserveScope(auth, epProblem); if (denied) return denied; }
  if (!hasApiPermission(auth, 'scim.manage')) {
    return epProblem(403, 'insufficient_permissions', 'SCIM token management requires scim.manage or admin permission');
  }
  const tenantId = authEntityId(auth);
  const supabase = getGuardedClient();

  try {
    const { data, error } = await supabase
      .from('scim_provisioning_tokens')
      .select('id, token_prefix, label, created_at, last_used_at, revoked_at')
      .eq('tenant_id', tenantId)
      .order('created_at', { ascending: false });
    if (error) return epProblem(503, 'list_failed', 'Could not list tokens');
    return Response.json({ tokens: data || [] });
  } catch (err) {
    logger.error('[scim/token] list error:', err);
    return epProblem(500, 'internal_error', 'Could not list tokens');
  }
}
