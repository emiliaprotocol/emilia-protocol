// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Users/{id} — SCIM 2.0 User resource (RFC 7644 §3.4.1 get,
// §3.5.1 replace, §3.5.2 patch, §3.6 delete).

import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimUser, fromScimUser, applyPatch, etag, validateScimUser,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';
import { recordApproverEligible } from '@/lib/scim/approver-link';
import { isScimAutoApproverEnabled } from '@/lib/env';

type ScimAuthResult = {
  response?: NextResponse;
  tenantId?: string;
  organizationId?: string;
  tokenId?: string;
};

type ScimPatchResult = {
  error?: { status: any; detail: any; scimType: any };
  resource?: any;
};

type RouteParams = { params: Promise<{ id: string }> };

async function loadUser(supabase: any, tenantId: string | undefined, id: string) {
  const { data, error } = await supabase
    .from('scim_users')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('id', id)
    .maybeSingle();
  return { data, error };
}

export async function GET(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();

  const { data, error } = await loadUser(supabase, auth.tenantId, id);
  if (error) { logger.error('[scim/Users/:id] get failed:', error); return scimErrorResponse(503, 'Directory unavailable'); }
  if (!data) return scimErrorResponse(404, `User ${id} not found`);

  const resource = toScimUser(data, scimBaseUrl(request));
  return scimJson(resource, { etag: etag(data.version ?? 1) });
}

export async function PUT(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;

  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const validation = validateScimUser(body);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }

  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadUser(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `User ${id} not found`);

  const fields = fromScimUser(body);

  return writeUser(supabase, auth.tokenId, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function PATCH(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;

  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadUser(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `User ${id} not found`);

  // Patch in SCIM space, then map back to columns.
  const base = scimBaseUrl(request);
  const patched = applyPatch(toScimUser(current, base), body) as ScimPatchResult;
  if (patched.error) return scimErrorResponse(patched.error.status, patched.error.detail, patched.error.scimType);

  const validation = validateScimUser(patched.resource);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }
  const fields = fromScimUser(patched.resource);
  return writeUser(supabase, auth.tokenId, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function DELETE(request: NextRequest, { params }: RouteParams): Promise<Response> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();

  const { data: current, error: loadErr } = await loadUser(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `User ${id} not found`);

  const { data, error } = await supabase.rpc('apply_scim_user_and_authority_atomic', {
    p_token_id: auth.tokenId,
    p_tenant_id: auth.tenantId,
    p_organization_id: auth.organizationId ?? null,
    p_user_id: id,
    p_expected_version: current.version ?? 1,
    p_fields: {},
    p_delete: true,
    p_reason: 'scim_delete',
  });
  if (error) { logger.error('[scim/Users/:id] atomic delete failed:', error); return scimErrorResponse(503, 'Directory unavailable'); }
  if (data?.error === 'user_not_found') return scimErrorResponse(404, `User ${id} not found`);
  if (data?.error === 'version_conflict') return scimErrorResponse(409, 'User changed during deprovision', 'mutability');
  if (data?.error === 'token_authority_invalid') return scimErrorResponse(401, 'SCIM token is no longer authorized');
  if (data?.status !== 'deleted') return scimErrorResponse(503, 'Directory unavailable');
  return new Response(null, { status: 204 });
}

// Shared write path for PUT/PATCH: bump version, persist, return the resource.
async function writeUser(
  supabase: any,
  tokenId: string | undefined,
  tenantId: string | undefined,
  organizationId: string | undefined,
  id: string,
  current: any,
  fields: any,
  request: NextRequest,
): Promise<NextResponse> {
  // Capture the prior active state BEFORE the write — the update mutates the
  // user row, and the linkage decision is about the transition.
  const wasActive = current.active !== false;
  try {
    const { data: result, error } = await supabase.rpc('apply_scim_user_and_authority_atomic', {
      p_token_id: tokenId,
      p_tenant_id: tenantId,
      p_organization_id: organizationId ?? null,
      p_user_id: id,
      p_expected_version: current.version ?? 1,
      p_fields: fields,
      p_delete: false,
      p_reason: 'scim_deactivate',
    });

    if (error) {
      if (error.code === '23505') return scimErrorResponse(409, `userName ${fields.user_name} already in use`, 'uniqueness');
      logger.error('[scim/Users/:id] write failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }
    if (result?.error === 'user_not_found') return scimErrorResponse(404, `User ${id} not found`);
    if (result?.error === 'version_conflict') return scimErrorResponse(409, 'User changed during update', 'mutability');
    if (result?.error === 'token_authority_invalid') return scimErrorResponse(401, 'SCIM token is no longer authorized');
    const data = result?.user;
    if (result?.status !== 'updated' || !data) return scimErrorResponse(503, 'Directory unavailable');

    // Deprovision and credential revocation were committed atomically by the
    // RPC. Re-activation makes the human eligible to RE-ENROLL; it never
    // resurrects revoked keys.
    const isActive = data.active !== false;
    if (!wasActive && isActive && isScimAutoApproverEnabled()) {
      // Re-activation grants approver eligibility ONLY when auto-approver is
      // explicitly enabled; otherwise eligibility goes through admin approval so
      // a compromised SCIM token can't mint an approver. (T3) Note: deactivation
      // always revokes, regardless of the flag — fail safe in both directions.
      await recordApproverEligible(supabase, tenantId, data.user_name);
    }

    const resource = toScimUser(data, scimBaseUrl(request));
    return scimJson(resource, { etag: etag(data.version ?? ((current.version ?? 1) + 1)) });
  } catch (err) {
    logger.error('[scim/Users/:id] write error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}
