// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Groups/{id} — SCIM 2.0 Group resource (RFC 7644).

import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimGroup, fromScimGroup, applyPatch, etag, validateScimGroup,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';

type ScimAuthResult =
  | { tenantId: string; organizationId?: string; tokenId: string; response?: undefined }
  | { response: NextResponse; tenantId?: undefined; organizationId?: undefined; tokenId?: undefined };

type ScimPatchResult =
  | { resource: any; error?: undefined }
  | { error: { status: any; detail: any; scimType: any }; resource?: undefined };

type RouteParams = { params: Promise<{ id: string }> };

async function loadGroup(supabase: any, tenantId: string | undefined, id: string) {
  return supabase.from('scim_groups').select('*').eq('tenant_id', tenantId).eq('id', id).maybeSingle();
}

export async function GET(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const { data, error } = await loadGroup(getGuardedClient(), auth.tenantId, id);
  if (error) return scimErrorResponse(503, 'Directory unavailable');
  if (!data) return scimErrorResponse(404, `Group ${id} not found`);
  return scimJson(toScimGroup(data, scimBaseUrl(request)), { etag: etag(data.version ?? 1) });
}

export async function PUT(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const validation = validateScimGroup(body);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }

  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadGroup(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `Group ${id} not found`);

  const fields = fromScimGroup(body);
  return writeGroup(supabase, auth.tokenId, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function PATCH(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadGroup(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `Group ${id} not found`);

  const base = scimBaseUrl(request);
  const patched = applyPatch(toScimGroup(current, base), body) as ScimPatchResult;
  if (patched.error) return scimErrorResponse(patched.error.status, patched.error.detail, patched.error.scimType);

  const validation = validateScimGroup(patched.resource);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }
  const fields = fromScimGroup(patched.resource);
  return writeGroup(supabase, auth.tokenId, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function DELETE(request: NextRequest, { params }: RouteParams): Promise<Response> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadGroup(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `Group ${id} not found`);

  const { data: result, error } = await supabase.rpc('apply_scim_group_authorized', {
    p_token_id: auth.tokenId,
    p_tenant_id: auth.tenantId,
    p_organization_id: auth.organizationId,
    p_group_id: id,
    p_expected_version: current.version ?? 1,
    p_fields: {},
    p_delete: true,
  });
  if (error) return scimErrorResponse(503, 'Directory unavailable');
  if (result?.error === 'token_authority_invalid') return scimErrorResponse(401, 'SCIM token is no longer authorized');
  if (result?.error === 'group_not_found') return scimErrorResponse(404, `Group ${id} not found`);
  if (result?.error === 'version_conflict') return scimErrorResponse(409, 'Group changed during delete', 'mutability');
  if (result?.status !== 'deleted') return scimErrorResponse(503, 'Directory unavailable');
  return new Response(null, { status: 204 });
}

async function writeGroup(
  supabase: any,
  tokenId: string,
  tenantId: string | undefined,
  organizationId: string | undefined,
  id: string,
  current: any,
  fields: any,
  request: NextRequest,
): Promise<NextResponse> {
  const nextVersion = (current.version ?? 1) + 1;
  try {
    const { data: result, error } = await supabase.rpc('apply_scim_group_authorized', {
      p_token_id: tokenId,
      p_tenant_id: tenantId,
      p_organization_id: organizationId,
      p_group_id: id,
      p_expected_version: current.version ?? 1,
      p_fields: fields,
      p_delete: false,
    });
    if (error) {
      if (error.code === '23505') return scimErrorResponse(409, `displayName ${fields.display_name} already in use`, 'uniqueness');
      logger.error('[scim/Groups/:id] write failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }
    if (result?.error === 'token_authority_invalid') return scimErrorResponse(401, 'SCIM token is no longer authorized');
    if (result?.error === 'group_not_found') return scimErrorResponse(404, `Group ${id} not found`);
    if (result?.error === 'version_conflict') return scimErrorResponse(409, 'Group changed during update', 'mutability');
    const data = result?.group;
    if (result?.status !== 'updated' || !data) return scimErrorResponse(503, 'Directory unavailable');
    return scimJson(toScimGroup(data, scimBaseUrl(request)), { etag: etag(data.version ?? nextVersion) });
  } catch (err) {
    logger.error('[scim/Groups/:id] write error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}
