// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Groups/{id} — SCIM 2.0 Group resource (RFC 7644).

import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import { toScimGroup, fromScimGroup, applyPatch, etag } from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';

async function loadGroup(supabase, tenantId, id) {
  return supabase.from('scim_groups').select('*').eq('tenant_id', tenantId).eq('id', id).maybeSingle();
}

export async function GET(request, { params }) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;
  const { id } = await params;
  const { data, error } = await loadGroup(getGuardedClient(), auth.tenantId, id);
  if (error) return scimErrorResponse(503, 'Directory unavailable');
  if (!data) return scimErrorResponse(404, `Group ${id} not found`);
  return scimJson(toScimGroup(data, scimBaseUrl(request)), { etag: etag(data.version ?? 1) });
}

export async function PUT(request, { params }) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;
  const { id } = await params;
  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadGroup(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `Group ${id} not found`);

  const fields = fromScimGroup(body);
  if (!fields.display_name) return scimErrorResponse(400, 'displayName is required', 'invalidValue');
  return writeGroup(supabase, auth.tenantId, id, current, fields, request);
}

export async function PATCH(request, { params }) {
  const auth = await requireScimAuth(request);
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
  const patched = applyPatch(toScimGroup(current, base), body);
  if (patched.error) return scimErrorResponse(patched.error.status, patched.error.detail, patched.error.scimType);

  const fields = fromScimGroup(patched.resource);
  return writeGroup(supabase, auth.tenantId, id, current, fields, request);
}

export async function DELETE(request, { params }) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();
  const { data: current, error: loadErr } = await loadGroup(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `Group ${id} not found`);

  const { error } = await supabase.from('scim_groups').delete().eq('tenant_id', auth.tenantId).eq('id', id);
  if (error) return scimErrorResponse(503, 'Directory unavailable');
  return new Response(null, { status: 204 });
}

async function writeGroup(supabase, tenantId, id, current, fields, request) {
  const nextVersion = (current.version ?? 1) + 1;
  try {
    const { data, error } = await supabase
      .from('scim_groups')
      .update({ ...fields, version: nextVersion, updated_at: new Date().toISOString() })
      .eq('tenant_id', tenantId).eq('id', id).select('*').single();
    if (error) {
      if (error.code === '23505') return scimErrorResponse(409, `displayName ${fields.display_name} already in use`, 'uniqueness');
      logger.error('[scim/Groups/:id] write failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }
    return scimJson(toScimGroup(data, scimBaseUrl(request)), { etag: etag(data.version ?? nextVersion) });
  } catch (err) {
    logger.error('[scim/Groups/:id] write error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}
