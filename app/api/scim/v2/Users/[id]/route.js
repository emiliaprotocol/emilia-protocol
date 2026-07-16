// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Users/{id} — SCIM 2.0 User resource (RFC 7644 §3.4.1 get,
// §3.5.1 replace, §3.5.2 patch, §3.6 delete).

import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimUser, fromScimUser, applyPatch, etag, validateScimUser,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';
import { revokeApproverCredentials, recordApproverEligible } from '@/lib/scim/approver-link';
import { isScimAutoApproverEnabled } from '@/lib/env';

async function loadUser(supabase, tenantId, id) {
  const { data, error } = await supabase
    .from('scim_users')
    .select('*')
    .eq('tenant_id', tenantId)
    .eq('id', id)
    .maybeSingle();
  return { data, error };
}

export async function GET(request, { params }) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();

  const { data, error } = await loadUser(supabase, auth.tenantId, id);
  if (error) { logger.error('[scim/Users/:id] get failed:', error); return scimErrorResponse(503, 'Directory unavailable'); }
  if (!data) return scimErrorResponse(404, `User ${id} not found`);

  const resource = toScimUser(data, scimBaseUrl(request));
  return scimJson(resource, { etag: etag(data.version ?? 1) });
}

export async function PUT(request, { params }) {
  const auth = await requireScimAuth(request);
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

  return writeUser(supabase, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function PATCH(request, { params }) {
  const auth = await requireScimAuth(request);
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
  const patched = applyPatch(toScimUser(current, base), body);
  if (patched.error) return scimErrorResponse(patched.error.status, patched.error.detail, patched.error.scimType);

  const validation = validateScimUser(patched.resource);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }
  const fields = fromScimUser(patched.resource);
  return writeUser(supabase, auth.tenantId, auth.organizationId, id, current, fields, request);
}

export async function DELETE(request, { params }) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;
  const { id } = await params;
  const supabase = getGuardedClient();

  const { data: current, error: loadErr } = await loadUser(supabase, auth.tenantId, id);
  if (loadErr) return scimErrorResponse(503, 'Directory unavailable');
  if (!current) return scimErrorResponse(404, `User ${id} not found`);

  const { error } = await supabase.from('scim_users').delete().eq('tenant_id', auth.tenantId).eq('id', id);
  if (error) { logger.error('[scim/Users/:id] delete failed:', error); return scimErrorResponse(503, 'Directory unavailable'); }

  // Hard delete is the strongest deprovision: revoke any live signing
  // credentials for this identity in the same write.
  await revokeApproverCredentials(supabase, auth.tenantId, current.user_name, 'scim_delete', auth.organizationId);
  return new Response(null, { status: 204 });
}

// Shared write path for PUT/PATCH: bump version, persist, return the resource.
async function writeUser(supabase, tenantId, organizationId, id, current, fields, request) {
  const nextVersion = (current.version ?? 1) + 1;
  // Capture the prior active state BEFORE the write — the update mutates the
  // user row, and the linkage decision is about the transition.
  const wasActive = current.active !== false;
  try {
    const { data, error } = await supabase
      .from('scim_users')
      .update({ ...fields, version: nextVersion, updated_at: new Date().toISOString() })
      .eq('tenant_id', tenantId)
      .eq('id', id)
      .select('*')
      .single();

    if (error) {
      if (error.code === '23505') return scimErrorResponse(409, `userName ${fields.user_name} already in use`, 'uniqueness');
      logger.error('[scim/Users/:id] write failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }

    // SCIM → approver linkage. Deprovision (active true→false) revokes every
    // live signing credential for this identity in the same write; offboarding
    // in the IdP removes signing authority in the same sync. Re-activation
    // makes the human eligible to RE-ENROLL — it never resurrects revoked keys.
    const isActive = data.active !== false;
    if (wasActive && !isActive) {
      await revokeApproverCredentials(supabase, tenantId, current.user_name, 'scim_deactivate', organizationId);
    } else if (!wasActive && isActive && isScimAutoApproverEnabled()) {
      // Re-activation grants approver eligibility ONLY when auto-approver is
      // explicitly enabled; otherwise eligibility goes through admin approval so
      // a compromised SCIM token can't mint an approver. (T3) Note: deactivation
      // always revokes, regardless of the flag — fail safe in both directions.
      await recordApproverEligible(supabase, tenantId, data.user_name);
    }

    const resource = toScimUser(data, scimBaseUrl(request));
    return scimJson(resource, { etag: etag(data.version ?? nextVersion) });
  } catch (err) {
    logger.error('[scim/Users/:id] write error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}
