// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Users — SCIM 2.0 User collection (RFC 7644 §3.4 list, §3.3 create).

import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimUser, fromScimUser, listResponse, parseFilter, etag,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl } from '@/lib/scim/http';
import { recordApproverEligible } from '@/lib/scim/approver-link';

// Map SCIM filter attributes to scim_users columns.
const USER_FILTER_COLUMN = {
  userName: 'user_name',
  externalId: 'external_id',
  active: 'active',
  id: 'id',
};

export async function GET(request) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;

  const url = new URL(request.url);
  const filter = parseFilter(url.searchParams.get('filter'));
  if (filter?.unsupported) {
    return scimErrorResponse(400, `Unsupported filter: ${filter.raw}`, 'invalidFilter');
  }

  const startIndex = Math.max(1, parseInt(url.searchParams.get('startIndex') || '1', 10) || 1);
  const count = clamp(parseInt(url.searchParams.get('count') ?? '100', 10), 0, 200);

  const base = scimBaseUrl(request);
  const supabase = getGuardedClient();

  try {
    let query = supabase
      .from('scim_users')
      .select('*', { count: 'exact' })
      .eq('tenant_id', auth.tenantId);

    if (filter) {
      const column = USER_FILTER_COLUMN[filter.attribute];
      if (!column) return scimErrorResponse(400, `Unsupported filter attribute: ${filter.attribute}`, 'invalidFilter');
      query = query.eq(column, filter.value);
    }

    // SCIM startIndex is 1-based and inclusive.
    query = query.order('created_at', { ascending: true }).range(startIndex - 1, startIndex - 1 + Math.max(count, 1) - 1);

    const { data, count: total, error } = await query;
    if (error) {
      logger.error('[scim/Users] list failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }

    const resources = (count === 0 ? [] : (data || [])).map((row) => toScimUser(row, base));
    return scimJson(listResponse(resources, {
      totalResults: total ?? resources.length,
      startIndex,
      itemsPerPage: resources.length,
    }));
  } catch (err) {
    logger.error('[scim/Users] list error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}

export async function POST(request) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;

  let body;
  try {
    body = await request.json();
  } catch {
    return scimErrorResponse(400, 'Request body must be valid JSON', 'invalidSyntax');
  }

  const fields = fromScimUser(body);
  if (!fields.user_name) {
    return scimErrorResponse(400, 'userName is required', 'invalidValue');
  }

  const base = scimBaseUrl(request);
  const supabase = getGuardedClient();

  try {
    const { data, error } = await supabase
      .from('scim_users')
      .insert({ ...fields, tenant_id: auth.tenantId })
      .select('*')
      .single();

    if (error) {
      // 23505 = unique_violation → SCIM uniqueness error (409).
      if (error.code === '23505') {
        return scimErrorResponse(409, `User ${fields.user_name} already exists`, 'uniqueness');
      }
      logger.error('[scim/Users] create failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }

    // SCIM → approver linkage. Approver eligibility is NOT granted automatically
    // from directory provisioning by default: a compromised SCIM token must not
    // be able to mint an approver who can enroll a signing passkey and approve
    // actions. Opt in explicitly with EP_SCIM_AUTO_APPROVER=true; otherwise
    // eligibility is established through the admin approval path. (T3)
    if (data.active !== false && process.env.EP_SCIM_AUTO_APPROVER === 'true') {
      await recordApproverEligible(supabase, auth.tenantId, data.user_name);
    }

    const resource = toScimUser(data, base);
    return scimJson(resource, { status: 201, etag: etag(data.version ?? 1) });
  } catch (err) {
    logger.error('[scim/Users] create error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}

function clamp(n, lo, hi) {
  if (Number.isNaN(n)) return hi;
  return Math.min(hi, Math.max(lo, n));
}
