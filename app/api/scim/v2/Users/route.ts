// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Users — SCIM 2.0 User collection (RFC 7644 §3.4 list, §3.3 create).

import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimUser, fromScimUser, listResponse, parseFilter, etag, validateScimUser,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';
import { recordApproverEligible } from '@/lib/scim/approver-link';
import { isScimAutoApproverEnabled } from '@/lib/env';

// Map SCIM filter attributes to scim_users columns.
const USER_FILTER_COLUMN: Record<string, string> = {
  userName: 'user_name',
  externalId: 'external_id',
  active: 'active',
  id: 'id',
};

type ScimAuthResult =
  | { tenantId: string; organizationId?: string; tokenId: string; response?: undefined }
  | { tenantId?: undefined; organizationId?: undefined; tokenId?: undefined; response: NextResponse };

type ScimUserFilter =
  | { attribute: string; operator: 'eq'; value: string | boolean; unsupported?: undefined; raw?: undefined }
  | { attribute?: undefined; operator?: undefined; value?: undefined; unsupported: true; raw: string };

export async function GET(request: NextRequest): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;

  const url = new URL(request.url);
  const filter = parseFilter(url.searchParams.get('filter')) as ScimUserFilter | null;
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
      const column = USER_FILTER_COLUMN[filter.attribute as string];
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

    const resources = (count === 0 ? [] : (data || [])).map((row: any) => toScimUser(row, base));
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

export async function POST(request: NextRequest): Promise<NextResponse> {
  const auth = (await requireScimAuth(request)) as ScimAuthResult;
  if (auth.response) return auth.response;

  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const validation = validateScimUser(body);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }
  const fields = fromScimUser(body);

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
    if (data.active !== false && isScimAutoApproverEnabled()) {
      await recordApproverEligible(supabase, auth.tenantId, data.user_name);
    }

    const resource = toScimUser(data, base);
    return scimJson(resource, { status: 201, etag: etag(data.version ?? 1) });
  } catch (err) {
    logger.error('[scim/Users] create error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}

function clamp(n: number, lo: number, hi: number): number {
  if (Number.isNaN(n)) return hi;
  return Math.min(hi, Math.max(lo, n));
}
