// SPDX-License-Identifier: Apache-2.0
// /api/scim/v2/Groups — SCIM 2.0 Group collection (RFC 7644).

import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import {
  toScimGroup, fromScimGroup, listResponse, parseFilter, etag, validateScimGroup,
} from '@/lib/scim/core';
import { scimJson, scimErrorResponse, requireScimAuth, scimBaseUrl, readScimJson } from '@/lib/scim/http';

const GROUP_FILTER_COLUMN = { displayName: 'display_name', externalId: 'external_id', id: 'id' };

export async function GET(request) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;

  const url = new URL(request.url);
  const filter = parseFilter(url.searchParams.get('filter'));
  if (filter?.unsupported) return scimErrorResponse(400, `Unsupported filter: ${filter.raw}`, 'invalidFilter');

  const startIndex = Math.max(1, parseInt(url.searchParams.get('startIndex') || '1', 10) || 1);
  const count = clamp(parseInt(url.searchParams.get('count') ?? '100', 10), 0, 200);
  const base = scimBaseUrl(request);
  const supabase = getGuardedClient();

  try {
    let query = supabase.from('scim_groups').select('*', { count: 'exact' }).eq('tenant_id', auth.tenantId);
    if (filter) {
      const column = GROUP_FILTER_COLUMN[filter.attribute];
      if (!column) return scimErrorResponse(400, `Unsupported filter attribute: ${filter.attribute}`, 'invalidFilter');
      query = query.eq(column, filter.value);
    }
    query = query.order('created_at', { ascending: true }).range(startIndex - 1, startIndex - 1 + Math.max(count, 1) - 1);

    const { data, count: total, error } = await query;
    if (error) { logger.error('[scim/Groups] list failed:', error); return scimErrorResponse(503, 'Directory unavailable'); }

    const resources = (count === 0 ? [] : (data || [])).map((row) => toScimGroup(row, base));
    return scimJson(listResponse(resources, { totalResults: total ?? resources.length, startIndex, itemsPerPage: resources.length }));
  } catch (err) {
    logger.error('[scim/Groups] list error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}

export async function POST(request) {
  const auth = await requireScimAuth(request);
  if (auth.response) return auth.response;

  const parsed = await readScimJson(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const validation = validateScimGroup(body);
  if (!validation.ok) {
    const { status, detail, scimType } = validation.error;
    return scimErrorResponse(status, detail, scimType);
  }
  const fields = fromScimGroup(body);

  const supabase = getGuardedClient();
  try {
    const { data, error } = await supabase
      .from('scim_groups')
      .insert({ ...fields, tenant_id: auth.tenantId })
      .select('*')
      .single();
    if (error) {
      if (error.code === '23505') return scimErrorResponse(409, `Group ${fields.display_name} already exists`, 'uniqueness');
      logger.error('[scim/Groups] create failed:', error);
      return scimErrorResponse(503, 'Directory unavailable');
    }
    return scimJson(toScimGroup(data, scimBaseUrl(request)), { status: 201, etag: etag(data.version ?? 1) });
  } catch (err) {
    logger.error('[scim/Groups] create error:', err);
    return scimErrorResponse(500, 'Internal error');
  }
}

function clamp(n, lo, hi) { if (Number.isNaN(n)) return hi; return Math.min(hi, Math.max(lo, n)); }
