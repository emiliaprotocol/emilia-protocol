// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { DemandServiceError, verifyAuthorityRecordDemandRequest } from '@/lib/works/demand-service';
import { createSupabaseAuthorityDemandStore } from '@/lib/works/demand-store';
import { isWorksV0Enabled } from '@/lib/works/env';

const HEADERS = { 'cache-control': 'no-store, max-age=0', 'x-content-type-options': 'nosniff' };

export async function POST(request: NextRequest) {
  if (!isWorksV0Enabled()) return epProblem(404, 'not_found', 'Not found');
  try {
    const parsed = await readEpJson(request, 4096);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as Record<string, unknown>;
    const result = await verifyAuthorityRecordDemandRequest({
      token: body.token,
      store: createSupabaseAuthorityDemandStore(),
    });
    return Response.json(result, { headers: HEADERS });
  } catch (error) {
    return error instanceof DemandServiceError
      ? epProblem(error.status, error.code, error.message)
      : epProblem(500, 'authority_demand_internal_error', 'Verification failed.');
  }
}
