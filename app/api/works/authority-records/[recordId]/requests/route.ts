// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { sendAuthorityDemandVerificationEmail } from '@/lib/works/demand-email';
import {
  createAuthorityRecordDemandRequest,
  DemandServiceError,
  readAuthorityRecordDemandCounts,
} from '@/lib/works/demand-service';
import { createSupabaseAuthorityDemandStore } from '@/lib/works/demand-store';
import { isWorksV0Enabled } from '@/lib/works/env';

type Context = { params: Promise<{ recordId: string }> };
const HEADERS = { 'cache-control': 'no-store, max-age=0', 'x-content-type-options': 'nosniff' };

function unavailable() {
  return epProblem(404, 'not_found', 'Not found');
}

function failure(error: unknown) {
  return error instanceof DemandServiceError
    ? epProblem(error.status, error.code, error.message)
    : epProblem(500, 'authority_demand_internal_error', 'Request failed.');
}

export async function POST(request: NextRequest, { params }: Context) {
  if (!isWorksV0Enabled()) return unavailable();
  try {
    const parsed = await readEpJson(request, 4096);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as Record<string, unknown>;
    const { recordId } = await params;
    await createAuthorityRecordDemandRequest({
      input: { record_id: recordId, email: body.email },
      store: createSupabaseAuthorityDemandStore(),
      hmacKey: process.env.WORKS_DEMAND_HMAC_KEY || '',
      siteOrigin: new URL(request.url).origin,
      sendEmail: sendAuthorityDemandVerificationEmail,
    });
    return Response.json({ accepted: true }, { status: 202, headers: HEADERS });
  } catch (error) {
    return failure(error);
  }
}

export async function GET(_request: NextRequest, { params }: Context) {
  if (!isWorksV0Enabled()) return unavailable();
  try {
    const { recordId } = await params;
    const counts = await readAuthorityRecordDemandCounts({
      recordId, store: createSupabaseAuthorityDemandStore(),
    });
    return Response.json(counts, { headers: HEADERS });
  } catch (error) {
    return failure(error);
  }
}
