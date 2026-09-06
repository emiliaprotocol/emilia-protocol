// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';

import { readEpJson } from '@/lib/http/route-body';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit';
import { isWorksV0Enabled } from '@/lib/works/env';
import {
  evaluateMarketplaceQualification,
  MARKETPLACE_QUALIFICATION_MAX_BYTES,
  readHostedQualificationConfiguration,
} from '@/lib/works/marketplace-qualification';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const HEADERS = {
  'cache-control': 'no-store, max-age=0',
  'x-content-type-options': 'nosniff',
};

function failure(status: number, reason: string, message: string) {
  return NextResponse.json({
    status: status >= 500 ? 'UNAVAILABLE' : 'INVALID_REQUEST',
    reason, message, result: null, display: null,
  }, { status, headers: HEADERS });
}

/** Public read-only verification. It creates no listing, entitlement or authority. */
export async function POST(request: Request): Promise<NextResponse> {
  if (!isWorksV0Enabled()) return failure(404, 'not_found', 'Not found');

  try {
    const limit = await checkRateLimit(`works-qualification:${getClientIP(request)}`, 'mcp_tool_call', { requireDurable: true });
    if (!limit.allowed) {
      const response = limit.error
        ? failure(503, 'qualification_rate_limit_unavailable', 'The verification service is unavailable. Try again later.')
        : failure(429, 'rate_limited', 'Too many verification requests. Try again later.');
      response.headers.set('retry-after', String(Math.max(1, Number(limit.reset) || 60)));
      return response;
    }
  } catch {
    return failure(503, 'qualification_rate_limit_unavailable', 'The verification service is unavailable. Try again later.');
  }

  if (!/^application\/json(?:\s*;|\s*$)/i.test(request.headers.get('content-type') ?? '')) {
    return failure(415, 'json_required', 'Send a JSON qualification evidence request.');
  }

  try {
    const parsed = await readEpJson(request, MARKETPLACE_QUALIFICATION_MAX_BYTES);
    if (!parsed.ok) {
      // Do not echo parser details or caller-controlled keys from private evidence.
      return failure(parsed.error.status, parsed.error.code, parsed.error.status === 413
        ? 'Keep the complete request below 256 KiB.' : 'Send valid JSON with one scope_id and its evidence.');
    }
    const result = evaluateMarketplaceQualification(parsed.value, readHostedQualificationConfiguration());
    const status = result.status === 'INVALID_REQUEST' ? 400 : result.status === 'UNAVAILABLE' ? 503 : 200;
    return NextResponse.json(result, { status, headers: HEADERS });
  } catch {
    return failure(503, 'qualification_verification_unavailable', 'No qualification result could be established.');
  }
}
