// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { ArenaServiceError, loadPublicArenaRefusal } from '@/lib/arena/service';

export const dynamic = 'force-dynamic';

const CURRENT_STATUS_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, max-age=0',
  Pragma: 'no-cache',
  Expires: '0',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
});

function currentStatusResponse(response: NextResponse): NextResponse {
  for (const [key, value] of Object.entries(CURRENT_STATUS_HEADERS)) response.headers.set(key, value);
  return response;
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ shareId: string }> | { shareId: string } },
): Promise<NextResponse> {
  try {
    const { shareId } = await context.params;
    const result = await loadPublicArenaRefusal(shareId);
    if (!result) {
      return currentStatusResponse(epProblem(404, 'arena_refusal_not_found', 'Arena refusal not found'));
    }
    return NextResponse.json(result, { headers: CURRENT_STATUS_HEADERS });
  } catch (error) {
    if (error instanceof ArenaServiceError) {
      return currentStatusResponse(epProblem(error.status, error.code, error.message));
    }
    logger.error('[arena] public refusal load failed', { kind: 'arena_refusal_load_failed' });
    return currentStatusResponse(epProblem(503, 'arena_unavailable', 'Arena is temporarily unavailable'));
  }
}
