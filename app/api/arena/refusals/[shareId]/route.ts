// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { ArenaServiceError, loadPublicArenaRefusal } from '@/lib/arena/service';

export const dynamic = 'force-dynamic';

export async function GET(
  _request: Request,
  context: { params: Promise<{ shareId: string }> | { shareId: string } },
): Promise<NextResponse> {
  try {
    const { shareId } = await context.params;
    const result = await loadPublicArenaRefusal(shareId);
    if (!result) return epProblem(404, 'arena_refusal_not_found', 'Arena refusal not found');
    return NextResponse.json(result, {
      headers: {
        'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    if (error instanceof ArenaServiceError) return epProblem(error.status, error.code, error.message);
    logger.error('[arena] public refusal load failed', { kind: 'arena_refusal_load_failed' });
    return epProblem(503, 'arena_unavailable', 'Arena is temporarily unavailable');
  }
}
