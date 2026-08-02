// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { ArenaServiceError, publishArenaRefusal } from '@/lib/arena/service';

export const dynamic = 'force-dynamic';

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string; attemptId: string }> | { sessionId: string; attemptId: string } },
): Promise<NextResponse> {
  try {
    const { sessionId, attemptId } = await context.params;
    const published = await publishArenaRefusal({ request, sessionId, attemptId });
    return NextResponse.json(published, {
      status: 201,
      headers: { 'Cache-Control': 'no-store, max-age=0', 'Referrer-Policy': 'no-referrer' },
    });
  } catch (error) {
    if (error instanceof ArenaServiceError) return epProblem(error.status, error.code, error.message);
    logger.error('[arena] publication failed', { kind: 'arena_publication_failed' });
    return epProblem(503, 'arena_unavailable', 'Arena is temporarily unavailable');
  }
}
