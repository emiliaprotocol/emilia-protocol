// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '@/lib/logger.js';
import { ArenaServiceError, submitArenaAttempt } from '@/lib/arena/service';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 8 * 1024;

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> | { sessionId: string } },
): Promise<NextResponse> {
  try {
    const parsed: any = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const { sessionId } = await context.params;
    const attempt = await submitArenaAttempt({ request, sessionId, input: parsed.value });
    return NextResponse.json(attempt, {
      status: 201,
      headers: { 'Cache-Control': 'no-store, max-age=0', 'Referrer-Policy': 'no-referrer' },
    });
  } catch (error) {
    if (error instanceof ArenaServiceError) return epProblem(error.status, error.code, error.message);
    logger.error('[arena] attempt failed', { kind: 'arena_attempt_failed' });
    return epProblem(503, 'arena_unavailable', 'Arena is temporarily unavailable');
  }
}
