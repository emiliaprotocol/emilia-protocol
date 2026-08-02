// SPDX-License-Identifier: Apache-2.0
import { NextRequest, NextResponse } from 'next/server';

import { epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '@/lib/logger.js';
import { ArenaServiceError, provisionArenaSession } from '@/lib/arena/service';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 4 * 1024;

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const parsed: any = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || Reflect.ownKeys(body).length !== 1
        || Reflect.ownKeys(body).some((key) => key !== 'agent_name')
        || typeof body.agent_name !== 'string'
        || body.agent_name.trim().length < 1
        || body.agent_name.trim().length > 64) {
      return epProblem(400, 'arena_session_input_invalid', 'agent_name is required');
    }
    const session = await provisionArenaSession({ agentName: body.agent_name });
    return NextResponse.json(session, {
      status: 201,
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        Pragma: 'no-cache',
        'Referrer-Policy': 'no-referrer',
      },
    });
  } catch (error) {
    if (error instanceof ArenaServiceError) return epProblem(error.status, error.code, error.message);
    logger.error('[arena] session provisioning failed', { kind: 'arena_session_provision_failed' });
    return epProblem(503, 'arena_unavailable', 'Arena is temporarily unavailable');
  }
}
