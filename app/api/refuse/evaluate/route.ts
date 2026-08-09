// SPDX-License-Identifier: Apache-2.0
//
// POST /api/refuse/evaluate — Watch It Refuse public demo evaluation.
//
// Runs the real EMILIA evaluation (CAID computation, evidence sufficiency,
// gate refusal, and — on the demo-approval path — the full receipt lifecycle
// including one-time consumption) over synthetic demo artifacts. No action is
// ever executed. 404 unless WATCH_IT_REFUSE=1. Rate-limited via the
// middleware ROUTE_POLICIES 'submit' category (IP-keyed; no credential).

import { NextRequest, NextResponse } from 'next/server';

import { isWatchItRefuseEnabled } from '@/lib/env';
import { epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '@/lib/logger.js';
import { WirInputError, evaluateWatchItRefuse } from '@/lib/watch-it-refuse/evaluate';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 4 * 1024;

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!isWatchItRefuseEnabled()) {
    return epProblem(404, 'not_found', 'Not found');
  }
  try {
    const parsed: any = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return epProblem(400, 'refuse_input_invalid', 'body must be a JSON object with a "text" field');
    }
    const allowedKeys = new Set(['text', 'approve']);
    if (Reflect.ownKeys(body).some((key) => typeof key !== 'string' || !allowedKeys.has(key))) {
      return epProblem(400, 'refuse_input_invalid', 'body accepts only "text" and "approve"');
    }
    if (body.approve !== undefined && typeof body.approve !== 'boolean') {
      return epProblem(400, 'refuse_input_invalid', 'approve must be a boolean');
    }
    const result = await evaluateWatchItRefuse({
      text: body.text,
      approve: body.approve === true,
    });
    return NextResponse.json(result, {
      status: 200,
      headers: { 'Cache-Control': 'no-store, max-age=0' },
    });
  } catch (error) {
    if (error instanceof WirInputError) {
      return epProblem(error.status, error.code, error.message);
    }
    logger.error('[watch-it-refuse] evaluation failed', { kind: 'wir_evaluate_failed' });
    return epProblem(500, 'refuse_evaluation_failed', 'Evaluation is temporarily unavailable');
  }
}
