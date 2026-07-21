import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors';

/**
 * GET /api/score/[entityId]/history — RETIRED (HTTP 410 Gone).
 *
 * The compatibility-score history endpoint has been retired along with the
 * 0-100 score itself. EMILIA publishes verifiable evidence, not a reputation
 * score tracked over time. For current trust state use
 * GET /api/trust/profile/:entityId; for an entity's receipts, verify them at
 * /verify or via @emilia-protocol/verify.
 */
export async function GET(): Promise<NextResponse> {
  return epProblem(
    410,
    'endpoint_retired',
    'The score-history endpoint has been retired. EMILIA publishes verifiable evidence, not a tracked score. Use GET /api/trust/profile/:entityId.',
  );
}
