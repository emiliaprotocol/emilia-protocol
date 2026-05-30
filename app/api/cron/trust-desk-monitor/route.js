/**
 * GET /api/cron/trust-desk-monitor
 *
 * @license Apache-2.0
 * @internal
 * @access cron — requires operator auth (CRON_SECRET or per-operator token).
 *
 * Scans published trust pages and emails customers a refresh notice when a page
 * crosses into "expiring" (30 days out) or "stale" (past expiry). Idempotent
 * per status transition. Wired in vercel.json to run daily.
 */

import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors';
import { authenticateOperator } from '@/lib/operator-auth';
import { runMonitor } from '@/lib/trust-desk/monitor';
import { logger } from '@/lib/logger';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request) {
  const auth = authenticateOperator(request);
  if (!auth.valid) {
    return epProblem(401, 'unauthorized', auth.error || 'Unauthorized');
  }
  try {
    const result = await runMonitor();
    return NextResponse.json({ ok: true, ...result });
  } catch (err) {
    logger.error('trust-desk monitor cron: failed', { error: err.message });
    return epProblem(500, 'monitor_error', 'monitor pass failed');
  }
}
