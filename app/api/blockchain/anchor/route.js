import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { runAnchorBatch } from '@/lib/blockchain';
import { epProblem } from '@/lib/errors';
import { authenticateOperator } from '@/lib/operator-auth';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/blockchain/anchor
 *
 * @internal
 * @access cron — requires operator token or CRON_SECRET (legacy).
 *
 * Cron endpoint: collects unanchored receipts, builds Merkle tree,
 * anchors root to Base L2. Called every 6 hours via Vercel Cron.
 * Auth: Per-operator token (ep_op_*) or legacy CRON_SECRET.
 * Vercel cron config: see vercel.json (schedule: every 6 hours)
 */
export async function POST(request) {
  try {
    // Verify operator identity (supports per-operator tokens + legacy CRON_SECRET)
    const auth = authenticateOperator(request);
    if (!auth.valid) {
      return epProblem(401, 'unauthorized', auth.error || 'Unauthorized');
    }

    const supabase = getGuardedClient();
    const result = await runAnchorBatch(supabase);

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Anchor cron error:', err);
    return epProblem(500, 'anchor_failed', 'Anchor batch processing failed');
  }
}

// Vercel Cron sends GET by default, but we require POST to avoid
// leaking the Authorization header in access logs / query strings.
// Vercel Cron sends GET requests — proxy to POST handler
export async function GET(request) {
  return POST(request);
}
