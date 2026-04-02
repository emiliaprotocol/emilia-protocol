import { NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';
import { getGuardedClient } from '@/lib/write-guard';
import { runAnchorBatch } from '@/lib/blockchain';
import { epProblem } from '@/lib/errors';
import { getCronSecret } from '@/lib/env';
import { logger } from '../../../../lib/logger.js';

function safeCompare(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * POST /api/blockchain/anchor
 *
 * @internal
 * @access cron — requires CRON_SECRET. Not part of the public API.
 *
 * Cron endpoint: collects unanchored receipts, builds Merkle tree,
 * anchors root to Base L2. Called every 6 hours via Vercel Cron.
 * Auth: CRON_SECRET header required.
 * Vercel cron config: see vercel.json (schedule: every 6 hours)
 */
export async function POST(request) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    const cronSecret = getCronSecret();

    if (!cronSecret) {
      return epProblem(500, 'cron_secret_missing', 'CRON_SECRET not configured');
    }

    if (!safeCompare(authHeader, `Bearer ${cronSecret}`)) {
      return epProblem(401, 'unauthorized', 'Unauthorized');
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
