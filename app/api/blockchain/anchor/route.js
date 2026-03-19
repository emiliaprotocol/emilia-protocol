import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { runAnchorBatch } from '@/lib/blockchain';
import { epProblem } from '@/lib/errors';
import { getCronSecret } from '@/lib/env';

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

    if (authHeader !== `Bearer ${cronSecret}`) {
      return epProblem(401, 'unauthorized', 'Unauthorized');
    }

    const supabase = getServiceClient();
    const result = await runAnchorBatch(supabase);

    return NextResponse.json(result);
  } catch (err) {
    console.error('Anchor cron error:', err);
    return epProblem(500, 'anchor_failed', 'Anchor batch processing failed');
  }
}

// Also support GET for Vercel Cron (which sends GET by default)
export async function GET(request) {
  return POST(request);
}
