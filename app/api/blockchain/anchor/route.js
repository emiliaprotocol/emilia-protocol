import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { runAnchorBatch } from '@/lib/blockchain';

// POST /api/blockchain/anchor
//
// Cron endpoint: collects unanchored receipts, builds Merkle tree,
// anchors root to Base L2. Called every 6 hours via Vercel Cron.
// Auth: CRON_SECRET header required.
// Vercel cron config: see vercel.json (schedule: every 6 hours)
export async function POST(request) {
  try {
    // Verify cron secret
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;

    if (!cronSecret) {
      return NextResponse.json({ error: 'CRON_SECRET not configured' }, { status: 500 });
    }

    if (authHeader !== `Bearer ${cronSecret}`) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const supabase = getServiceClient();
    const result = await runAnchorBatch(supabase);

    return NextResponse.json(result);
  } catch (err) {
    console.error('Anchor cron error:', err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

// Also support GET for Vercel Cron (which sends GET by default)
export async function GET(request) {
  return POST(request);
}
