import { NextResponse } from 'next/server';
import { canonicalResolveDispute } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/disputes/resolve
 * 
 * Operator resolves a dispute. Routes through canonical writer.
 * Reversal triggers score recomputation and trust materialization.
 */
export async function POST(request) {
  try {
    // Operator auth via CRON_SECRET
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    const body = await request.json();
    if (!body.dispute_id || !body.resolution) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and resolution are required');
    }

    const validResolutions = ['upheld', 'reversed', 'dismissed', 'superseded'];
    if (!validResolutions.includes(body.resolution)) {
      return EP_ERRORS.BAD_REQUEST(`resolution must be one of: ${validResolutions.join(', ')}`);
    }

    const result = await canonicalResolveDispute(
      body.dispute_id, body.resolution, body.rationale || null, 'operator'
    );

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    return NextResponse.json({
      ...result,
      _message: `Dispute ${body.resolution}. Trust state updated.`,
    });
  } catch (err) {
    console.error('Dispute resolution error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
