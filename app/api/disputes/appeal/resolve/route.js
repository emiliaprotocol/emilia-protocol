import { NextResponse } from 'next/server';
import { canonicalResolveAppeal } from '@/lib/canonical-writer';
import { validateTransition, DISPUTE_STATES, recordOperatorAction } from '@/lib/procedural-justice';
import { EP_ERRORS } from '@/lib/errors';
import { getServiceClient } from '@/lib/supabase';

/**
 * POST /api/disputes/appeal/resolve
 * 
 * Operator resolves an appeal. Requires CRON_SECRET auth.
 * appeal_upheld = original resolution stands
 * appeal_reversed = original resolution overturned, trust recomputed
 * appeal_dismissed = appeal dismissed
 */
export async function POST(request) {
  try {
    const authHeader = request.headers.get('authorization');
    const cronSecret = process.env.CRON_SECRET;
    if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    const body = await request.json();
    if (!body.dispute_id || !body.resolution) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and resolution are required');
    }

    const supabase = getServiceClient();

    // Fetch current state for audit
    const { data: dispute } = await supabase
      .from('disputes')
      .select('status')
      .eq('dispute_id', body.dispute_id)
      .single();

    if (!dispute) return EP_ERRORS.NOT_FOUND('Dispute');

    const result = await canonicalResolveAppeal(
      body.dispute_id, body.resolution, body.rationale || null, 'appeal_reviewer'
    );

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    // Audit trail
    await recordOperatorAction(supabase, {
      operatorId: 'appeal_reviewer',
      operatorRole: 'appeal_reviewer',
      targetType: 'dispute',
      targetId: body.dispute_id,
      action: 'resolve_appeal',
      beforeState: { status: dispute.status },
      afterState: { status: body.resolution },
      reasoning: body.rationale,
    });

    return NextResponse.json(result);
  } catch (err) {
    console.error('Appeal resolution error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
