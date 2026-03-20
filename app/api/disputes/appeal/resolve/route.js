import { NextResponse } from 'next/server';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { recordOperatorAction } from '@/lib/procedural-justice';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { getGuardedClient } from '@/lib/write-guard';
import { getCronSecret } from '@/lib/env';

/**
 * POST /api/disputes/appeal/resolve
 *
 * @operator
 * @access operator — requires CRON_SECRET. Not part of the public API.
 *
 * Operator resolves an appeal. Requires CRON_SECRET auth.
 * appeal_upheld = original resolution stands
 * appeal_reversed = original resolution overturned, trust recomputed
 * appeal_dismissed = appeal dismissed
 */
export async function POST(request) {
  try {
    const authHeader = request.headers.get('authorization');
    const cronSecret = getCronSecret();
    if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    const body = await request.json();
    if (!body.dispute_id || !body.resolution) {
      return EP_ERRORS.BAD_REQUEST('dispute_id and resolution are required');
    }

    const supabase = getGuardedClient();

    // Fetch current state for audit
    const { data: dispute } = await supabase
      .from('disputes')
      .select('status')
      .eq('dispute_id', body.dispute_id)
      .single();

    if (!dispute) return EP_ERRORS.NOT_FOUND('Dispute');

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESOLVE_APPEAL,
      input: {
        dispute_id: body.dispute_id,
        resolution: body.resolution,
        rationale: body.rationale || null,
        operator_id: 'appeal_reviewer',
      },
      actor: 'appeal_reviewer',
    });

    if (result.error) {
      return epProblem(result.status || 500, 'appeal_resolution_failed', result.error);
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
