import { NextResponse } from 'next/server';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { validateTransition, DISPUTE_STATES, recordOperatorAction } from '@/lib/procedural-justice';
import { getGuardedClient } from '@/lib/write-guard';
import { getCronSecret } from '@/lib/env';

/**
 * POST /api/disputes/resolve
 *
 * @operator
 * @access operator — requires CRON_SECRET. Not part of the public API.
 *
 * Operator resolves a dispute. Routes through protocol write.
 * Validates state transition against formal dispute state machine.
 * Records operator action in audit trail.
 * Reversal triggers score recomputation and trust materialization.
 */
export async function POST(request) {
  try {
    // Operator auth via CRON_SECRET
    const authHeader = request.headers.get('authorization');
    const cronSecret = getCronSecret();
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

    // Fetch current state for validation
    const supabase = getGuardedClient();
    const { data: dispute } = await supabase
      .from('disputes')
      .select('status')
      .eq('dispute_id', body.dispute_id)
      .single();

    if (!dispute) return EP_ERRORS.NOT_FOUND('Dispute');

    // Validate state transition
    const transition = validateTransition(DISPUTE_STATES, dispute.status, body.resolution);
    if (!transition.valid) {
      return EP_ERRORS.BAD_REQUEST(`Invalid state transition: ${transition.reason}`);
    }

    const result = await protocolWrite({
      type: COMMAND_TYPES.RESOLVE_DISPUTE,
      input: {
        dispute_id: body.dispute_id,
        resolution: body.resolution,
        rationale: body.rationale || null,
        operator_id: 'operator',
      },
      actor: 'operator',
    });

    if (result.error) {
      return epProblem(result.status || 500, 'resolution_failed', result.error);
    }

    // Record in audit trail
    await recordOperatorAction(supabase, {
      operatorId: 'operator',
      operatorRole: 'operator',
      targetType: 'dispute',
      targetId: body.dispute_id,
      action: 'resolve',
      beforeState: { status: dispute.status },
      afterState: { status: body.resolution },
      reasoning: body.rationale,
    });

    return NextResponse.json({
      ...result,
      _message: `Dispute ${body.resolution}. Trust state updated.`,
    });
  } catch (err) {
    console.error('Dispute resolution error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
