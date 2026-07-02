import { NextResponse } from 'next/server';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { validateTransition, DISPUTE_STATES, recordOperatorAction } from '@/lib/procedural-justice';
import { getGuardedClient } from '@/lib/write-guard';
import { authenticateOperator } from '@/lib/operator-auth';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 64 * 1024;

/**
 * POST /api/disputes/resolve
 *
 * @operator
 * @access operator — requires a per-operator token (NAMED operator). Once
 *   EP_OPERATOR_KEYS is configured, the shared CRON_SECRET is refused here so
 *   every dispute resolution ties to an accountable operator. Not public.
 *
 * Operator resolves a dispute. Routes through protocol write.
 * Validates state transition against formal dispute state machine.
 * Records operator action in audit trail.
 * Reversal triggers score recomputation and trust materialization.
 */
export async function POST(request) {
  try {
    // Sensitive operator action — require a named operator identity for audit.
    const opAuth = authenticateOperator(request, { requireOperatorIdentity: true });
    if (!opAuth.valid) return EP_ERRORS.UNAUTHORIZED();
    const operatorId = opAuth.operator_id;

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value;
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
        operator_id: operatorId,
      },
      actor: operatorId,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'resolution_failed', result.error);
    }

    // Record in audit trail
    await recordOperatorAction(supabase, {
      operatorId,
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
    logger.error('Dispute resolution error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
