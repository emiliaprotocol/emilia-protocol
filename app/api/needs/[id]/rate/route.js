import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { createReceipt } from '@/lib/create-receipt';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/needs/[id]/rate
 *
 * Rate the entity that fulfilled a need.
 * Delegates to createReceipt() — same trust path as /api/receipts/submit.
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { id } = await params;
    const body = await request.json();
    const supabase = getGuardedClient();

    // Fetch the need
    const { data: need, error: fetchError } = await supabase
      .from('needs')
      .select('*')
      .eq('need_id', id)
      .single();

    if (fetchError || !need) {
      return epProblem(404, 'need_not_found', 'Need not found');
    }

    if (need.status !== 'completed') {
      return epProblem(409, 'need_not_completed', `Need is ${need.status}, can only rate completed needs`);
    }

    if (need.from_entity_id !== auth.entity.id) {
      return epProblem(403, 'not_requester', 'Only the requesting entity can rate this need');
    }

    // Check if already rated
    const { data: existingReceipt } = await supabase
      .from('receipts')
      .select('id')
      .eq('transaction_ref', `need:${need.need_id}`)
      .single();

    if (existingReceipt) {
      return epProblem(409, 'already_rated', 'This need has already been rated');
    }

    // Require at least one signal or behavior
    const hasSignal = [body.delivery_accuracy, body.product_accuracy, body.price_integrity,
      body.return_processing, body.agent_satisfaction].some(v => v != null && !isNaN(v));
    const hasBehavior = !!body.agent_behavior;

    if (!hasSignal && !hasBehavior) {
      return epProblem(400, 'missing_signal', 'Must include at least one signal or agent_behavior');
    }

    // Use the SAME receipt engine as /api/receipts/submit
    const result = await createReceipt({
      targetEntitySlug: need.claimed_by,
      submitter: auth.entity,
      transactionRef: `need:${need.need_id}`,
      transactionType: 'task_completion',
      signals: {
        delivery_accuracy: body.delivery_accuracy ?? null,
        product_accuracy: body.product_accuracy ?? null,
        price_integrity: body.price_integrity ?? null,
        return_processing: body.return_processing ?? null,
        agent_satisfaction: body.agent_satisfaction ?? null,
      },
      agentBehavior: body.agent_behavior || null,
      claims: body.claims || null,
      evidence: body.evidence || {},
      context: body.context || (need.category ? { task_type: 'task_completion', category: need.category } : null),
    });

    if (result.error) {
      return epProblem(result.status || 500, 'receipt_creation_failed', result.error, {
        flags: result.flags,
      });
    }

    const response = {
      receipt: result.receipt,
      entity_score: result.entityScore,
      message: 'Need rated. Receipt added to the EMILIA ledger.',
    };
    if (result.warnings) {
      response.warnings = result.warnings;
    }

    return NextResponse.json(response, { status: 201 });
  } catch (err) {
    console.error('Need rate error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
