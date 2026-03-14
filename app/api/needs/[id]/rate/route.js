import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { createReceipt } from '@/lib/create-receipt';

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
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const { id } = await params;
    const body = await request.json();
    const supabase = getServiceClient();

    // Fetch the need
    const { data: need, error: fetchError } = await supabase
      .from('needs')
      .select('*')
      .eq('need_id', id)
      .single();

    if (fetchError || !need) {
      return NextResponse.json({ error: 'Need not found' }, { status: 404 });
    }

    if (need.status !== 'completed') {
      return NextResponse.json({ error: `Need is ${need.status}, can only rate completed needs` }, { status: 409 });
    }

    if (need.from_entity_id !== auth.entity.id) {
      return NextResponse.json({ error: 'Only the requesting entity can rate this need' }, { status: 403 });
    }

    // Check if already rated
    const { data: existingReceipt } = await supabase
      .from('receipts')
      .select('id')
      .eq('transaction_ref', `need:${need.need_id}`)
      .single();

    if (existingReceipt) {
      return NextResponse.json({ error: 'This need has already been rated' }, { status: 409 });
    }

    // Require at least one signal or behavior
    const hasSignal = [body.delivery_accuracy, body.product_accuracy, body.price_integrity,
      body.return_processing, body.agent_satisfaction].some(v => v != null && !isNaN(v));
    const hasBehavior = !!body.agent_behavior;

    if (!hasSignal && !hasBehavior) {
      return NextResponse.json({ error: 'Must include at least one signal or agent_behavior' }, { status: 400 });
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
      return NextResponse.json(
        { error: result.error, flags: result.flags },
        { status: result.status || 500 }
      );
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
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
