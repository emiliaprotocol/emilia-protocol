import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { createReceipt } from '@/lib/create-receipt';

/**
 * POST /api/receipts/submit
 *
 * Submit a transaction receipt to the EMILIA ledger.
 * Delegates ALL receipt logic to lib/create-receipt.js — ONE truth path.
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();

    // === VALIDATION (input validation is route responsibility) ===
    if (!body.entity_id) {
      return NextResponse.json({ error: 'entity_id is required' }, { status: 400 });
    }
    if (!body.transaction_type) {
      return NextResponse.json({ error: 'transaction_type is required' }, { status: 400 });
    }
    if (!body.transaction_ref) {
      return NextResponse.json({ error: 'transaction_ref is required — every receipt must reference an external transaction' }, { status: 400 });
    }

    const validTypes = ['purchase', 'service', 'task_completion', 'delivery', 'return'];
    if (!validTypes.includes(body.transaction_type)) {
      return NextResponse.json({ error: `transaction_type must be one of: ${validTypes.join(', ')}` }, { status: 400 });
    }

    const validBehaviors = ['completed', 'retried_same', 'retried_different', 'abandoned', 'disputed'];
    if (body.agent_behavior && !validBehaviors.includes(body.agent_behavior)) {
      return NextResponse.json({ error: `agent_behavior must be one of: ${validBehaviors.join(', ')}` }, { status: 400 });
    }

    const hasSignal = [body.delivery_accuracy, body.product_accuracy, body.price_integrity,
      body.return_processing, body.agent_satisfaction].some(v => v != null && !isNaN(v));
    const hasClaims = body.claims && typeof body.claims === 'object' && Object.keys(body.claims).length > 0;
    const hasBehavior = !!body.agent_behavior;

    if (!hasSignal && !hasClaims && !hasBehavior) {
      return NextResponse.json({ error: 'Receipt must include at least one signal, claims object, or agent_behavior' }, { status: 400 });
    }

    // === DELEGATE TO SHARED RECEIPT ENGINE ===
    const result = await createReceipt({
      targetEntitySlug: body.entity_id,
      submitter: auth.entity,
      transactionRef: body.transaction_ref,
      transactionType: body.transaction_type,
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
    };
    if (result.warnings) {
      response.warnings = result.warnings;
    }

    return NextResponse.json(response, { status: 201 });
  } catch (err) {
    console.error('Receipt submission error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
