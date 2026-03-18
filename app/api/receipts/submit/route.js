import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { canonicalSubmitReceipt } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';
import { buildAttributionChain, applyAttributionChain } from '@/lib/attribution';

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

    const validTypes = [
      // Commerce
      'purchase', 'service', 'task_completion', 'delivery', 'return',
      // Software lifecycle (EP-SX)
      'install', 'uninstall', 'permission_grant', 'permission_escalation',
      'execution', 'incident', 'listing_review', 'provenance_check',
    ];
    if (!validTypes.includes(body.transaction_type)) {
      return NextResponse.json({ error: `transaction_type must be one of: ${validTypes.join(', ')}` }, { status: 400 });
    }

    const validBehaviors = ['completed', 'retried_same', 'retried_different', 'abandoned', 'disputed'];
    if (body.agent_behavior && !validBehaviors.includes(body.agent_behavior)) {
      return NextResponse.json({ error: `agent_behavior must be one of: ${validBehaviors.join(', ')}` }, { status: 400 });
    }

    // Validate and clamp numeric signal fields to [0, 100]
    const numericSignals = ['delivery_accuracy', 'product_accuracy', 'price_integrity', 'return_processing', 'agent_satisfaction'];
    for (const field of numericSignals) {
      if (body[field] != null) {
        const val = Number(body[field]);
        if (!Number.isFinite(val) || val < 0 || val > 100) {
          return NextResponse.json({ error: `${field} must be a number between 0 and 100` }, { status: 400 });
        }
        body[field] = val;
      }
    }

    if (typeof body.transaction_ref === 'string' && body.transaction_ref.length > 500) {
      return NextResponse.json({ error: 'transaction_ref must not exceed 500 characters' }, { status: 400 });
    }

    const hasSignal = numericSignals.some(f => body[f] != null);
    const hasClaims = body.claims && typeof body.claims === 'object' && Object.keys(body.claims).length > 0;
    const hasBehavior = !!body.agent_behavior;

    if (!hasSignal && !hasClaims && !hasBehavior) {
      return NextResponse.json({ error: 'Receipt must include at least one signal, claims object, or agent_behavior' }, { status: 400 });
    }

    // === DELEGATE TO CANONICAL WRITE ENGINE ===
    const result = await canonicalSubmitReceipt(body, auth.entity);

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

    // === ATTRIBUTION CHAIN (fire-and-forget) ===
    // If the receipt carries a delegation_id, propagate the outcome up the
    // chain to the authorizing principal as a weak delegation judgment signal.
    // This runs entirely async — it must never delay or fail the submit response.
    if (body.delegation_id && result.receipt && !result.deduplicated) {
      const receiptForAttribution = {
        ...result.receipt,
        entity_id: body.entity_id,
        agent_behavior: body.agent_behavior || null,
        delegation_id: body.delegation_id,
        context: body.context || null,
      };
      const chain = buildAttributionChain(receiptForAttribution);
      // Only run if the chain actually includes a principal (i.e., context.principal_id
      // was provided alongside the delegation_id).
      if (chain.length > 1) {
        applyAttributionChain(receiptForAttribution, chain).catch((err) => {
          console.error('[EP Attribution] Background attribution failed:', err.message);
        });
      }
    }

    return NextResponse.json(response, { status: 201 });
  } catch (err) {
    console.error('Receipt submission error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
