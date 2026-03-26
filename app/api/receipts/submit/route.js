import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { protocolWrite, COMMAND_TYPES } from '@/lib/protocol-write';
import { EP_ERRORS, epProblem } from '@/lib/errors';
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
      return epProblem(401, 'unauthorized', auth.error);
    }

    const body = await request.json();

    // === VALIDATION (input validation is route responsibility) ===
    if (!body.entity_id) {
      return epProblem(400, 'missing_entity_id', 'entity_id is required');
    }
    if (!body.transaction_type) {
      return epProblem(400, 'missing_transaction_type', 'transaction_type is required');
    }
    if (!body.transaction_ref) {
      return epProblem(400, 'missing_transaction_ref', 'transaction_ref is required — every receipt must reference an external transaction');
    }

    const validTypes = [
      // Commerce
      'purchase', 'service', 'task_completion', 'delivery', 'return',
      // Software lifecycle (EP-SX)
      'install', 'uninstall', 'permission_grant', 'permission_escalation',
      'execution', 'incident', 'listing_review', 'provenance_check',
    ];
    if (!validTypes.includes(body.transaction_type)) {
      return epProblem(400, 'invalid_transaction_type', `transaction_type must be one of: ${validTypes.join(', ')}`);
    }

    const validBehaviors = ['completed', 'retried_same', 'retried_different', 'abandoned', 'disputed'];
    if (body.agent_behavior && !validBehaviors.includes(body.agent_behavior)) {
      return epProblem(400, 'invalid_agent_behavior', `agent_behavior must be one of: ${validBehaviors.join(', ')}`);
    }

    // Validate and clamp numeric signal fields to [0, 100]
    const numericSignals = ['delivery_accuracy', 'product_accuracy', 'price_integrity', 'return_processing', 'agent_satisfaction'];
    for (const field of numericSignals) {
      if (body[field] != null) {
        const val = Number(body[field]);
        if (!Number.isFinite(val) || val < 0 || val > 100) {
          return epProblem(400, 'invalid_signal_value', `${field} must be a number between 0 and 100`);
        }
        body[field] = val;
      }
    }

    if (typeof body.transaction_ref === 'string' && body.transaction_ref.length > 500) {
      return epProblem(400, 'transaction_ref_too_long', 'transaction_ref must not exceed 500 characters');
    }

    const hasSignal = numericSignals.some(f => body[f] != null);
    const hasClaims = body.claims && typeof body.claims === 'object' && Object.keys(body.claims).length > 0;
    const hasBehavior = !!body.agent_behavior;

    if (!hasSignal && !hasClaims && !hasBehavior) {
      return epProblem(400, 'missing_signal', 'Receipt must include at least one signal, claims object, or agent_behavior');
    }

    // === DELEGATE TO CANONICAL WRITE ENGINE ===
    const result = await protocolWrite({
      type: COMMAND_TYPES.SUBMIT_RECEIPT,
      input: body,
      actor: auth.entity,
    });

    if (result.error) {
      return epProblem(result.status || 500, 'receipt_submission_failed', result.error, {
        flags: result.flags,
      });
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
    // chain to the authorizing principal as a weak delegation authority signal.
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
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
