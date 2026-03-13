import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { computeReceiptComposite, computeReceiptHash } from '@/lib/scoring';
import { randomBytes } from 'crypto';

/**
 * POST /api/receipts/submit
 * 
 * Submit a transaction receipt to the EMILIA ledger.
 * This is the core action in the protocol. Every receipt is:
 * - Append-only (cannot be modified or deleted)
 * - Cryptographically hashed (tamper-evident)
 * - Chain-linked (each receipt references the previous one)
 * 
 * Auth: Bearer ep_live_...
 * 
 * Body: {
 *   entity_id: "uuid",                    // the entity being scored
 *   transaction_ref: "ucp_order_123",     // external reference
 *   transaction_type: "purchase",          // purchase | service | task_completion | delivery | return
 *   delivery_accuracy: 95,                // 0-100, optional
 *   product_accuracy: 88,                 // 0-100, optional
 *   price_integrity: 100,                 // 0-100, optional
 *   return_processing: null,              // 0-100, optional (null if no return)
 *   agent_satisfaction: 90,               // 0-100, optional
 *   evidence: {                           // structured evidence, not opinions
 *     promised_delivery: "2 business days",
 *     actual_delivery: "2.5 business days",
 *     price_quoted: 29999,
 *     price_charged: 29999,
 *   }
 * }
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();
    const supabase = getServiceClient();

    // Validate
    if (!body.entity_id) {
      return NextResponse.json({ error: 'entity_id is required' }, { status: 400 });
    }
    if (!body.transaction_type) {
      return NextResponse.json({ error: 'transaction_type is required' }, { status: 400 });
    }

    const validTypes = ['purchase', 'service', 'task_completion', 'delivery', 'return'];
    if (!validTypes.includes(body.transaction_type)) {
      return NextResponse.json({ error: `transaction_type must be one of: ${validTypes.join(', ')}` }, { status: 400 });
    }

    // Cannot score yourself
    if (body.entity_id === auth.entity.id) {
      return NextResponse.json({ error: 'An entity cannot submit receipts for itself' }, { status: 403 });
    }

    // Verify the target entity exists
    const { data: targetEntity } = await supabase
      .from('entities')
      .select('id, entity_id')
      .eq('id', body.entity_id)
      .single();

    if (!targetEntity) {
      return NextResponse.json({ error: 'Target entity not found' }, { status: 404 });
    }

    // Compute composite score
    const composite = computeReceiptComposite({
      delivery_accuracy: body.delivery_accuracy,
      product_accuracy: body.product_accuracy,
      price_integrity: body.price_integrity,
      return_processing: body.return_processing,
      agent_satisfaction: body.agent_satisfaction,
    });

    // Get previous receipt hash for chain integrity
    const { data: prevReceipt } = await supabase
      .from('receipts')
      .select('receipt_hash')
      .eq('entity_id', body.entity_id)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    const previousHash = prevReceipt?.receipt_hash || null;

    // Generate receipt ID
    const receiptId = `ep_rcpt_${randomBytes(16).toString('hex')}`;

    // Compute receipt hash
    const receiptData = {
      entity_id: body.entity_id,
      submitted_by: auth.entity.id,
      transaction_ref: body.transaction_ref || null,
      transaction_type: body.transaction_type,
      delivery_accuracy: body.delivery_accuracy ?? null,
      product_accuracy: body.product_accuracy ?? null,
      price_integrity: body.price_integrity ?? null,
      return_processing: body.return_processing ?? null,
      agent_satisfaction: body.agent_satisfaction ?? null,
      evidence: body.evidence || {},
    };

    const receiptHash = await computeReceiptHash(receiptData, previousHash);

    // Insert receipt (triggers score recomputation via DB trigger)
    const { data: receipt, error: insertError } = await supabase
      .from('receipts')
      .insert({
        receipt_id: receiptId,
        entity_id: body.entity_id,
        submitted_by: auth.entity.id,
        transaction_ref: body.transaction_ref || null,
        transaction_type: body.transaction_type,
        delivery_accuracy: body.delivery_accuracy ?? null,
        product_accuracy: body.product_accuracy ?? null,
        price_integrity: body.price_integrity ?? null,
        return_processing: body.return_processing ?? null,
        agent_satisfaction: body.agent_satisfaction ?? null,
        evidence: body.evidence || {},
        composite_score: composite,
        receipt_hash: receiptHash,
        previous_hash: previousHash,
      })
      .select()
      .single();

    if (insertError) {
      console.error('Receipt insert error:', insertError);
      return NextResponse.json({ error: 'Failed to submit receipt' }, { status: 500 });
    }

    // Get updated score
    const { data: updatedEntity } = await supabase
      .from('entities')
      .select('emilia_score, total_receipts')
      .eq('id', body.entity_id)
      .single();

    return NextResponse.json({
      receipt: {
        receipt_id: receipt.receipt_id,
        entity_id: receipt.entity_id,
        composite_score: receipt.composite_score,
        receipt_hash: receipt.receipt_hash,
        created_at: receipt.created_at,
      },
      entity_score: {
        emilia_score: updatedEntity.emilia_score,
        total_receipts: updatedEntity.total_receipts,
      },
    }, { status: 201 });
  } catch (err) {
    console.error('Receipt submission error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
