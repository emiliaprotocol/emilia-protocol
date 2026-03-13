import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { computeReceiptComposite, computeReceiptHash } from '@/lib/scoring';
import crypto from 'crypto';

/**
 * POST /api/needs/[id]/rate
 * 
 * Rate the entity that fulfilled a need. This creates a receipt
 * on the EMILIA ledger — the same receipt that updates their score.
 * 
 * Only the entity that broadcast the need can rate it.
 * Only completed needs can be rated.
 * 
 * Auth: Bearer ep_live_...
 * 
 * Body: {
 *   delivery_accuracy: 95,    // was it on time?
 *   product_accuracy: 88,     // was the output correct?
 *   price_integrity: 100,     // was the price honored?
 *   agent_satisfaction: 90,   // overall satisfaction
 *   evidence: { ... }
 * }
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

    // Only the requesting entity can rate
    if (need.from_entity_id !== auth.entity.id) {
      return NextResponse.json({ error: 'Only the requesting entity can rate this need' }, { status: 403 });
    }

    // Check if already rated (prevent double-rating)
    const { data: existingReceipt } = await supabase
      .from('receipts')
      .select('id')
      .eq('transaction_ref', `need:${need.need_id}`)
      .single();

    if (existingReceipt) {
      return NextResponse.json({ error: 'This need has already been rated' }, { status: 409 });
    }

    // Create a receipt scoring the fulfilling entity
    const composite = computeReceiptComposite({
      delivery_accuracy: body.delivery_accuracy,
      product_accuracy: body.product_accuracy,
      price_integrity: body.price_integrity,
      return_processing: body.return_processing,
      agent_satisfaction: body.agent_satisfaction,
    });

    // Get previous hash for chain integrity
    const { data: prevReceipt } = await supabase
      .from('receipts')
      .select('receipt_hash')
      .eq('entity_id', need.claimed_by)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    const previousHash = prevReceipt?.receipt_hash || null;
    const receiptId = `ep_rcpt_${crypto.randomBytes(16).toString('hex')}`;

    const receiptData = {
      entity_id: need.claimed_by,
      submitted_by: auth.entity.id,
      transaction_ref: `need:${need.need_id}`,
      transaction_type: 'task_completion',
      delivery_accuracy: body.delivery_accuracy ?? null,
      product_accuracy: body.product_accuracy ?? null,
      price_integrity: body.price_integrity ?? null,
      return_processing: body.return_processing ?? null,
      agent_satisfaction: body.agent_satisfaction ?? null,
      evidence: body.evidence || {},
    };

    const receiptHash = await computeReceiptHash(receiptData, previousHash);

    const { data: receipt, error: receiptError } = await supabase
      .from('receipts')
      .insert({
        receipt_id: receiptId,
        entity_id: need.claimed_by,
        submitted_by: auth.entity.id,
        transaction_ref: `need:${need.need_id}`,
        transaction_type: 'task_completion',
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

    if (receiptError) {
      console.error('Receipt creation error:', receiptError);
      return NextResponse.json({ error: 'Failed to create receipt' }, { status: 500 });
    }

    // Get updated score
    const { data: updatedEntity } = await supabase
      .from('entities')
      .select('emilia_score, total_receipts')
      .eq('id', need.claimed_by)
      .single();

    return NextResponse.json({
      receipt: {
        receipt_id: receipt.receipt_id,
        composite_score: receipt.composite_score,
        receipt_hash: receipt.receipt_hash,
      },
      entity_score: {
        emilia_score: updatedEntity?.emilia_score,
        total_receipts: updatedEntity?.total_receipts,
      },
      message: 'Need rated. Receipt added to the EMILIA ledger.',
    }, { status: 201 });
  } catch (err) {
    console.error('Need rate error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
