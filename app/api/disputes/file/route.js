import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import crypto from 'crypto';

/**
 * POST /api/disputes/file
 * 
 * File a dispute against a receipt. Any materially affected party can challenge.
 * This is the due-process layer: "trust must never be more powerful than appeal."
 * 
 * Auth: Bearer ep_live_...
 * 
 * Body: {
 *   receipt_id: "ep_rcpt_...",
 *   reason: "inaccurate_signals" | "fraudulent_receipt" | "identity_dispute" | 
 *           "context_mismatch" | "duplicate_transaction" | "coerced_receipt" | "other",
 *   description: "Delivery was actually on time, receipt claims 3 days late",
 *   evidence: { tracking_id: "1Z...", delivered_at: "2026-03-10T14:00:00Z" }
 * }
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();

    if (!body.receipt_id) {
      return NextResponse.json({ error: 'receipt_id is required' }, { status: 400 });
    }
    if (!body.reason) {
      return NextResponse.json({ error: 'reason is required' }, { status: 400 });
    }

    const validReasons = [
      'fraudulent_receipt', 'inaccurate_signals', 'identity_dispute',
      'context_mismatch', 'duplicate_transaction', 'coerced_receipt', 'other',
    ];
    if (!validReasons.includes(body.reason)) {
      return NextResponse.json({
        error: `Invalid reason. Must be one of: ${validReasons.join(', ')}`,
      }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Look up the receipt
    const { data: receipt, error: receiptError } = await supabase
      .from('receipts')
      .select('receipt_id, entity_id, submitted_by')
      .eq('receipt_id', body.receipt_id)
      .single();

    if (receiptError || !receipt) {
      return NextResponse.json({ error: 'Receipt not found' }, { status: 404 });
    }

    // Check if already disputed
    const { data: existing } = await supabase
      .from('disputes')
      .select('dispute_id, status')
      .eq('receipt_id', body.receipt_id)
      .in('status', ['open', 'under_review'])
      .limit(1);

    if (existing && existing.length > 0) {
      return NextResponse.json({
        error: 'This receipt already has an active dispute',
        existing_dispute: existing[0].dispute_id,
      }, { status: 409 });
    }

    // Determine filer type
    let filedByType = 'third_party';
    if (auth.entity.id === receipt.entity_id) {
      filedByType = 'receipt_subject'; // The entity the receipt is about
    } else if (auth.entity.id === receipt.submitted_by) {
      filedByType = 'affected_entity'; // The entity that submitted it (self-correction)
    }

    const disputeId = `ep_disp_${crypto.randomBytes(16).toString('hex')}`;

    const { data: dispute, error: insertError } = await supabase
      .from('disputes')
      .insert({
        dispute_id: disputeId,
        receipt_id: body.receipt_id,
        entity_id: receipt.entity_id,
        filed_by: auth.entity.id,
        filed_by_type: filedByType,
        reason: body.reason,
        description: body.description || null,
        evidence: body.evidence || null,
      })
      .select()
      .single();

    if (insertError) {
      console.error('Dispute filing error:', insertError);
      return NextResponse.json({ error: 'Failed to file dispute' }, { status: 500 });
    }

    // Mark the receipt as challenged
    await supabase
      .from('receipts')
      .update({ dispute_status: 'challenged' })
      .eq('receipt_id', body.receipt_id);

    return NextResponse.json({
      dispute_id: dispute.dispute_id,
      receipt_id: dispute.receipt_id,
      status: dispute.status,
      reason: dispute.reason,
      filed_by_type: filedByType,
      response_deadline: dispute.response_deadline,
      _message: 'Dispute filed. The receipt submitter has 7 days to respond.',
    }, { status: 201 });
  } catch (err) {
    console.error('Dispute filing error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
