import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';

/**
 * POST /api/receipts/confirm
 * 
 * Confirm a bilateral receipt. The entity that the receipt is ABOUT
 * confirms (or disputes) the submitter's claim.
 * 
 * When confirmed:
 *   - bilateral_status → 'confirmed'
 *   - provenance_tier upgrades to 'bilateral' (0.8x weight, up from 0.3x)
 *   - This is the single biggest trust quality improvement possible
 * 
 * When disputed:
 *   - bilateral_status → 'disputed'
 *   - provenance_tier stays 'self_attested' (0.3x)
 *   - A dispute is auto-filed
 * 
 * Auth: Bearer ep_live_... (must be the entity the receipt is about)
 * 
 * Body: {
 *   receipt_id: "ep_rcpt_...",
 *   confirm: true | false,
 *   notes: "optional explanation"
 * }
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();
    if (!body.receipt_id || body.confirm === undefined) {
      return NextResponse.json({ error: 'receipt_id and confirm (boolean) are required' }, { status: 400 });
    }

    const supabase = getServiceClient();

    const { data: receipt, error: fetchError } = await supabase
      .from('receipts')
      .select('receipt_id, entity_id, submitted_by, bilateral_status, confirmation_deadline')
      .eq('receipt_id', body.receipt_id)
      .single();

    if (fetchError || !receipt) {
      return NextResponse.json({ error: 'Receipt not found' }, { status: 404 });
    }

    // Only the subject entity can confirm
    if (receipt.entity_id !== auth.entity.id) {
      return NextResponse.json({
        error: 'Only the entity this receipt is about can confirm or dispute it',
      }, { status: 403 });
    }

    if (receipt.bilateral_status !== 'pending_confirmation') {
      return NextResponse.json({
        error: `Receipt bilateral status is '${receipt.bilateral_status}', not 'pending_confirmation'`,
      }, { status: 409 });
    }

    // Check deadline
    if (receipt.confirmation_deadline && new Date(receipt.confirmation_deadline) < new Date()) {
      await supabase
        .from('receipts')
        .update({ bilateral_status: 'expired' })
        .eq('receipt_id', body.receipt_id);
      return NextResponse.json({ error: 'Confirmation deadline expired (48h)' }, { status: 410 });
    }

    const now = new Date().toISOString();

    if (body.confirm) {
      // CONFIRMED — upgrade provenance to bilateral
      await supabase
        .from('receipts')
        .update({
          bilateral_status: 'confirmed',
          provenance_tier: 'bilateral',
          confirmed_by: auth.entity.id,
          confirmed_at: now,
        })
        .eq('receipt_id', body.receipt_id);

      return NextResponse.json({
        receipt_id: body.receipt_id,
        bilateral_status: 'confirmed',
        provenance_tier: 'bilateral',
        _message: 'Both parties confirmed. Receipt upgraded to bilateral provenance (0.8x weight).',
      });
    } else {
      // DISPUTED — mark as disputed, provenance stays self_attested
      await supabase
        .from('receipts')
        .update({
          bilateral_status: 'disputed',
          confirmed_by: auth.entity.id,
          confirmed_at: now,
        })
        .eq('receipt_id', body.receipt_id);

      return NextResponse.json({
        receipt_id: body.receipt_id,
        bilateral_status: 'disputed',
        provenance_tier: 'self_attested',
        _message: 'Counterparty disputed the receipt. Provenance remains self_attested (0.3x weight). Consider filing a formal dispute.',
      });
    }
  } catch (err) {
    console.error('Bilateral confirmation error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
