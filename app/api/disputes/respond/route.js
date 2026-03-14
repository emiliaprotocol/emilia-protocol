import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';

/**
 * POST /api/disputes/respond
 * 
 * The receipt submitter responds to a dispute within the 7-day window.
 * 
 * Auth: Bearer ep_live_... (must be the entity that submitted the disputed receipt)
 * 
 * Body: {
 *   dispute_id: "ep_disp_...",
 *   response: "The delivery was late — tracking shows arrival on March 13, not March 10 as claimed",
 *   evidence: { tracking_screenshot: "url", carrier_confirmation: "ref123" }
 * }
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();

    if (!body.dispute_id || !body.response) {
      return NextResponse.json({ error: 'dispute_id and response are required' }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Look up dispute
    const { data: dispute, error: fetchError } = await supabase
      .from('disputes')
      .select('*, receipt:receipts!disputes_receipt_id_fkey(submitted_by)')
      .eq('dispute_id', body.dispute_id)
      .single();

    if (fetchError || !dispute) {
      return NextResponse.json({ error: 'Dispute not found' }, { status: 404 });
    }

    // Only the receipt submitter can respond
    if (dispute.receipt?.submitted_by !== auth.entity.id) {
      return NextResponse.json({
        error: 'Only the entity that submitted the disputed receipt can respond',
      }, { status: 403 });
    }

    if (dispute.status !== 'open') {
      return NextResponse.json({
        error: `Dispute is ${dispute.status}, not open for response`,
      }, { status: 409 });
    }

    // Check response deadline
    if (new Date(dispute.response_deadline) < new Date()) {
      return NextResponse.json({
        error: 'Response deadline has passed (7 days from filing)',
      }, { status: 410 });
    }

    // Record response and move to under_review
    const { error: updateError } = await supabase
      .from('disputes')
      .update({
        response: body.response,
        response_evidence: body.evidence || null,
        responded_at: new Date().toISOString(),
        status: 'under_review',
        updated_at: new Date().toISOString(),
      })
      .eq('dispute_id', body.dispute_id);

    if (updateError) {
      console.error('Dispute response error:', updateError);
      return NextResponse.json({ error: 'Failed to record response' }, { status: 500 });
    }

    // Update receipt status
    await supabase
      .from('receipts')
      .update({ dispute_status: 'under_review' })
      .eq('receipt_id', dispute.receipt_id);

    return NextResponse.json({
      dispute_id: body.dispute_id,
      status: 'under_review',
      _message: 'Response recorded. Dispute is now under review.',
    });
  } catch (err) {
    console.error('Dispute response error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
