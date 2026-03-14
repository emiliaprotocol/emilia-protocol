import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * POST /api/disputes/resolve
 * 
 * Resolve a dispute. Currently operator-only (requires CRON_SECRET).
 * Future: community adjudication, oracle-based auto-resolution.
 * 
 * Auth: Bearer {CRON_SECRET}
 * 
 * Body: {
 *   dispute_id: "ep_disp_...",
 *   resolution: "upheld" | "reversed" | "dismissed",
 *   rationale: "Tracking data confirms delivery was on time. Receipt signals were inaccurate.",
 *   resolved_by: "operator"
 * }
 * 
 * If resolution is "reversed":
 *   - The disputed receipt's graph_weight is set to 0.0 (neutralized, not deleted)
 *   - The entity's score will be recomputed without this receipt's influence
 *   - The receipt remains in the ledger with dispute_status = "reversed"
 * 
 * If resolution is "upheld":
 *   - The receipt stands. dispute_status = "upheld"
 *   - The disputing entity's dispute behavior is noted
 * 
 * If resolution is "dismissed":
 *   - Insufficient evidence to act. Receipt unchanged.
 */
export async function POST(request) {
  try {
    // Operator auth via CRON_SECRET
    const authHeader = request.headers.get('authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/i, '');
    if (!token || token !== process.env.CRON_SECRET) {
      return NextResponse.json({ error: 'Unauthorized — operator access required' }, { status: 401 });
    }

    const body = await request.json();

    if (!body.dispute_id || !body.resolution || !body.rationale) {
      return NextResponse.json({
        error: 'dispute_id, resolution, and rationale are required',
      }, { status: 400 });
    }

    const validResolutions = ['upheld', 'reversed', 'dismissed'];
    if (!validResolutions.includes(body.resolution)) {
      return NextResponse.json({
        error: `Invalid resolution. Must be one of: ${validResolutions.join(', ')}`,
      }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Look up dispute
    const { data: dispute, error: fetchError } = await supabase
      .from('disputes')
      .select('*')
      .eq('dispute_id', body.dispute_id)
      .single();

    if (fetchError || !dispute) {
      return NextResponse.json({ error: 'Dispute not found' }, { status: 404 });
    }

    if (['upheld', 'reversed', 'dismissed', 'superseded'].includes(dispute.status)) {
      return NextResponse.json({
        error: `Dispute already resolved as: ${dispute.status}`,
      }, { status: 409 });
    }

    const now = new Date().toISOString();

    // Update dispute
    const { error: updateError } = await supabase
      .from('disputes')
      .update({
        status: body.resolution,
        resolution: body.resolution,
        resolution_rationale: body.rationale,
        resolved_by: body.resolved_by || 'operator',
        resolved_at: now,
        updated_at: now,
      })
      .eq('dispute_id', body.dispute_id);

    if (updateError) {
      console.error('Dispute resolution error:', updateError);
      return NextResponse.json({ error: 'Failed to resolve dispute' }, { status: 500 });
    }

    // Apply resolution effects to the receipt
    if (body.resolution === 'reversed') {
      // Neutralize the receipt — set graph_weight to 0.0
      await supabase
        .from('receipts')
        .update({
          graph_weight: 0.0,
          dispute_status: 'reversed',
        })
        .eq('receipt_id', dispute.receipt_id);

      // IMMEDIATELY recompute stored score — due process must actually undo harm
      try {
        const { data: newScore } = await supabase.rpc('compute_emilia_score', {
          p_entity_id: dispute.entity_id,
        });
        if (newScore !== null && newScore !== undefined) {
          await supabase
            .from('entities')
            .update({ emilia_score: newScore, updated_at: now })
            .eq('id', dispute.entity_id);
        }
      } catch (e) {
        console.warn('Score recomputation after reversal failed:', e.message);
        // Non-fatal — trust profile route still computes correctly from receipts
      }
    } else if (body.resolution === 'upheld') {
      await supabase
        .from('receipts')
        .update({ dispute_status: 'upheld' })
        .eq('receipt_id', dispute.receipt_id);
    } else {
      // Dismissed — clear the challenge status
      await supabase
        .from('receipts')
        .update({ dispute_status: null })
        .eq('receipt_id', dispute.receipt_id);
    }

    return NextResponse.json({
      dispute_id: body.dispute_id,
      resolution: body.resolution,
      rationale: body.rationale,
      receipt_id: dispute.receipt_id,
      effect: body.resolution === 'reversed'
        ? 'Receipt neutralized (graph_weight = 0.0). Score will update on next computation.'
        : body.resolution === 'upheld'
          ? 'Receipt stands. Dispute resolved.'
          : 'Insufficient evidence. Receipt unchanged.',
    });
  } catch (err) {
    console.error('Dispute resolution error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
