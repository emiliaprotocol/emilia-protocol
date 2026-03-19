import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/needs/[id]/complete
 *
 * Mark a claimed need as completed and provide the output.
 * Only the entity that claimed the need can complete it.
 *
 * Auth: Bearer ep_live_...
 *
 * Body: {
 *   output_data: { ... }  // the result of fulfilling the need
 * }
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
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
      return epProblem(404, 'need_not_found', 'Need not found');
    }

    if (need.status !== 'claimed' && need.status !== 'in_progress') {
      return epProblem(409, 'need_wrong_state', `Need is ${need.status}, cannot complete`);
    }

    // Only the claiming entity can complete
    if (need.claimed_by !== auth.entity.id) {
      return epProblem(403, 'not_claimant', 'Only the claiming entity can complete this need');
    }

    const { data: completed, error: updateError } = await supabase
      .from('needs')
      .update({
        status: 'completed',
        output_data: body.output_data || null,
        completed_at: new Date().toISOString(),
      })
      .eq('id', need.id)
      .select()
      .single();

    if (updateError) {
      console.error('Need complete error:', updateError);
      return epProblem(500, 'completion_failed', 'Failed to complete need');
    }

    return NextResponse.json({
      need: {
        need_id: completed.need_id,
        status: completed.status,
        completed_at: completed.completed_at,
      },
      message: 'Need completed. The requesting entity can now rate you via /api/needs/{id}/rate',
    });
  } catch (err) {
    console.error('Need complete error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
