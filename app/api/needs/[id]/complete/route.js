import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';

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

    if (need.status !== 'claimed' && need.status !== 'in_progress') {
      return NextResponse.json({ error: `Need is ${need.status}, cannot complete` }, { status: 409 });
    }

    // Only the claiming entity can complete
    if (need.claimed_by !== auth.entity.id) {
      return NextResponse.json({ error: 'Only the claiming entity can complete this need' }, { status: 403 });
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
      return NextResponse.json({ error: 'Failed to complete need' }, { status: 500 });
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
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
