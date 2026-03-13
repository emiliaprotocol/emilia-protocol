import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';

/**
 * POST /api/needs/[id]/claim
 * 
 * Claim an open need. Only agents with sufficient EMILIA Score can claim.
 * First valid claim wins — no double-claiming.
 * 
 * Auth: Bearer ep_live_...
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const { id } = await params;
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

    if (need.status !== 'open') {
      return NextResponse.json({ error: `Need is ${need.status}, not open` }, { status: 409 });
    }

    // Can't claim your own need
    if (need.from_entity_id === auth.entity.id) {
      return NextResponse.json({ error: 'Cannot claim your own need' }, { status: 403 });
    }

    // Check EMILIA Score requirement
    if (auth.entity.emilia_score < need.min_emilia_score) {
      return NextResponse.json({
        error: `Your EMILIA Score (${auth.entity.emilia_score}) is below the minimum required (${need.min_emilia_score})`,
      }, { status: 403 });
    }

    // Check expiry
    if (need.expires_at && new Date(need.expires_at) < new Date()) {
      await supabase
        .from('needs')
        .update({ status: 'expired' })
        .eq('id', need.id);
      return NextResponse.json({ error: 'Need has expired' }, { status: 410 });
    }

    // Atomic claim — only succeeds if status is still 'open'
    const { data: claimed, error: claimError } = await supabase
      .from('needs')
      .update({
        status: 'claimed',
        claimed_by: auth.entity.id,
        claimed_at: new Date().toISOString(),
      })
      .eq('id', need.id)
      .eq('status', 'open') // optimistic lock
      .select()
      .single();

    if (claimError || !claimed) {
      return NextResponse.json({ error: 'Need was already claimed by another entity' }, { status: 409 });
    }

    return NextResponse.json({
      need: {
        need_id: claimed.need_id,
        capability_needed: claimed.capability_needed,
        context: claimed.context,
        input_data: claimed.input_data,
        budget_cents: claimed.budget_cents,
        deadline_ms: claimed.deadline_ms,
        status: claimed.status,
        claimed_at: claimed.claimed_at,
      },
      message: 'Need claimed successfully. Complete it by posting to /api/needs/{id}/complete',
    });
  } catch (err) {
    console.error('Need claim error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
