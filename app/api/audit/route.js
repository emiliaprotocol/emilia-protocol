import { NextResponse } from 'next/server';
import { authenticateRequest, getServiceClient } from '@/lib/supabase';
import { EP_ERRORS } from '@/lib/errors';
import { filterByVisibility } from '@/lib/procedural-justice';

/**
 * GET /api/audit?target_id=...&target_type=...&limit=50
 * 
 * Query the append-only audit trail. Operator-level access only.
 * Every trust-changing action is recorded with before/after state.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const url = new URL(request.url);
    const targetId = url.searchParams.get('target_id');
    const targetType = url.searchParams.get('target_type');
    const actorId = url.searchParams.get('actor_id');
    const eventType = url.searchParams.get('event_type');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
    const offset = parseInt(url.searchParams.get('offset') || '0');

    const supabase = getServiceClient();
    let query = supabase
      .from('audit_events')
      .select('*')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (targetId) query = query.eq('target_id', targetId);
    if (targetType) query = query.eq('target_type', targetType);
    if (actorId) query = query.eq('actor_id', actorId);
    if (eventType) query = query.eq('event_type', eventType);

    const { data, error } = await query;

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    return NextResponse.json({
      events: data || [],
      count: (data || []).length,
      offset,
      limit,
    });
  } catch (err) {
    console.error('Audit query error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
