import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/score/[entityId]/history
 *
 * Get the score history for an entity — how their EMILIA Score has changed over time.
 * No authentication required — score history is public.
 *
 * Query params:
 *   limit  - max results (default 50, max 200)
 *   after  - ISO datetime, only return history after this date
 *   before - ISO datetime, only return history before this date
 *
 * Returns: {
 *   entity_id: "rex-booking-v1",
 *   history: [
 *     { score: 94.2, total_receipts: 1284, created_at: "2026-03-01T..." },
 *     { score: 93.8, total_receipts: 1280, created_at: "2026-02-28T..." },
 *     ...
 *   ]
 * }
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;
    const { searchParams } = new URL(request.url);
    const limit = Math.min(parseInt(searchParams.get('limit')) || 50, 200);
    const after = searchParams.get('after');
    const before = searchParams.get('before');

    const supabase = getServiceClient();

    // Resolve entity
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityId);

    const { data: entity, error: entityError } = await supabase
      .from('entities')
      .select('id, entity_id, display_name, emilia_score, total_receipts')
      .eq(isUuid ? 'id' : 'entity_id', entityId)
      .single();

    if (entityError || !entity) {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    // Query score history
    let query = supabase
      .from('score_history')
      .select('score, total_receipts, created_at')
      .eq('entity_id', entity.id)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (after) query = query.gte('created_at', after);
    if (before) query = query.lte('created_at', before);

    const { data: history, error: historyError } = await query;

    if (historyError) {
      console.error('Score history error:', historyError);
      return NextResponse.json({ error: 'Failed to fetch history' }, { status: 500 });
    }

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      current_score: entity.emilia_score,
      current_receipts: entity.total_receipts,
      history: history || [],
    });
  } catch (err) {
    console.error('Score history error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
