import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';

/**
 * GET /api/score/[entityId]/history
 *
 * LEGACY COMPATIBILITY: Compatibility score history over time.
 * For current trust state, use GET /api/trust/profile/:entityId.
 *
 * No authentication required — trust data is public.
 *
 * Query params:
 *   limit  - max results (default 50, max 200)
 *   after  - ISO datetime, only return history after this date
 *   before - ISO datetime, only return history before this date
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
      return epProblem(404, 'entity_not_found', 'Entity not found');
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
      return epProblem(500, 'history_fetch_failed', 'Failed to fetch history');
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
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
