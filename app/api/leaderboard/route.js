import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/leaderboard
 * 
 * Public reputation rankings. Sorted by EMILIA Score.
 * Only shows established entities (5+ receipts) by default.
 * 
 * No auth required — reputation is public.
 * 
 * Query params:
 *   type           - filter: agent, merchant, service_provider
 *   category       - filter: salon, legal, etc.
 *   include_new    - include unestablished entities (default false)
 *   limit          - max results (default 50, max 100)
 *   offset         - pagination offset
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const type = searchParams.get('type');
    const category = searchParams.get('category');
    const includeNew = searchParams.get('include_new') === 'true';
    const limit = Math.min(parseInt(searchParams.get('limit')) || 50, 100);
    const offset = parseInt(searchParams.get('offset')) || 0;

    const supabase = getServiceClient();

    let query = supabase
      .from('entities')
      .select(`
        entity_id, display_name, entity_type, description,
        category, capabilities,
        emilia_score, total_receipts, successful_receipts,
        verified, created_at
      `, { count: 'exact' })
      .eq('status', 'active')
      .order('emilia_score', { ascending: false })
      .range(offset, offset + limit - 1);

    if (!includeNew) {
      query = query.gte('total_receipts', 5);
    }
    if (type) query = query.eq('entity_type', type);
    if (category) query = query.eq('category', category);

    const { data: entities, error, count } = await query;

    if (error) {
      console.error('Leaderboard error:', error);
      return NextResponse.json({ error: 'Failed to fetch leaderboard' }, { status: 500 });
    }

    return NextResponse.json({
      leaderboard: (entities || []).map((e, i) => ({
        rank: offset + i + 1,
        entity_id: e.entity_id,
        display_name: e.display_name,
        entity_type: e.entity_type,
        category: e.category,
        emilia_score: e.emilia_score,
        total_receipts: e.total_receipts,
        success_rate: e.total_receipts > 0
          ? Math.round((e.successful_receipts / e.total_receipts) * 1000) / 10
          : null,
        verified: e.verified,
        // established requires per-entity effective_evidence computation
        // Use /api/score/:entityId for canonical establishment status
      })),
      total: count,
      offset,
      limit,
    });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
