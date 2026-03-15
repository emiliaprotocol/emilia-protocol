import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';

/**
 * GET /api/leaderboard
 * 
 * Public trust rankings.
 * 
 * Query params:
 *   type           - filter: agent, merchant, service_provider
 *   category       - filter by category
 *   include_new    - include unestablished entities (default false)
 *   rank_by        - "score" (default, legacy), "confidence", or "evidence"
 *   min_confidence - minimum confidence level: pending, insufficient, provisional, emerging, confident
 *   limit          - max results (default 50, max 100)
 *   offset         - pagination offset
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const type = searchParams.get('type');
    const category = searchParams.get('category');
    const includeNew = searchParams.get('include_new') === 'true';
    const rankBy = searchParams.get('rank_by') || 'score';
    const minConfidence = searchParams.get('min_confidence') || null;
    const limit = Math.min(parseInt(searchParams.get('limit')) || 50, 100);
    const offset = parseInt(searchParams.get('offset')) || 0;

    const supabase = getServiceClient();

    let query = supabase
      .from('entities')
      .select(`
        id, entity_id, display_name, entity_type, description,
        category, capabilities,
        emilia_score, total_receipts, successful_receipts,
        verified, created_at
      `, { count: 'exact' })
      .eq('status', 'active')
      .order('emilia_score', { ascending: false })
      .range(offset, offset + limit + 49 - 1);

    if (!includeNew) query = query.gte('total_receipts', 5);
    if (type) query = query.eq('entity_type', type);
    if (category) query = query.eq('category', category);

    const { data: entities, error, count } = await query;
    if (error) {
      console.error('Leaderboard error:', error);
      return NextResponse.json({ error: 'Failed to fetch leaderboard' }, { status: 500 });
    }

    const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];

    let leaderboard = await Promise.all((entities || []).map(async (e) => {
      const trust = await canonicalEvaluate(e.id, {
        includeDisputes: false,
        includeEstablishment: true,
      });
      return {
        entity_id: e.entity_id,
        display_name: e.display_name,
        entity_type: e.entity_type,
        category: e.category,
        compat_score: e.emilia_score,
        confidence: trust.confidence || 'pending',
        effective_evidence: trust.establishment?.effective_evidence || trust.effectiveEvidence || 0,
        unique_submitters: trust.establishment?.unique_submitters || trust.uniqueSubmitters || 0,
        total_receipts: e.total_receipts,
        success_rate: e.total_receipts > 0 ? Math.round((e.successful_receipts / e.total_receipts) * 1000) / 10 : null,
        verified: e.verified,
        established: trust.establishment?.established || false,
      };
    }));

    if (!includeNew) leaderboard = leaderboard.filter(e => e.established);
    if (minConfidence) {
      const minIdx = confLevels.indexOf(minConfidence);
      if (minIdx >= 0) leaderboard = leaderboard.filter(e => confLevels.indexOf(e.confidence) >= minIdx);
    }

    if (rankBy === 'evidence') {
      leaderboard.sort((a, b) => b.effective_evidence - a.effective_evidence);
    } else if (rankBy === 'confidence') {
      leaderboard.sort((a, b) => {
        const ca = confLevels.indexOf(a.confidence);
        const cb = confLevels.indexOf(b.confidence);
        if (cb !== ca) return cb - ca;
        return b.effective_evidence - a.effective_evidence;
      });
    } else {
      leaderboard.sort((a, b) => b.compat_score - a.compat_score);
    }

    leaderboard = leaderboard.slice(0, limit).map((e, i) => ({ ...e, rank: offset + i + 1 }));

    return NextResponse.json({ leaderboard, rank_by: rankBy, total: count, offset, limit });
  } catch (err) {
    console.error('Leaderboard error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
