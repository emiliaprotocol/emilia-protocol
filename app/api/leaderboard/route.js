import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../lib/logger.js';

/**
 * GET /api/leaderboard
 *
 * Public trust rankings.
 *
 * Query params:
 *   type           - filter by entity_type (see canonical types in register route / OpenAPI)
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
    const limit = Math.min(Math.max(0, parseInt(searchParams.get('limit'), 10) || 50), 100);
    const rawOffset = parseInt(searchParams.get('offset'), 10);
    const offset = Number.isFinite(rawOffset) && rawOffset >= 0 ? rawOffset : 0;

    const supabase = getGuardedClient();

    // Uses materialized trust data for performance. Live re-evaluation happens on profile/evaluate endpoints.
    let query = supabase
      .from('entities')
      .select(`
        id, entity_id, display_name, entity_type, description,
        category, capabilities,
        emilia_score, total_receipts, successful_receipts,
        verified, created_at, trust_snapshot
      `, { count: 'exact' })
      .eq('status', 'active')
      .order('emilia_score', { ascending: false })
      .range(offset, offset + limit - 1);

    if (!includeNew) query = query.gte('total_receipts', 5);
    if (type) query = query.eq('entity_type', type);
    if (category) query = query.eq('category', category);

    const { data: entities, error, count } = await query;
    if (error) {
      logger.error('Leaderboard error:', error);
      return epProblem(500, 'leaderboard_fetch_failed', 'Failed to fetch leaderboard');
    }

    const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];

    let leaderboard = (entities || []).map((e) => {
      const snap = e.trust_snapshot || {};
      const effectiveEvidence = snap.effectiveEvidence || 0;
      const uniqueSubmitters = snap.uniqueSubmitters || 0;
      return {
        entity_id: e.entity_id,
        display_name: e.display_name,
        entity_type: e.entity_type,
        category: e.category,
        compat_score: e.emilia_score,
        confidence: snap.confidence || 'pending',
        effective_evidence: effectiveEvidence,
        unique_submitters: uniqueSubmitters,
        total_receipts: e.total_receipts,
        success_rate: e.total_receipts > 0 ? Math.round((e.successful_receipts / e.total_receipts) * 1000) / 10 : null,
        verified: e.verified,
        established: effectiveEvidence >= 5 && uniqueSubmitters >= 2,
      };
    });

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

    leaderboard = leaderboard.map((e, i) => ({ ...e, rank: offset + i + 1 }));

    return NextResponse.json({ leaderboard, rank_by: rankBy, total: count, offset, limit });
  } catch (err) {
    logger.error('Leaderboard error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
