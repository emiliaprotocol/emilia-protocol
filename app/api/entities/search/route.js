import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { generateEmbedding } from '@/lib/providers/embeddings';
import { logger } from '../../../../lib/logger.js';

/**
 * Sanitize user input to prevent PostgREST filter DSL injection.
 * Strips metacharacters that could alter filter semantics.
 */
function sanitizePostgrestInput(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[,;.()"'\\]/g, '');
}

/**
 * GET /api/entities/search
 *
 * Search entities by capability, category, type, or semantic query.
 *
 * No auth required — entity directory is public.
 *
 * Query params:
 *   q              - semantic search query (uses embeddings)
 *   type           - filter by entity_type (see canonical types in register route / OpenAPI)
 *   category       - filter by category
 *   capability     - filter by capability keyword
 *   min_score      - LEGACY: minimum compatibility score sort key (default 0). Use min_confidence instead.
 *   min_confidence - minimum confidence: pending, insufficient, provisional, emerging, confident
 *   rank_by        - "score" (legacy default), "confidence", or "evidence"
 *   limit          - max results (default 20, max 50)
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const q = searchParams.get('q');
    const type = searchParams.get('type');
    const category = searchParams.get('category');
    const capability = searchParams.get('capability');
    // LEGACY: min_score filters by compat_score sort key, not trust decision.
    // New consumers should use min_confidence or rank_by=confidence instead.
    const minScore = parseFloat(searchParams.get('min_score')) || 0;
    const minConfidence = searchParams.get('min_confidence') || null;
    const rankBy = searchParams.get('rank_by') || 'score';
    const limit = Math.min(parseInt(searchParams.get('limit')) || 20, 50);

    const supabase = getGuardedClient();
    const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];

    // Uses materialized trust data for performance. Live re-evaluation happens on profile/evaluate endpoints.
    function enrichWithMaterializedTrust(results) {
      let enriched = (results || []).map((e) => {
        const snap = e.trust_snapshot || {};
        return {
          ...e,
          confidence: snap.confidence || 'pending',
          effective_evidence: snap.effectiveEvidence || 0,
          established: (snap.effectiveEvidence || 0) >= 5 && (snap.uniqueSubmitters || 0) >= 2,
        };
      });

      if (minConfidence) {
        const minIdx = confLevels.indexOf(minConfidence);
        if (minIdx >= 0) {
          enriched = enriched.filter(e => confLevels.indexOf(e.confidence) >= minIdx);
        }
      }

      if (rankBy === 'evidence') {
        enriched.sort((a, b) => b.effective_evidence - a.effective_evidence);
      } else if (rankBy === 'confidence') {
        enriched.sort((a, b) => {
          const ca = confLevels.indexOf(a.confidence);
          const cb = confLevels.indexOf(b.confidence);
          if (cb !== ca) return cb - ca;
          return b.effective_evidence - a.effective_evidence;
        });
      }

      return enriched;
    }

    // If semantic query provided, attempt vector search via embedding provider
    if (q) {
      try {
        const embedding = await generateEmbedding(q);

        if (embedding) {
          const { data: results, error } = await supabase.rpc('search_entities', {
            query_embedding: embedding,
            min_score: minScore,
            filter_type: type || null,
            filter_category: category || null,
            match_limit: limit,
          });

          if (!error && results) {
            let semanticResults = results.map(r => ({
              id: r.id,
              entity_id: r.entity_id,
              display_name: r.display_name,
              entity_type: r.entity_type,
              description: r.description,
              category: r.category,
              capabilities: r.capabilities,
              emilia_score: r.emilia_score,
              total_receipts: r.total_receipts,
              similarity: r.similarity,
              verified: r.verified,
            }));

            semanticResults = enrichWithMaterializedTrust(semanticResults);

            return NextResponse.json({
              entities: semanticResults,
              results: semanticResults,
              total: semanticResults.length,
              query: q,
              rank_by: rankBy,
            });
          }
        }
      } catch (e) {
        logger.warn('Semantic search failed, falling back to filter search:', e.message);
      }
    }

    // Fallback: filter-based search
    let query = supabase
      .from('entities')
      .select(`
        id, entity_id, display_name, entity_type, description,
        category, capabilities, emilia_score, total_receipts,
        verified, created_at, trust_snapshot
      `)
      .eq('status', 'active')
      .gte('emilia_score', minScore)
      .order('emilia_score', { ascending: false })
      .limit(limit);

    if (type) query = query.eq('entity_type', type);
    if (category) query = query.eq('category', category);
    if (capability) query = query.contains('capabilities', [capability]);
    if (q) {
      const sanitized = sanitizePostgrestInput(q);
      query = query.or(`display_name.ilike.%${sanitized}%,description.ilike.%${sanitized}%,entity_id.ilike.%${sanitized}%`);
    }

    const { data: results, error } = await query;

    if (error) {
      logger.error('Entity search error:', error);
      return epProblem(500, 'search_failed', 'Search failed');
    }

    const filtered = enrichWithMaterializedTrust(results || []);

    return NextResponse.json({
      entities: filtered,
      results: filtered,
      total: filtered.length,
      query: q,
      rank_by: rankBy,
    });
  } catch (err) {
    logger.error('Entity search error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
