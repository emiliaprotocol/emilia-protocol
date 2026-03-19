import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { epProblem } from '@/lib/errors';

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
 *   min_score      - minimum compatibility score (default 0, legacy fallback)
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
    const minScore = parseFloat(searchParams.get('min_score')) || 0;
    const minConfidence = searchParams.get('min_confidence') || null;
    const rankBy = searchParams.get('rank_by') || 'score';
    const limit = Math.min(parseInt(searchParams.get('limit')) || 20, 50);

    const supabase = getServiceClient();
    const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];

    async function enrichWithCanonicalTrust(results) {
      let enriched = await Promise.all((results || []).map(async (e) => {
        const trust = await canonicalEvaluate(e.id, {
          includeDisputes: false,
          includeEstablishment: true,
        });
        return {
          ...e,
          confidence: trust.confidence || 'pending',
          effective_evidence: trust.effectiveEvidence || 0,
          established: trust.establishment?.established || false,
        };
      }));

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

    // If semantic query provided and OpenAI key available, do vector search
    if (q && process.env.OPENAI_API_KEY) {
      try {
        const embRes = await fetch('https://api.openai.com/v1/embeddings', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'text-embedding-3-small',
            input: q,
          }),
        });

        if (embRes.ok) {
          const embData = await embRes.json();
          const embedding = embData.data[0].embedding;

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

            semanticResults = await enrichWithCanonicalTrust(semanticResults);

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
        console.warn('Semantic search failed, falling back to filter search:', e.message);
      }
    }

    // Fallback: filter-based search
    let query = supabase
      .from('entities')
      .select(`
        id, entity_id, display_name, entity_type, description,
        category, capabilities, emilia_score, total_receipts,
        verified, created_at
      `)
      .eq('status', 'active')
      .gte('emilia_score', minScore)
      .order('emilia_score', { ascending: false })
      .limit(limit);

    if (type) query = query.eq('entity_type', type);
    if (category) query = query.eq('category', category);
    if (capability) query = query.contains('capabilities', [capability]);
    if (q) {
      query = query.or(`display_name.ilike.%${q}%,description.ilike.%${q}%,entity_id.ilike.%${q}%`);
    }

    const { data: results, error } = await query;

    if (error) {
      console.error('Entity search error:', error);
      return epProblem(500, 'search_failed', 'Search failed');
    }

    const filtered = await enrichWithCanonicalTrust(results || []);

    return NextResponse.json({
      entities: filtered,
      results: filtered,
      total: filtered.length,
      query: q,
      rank_by: rankBy,
    });
  } catch (err) {
    console.error('Entity search error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}
