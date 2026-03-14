import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/entities/search
 * 
 * Search entities by capability, category, type, or semantic query.
 * 
 * No auth required — entity directory is public.
 * 
 * Query params:
 *   q              - semantic search query (uses embeddings)
 *   type           - filter by entity_type: agent, merchant, service_provider
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

            // Apply min_confidence filter to semantic results too
            if (minConfidence && semanticResults.length > 0) {
              const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];
              const minIdx = confLevels.indexOf(minConfidence);
              if (minIdx >= 0) {
                const withConf = await Promise.all(semanticResults.map(async (e) => {
                  let ee = 0;
                  try {
                    const { data: d } = await supabase.rpc('is_entity_established', { p_entity_id: e.id });
                    if (d && d[0]) ee = d[0].effective_evidence;
                  } catch {}
                  let c = ee === 0 ? 'pending' : ee < 1 ? 'insufficient' : ee < 5 ? 'provisional' : ee < 20 ? 'emerging' : 'confident';
                  return { ...e, confidence: c, effective_evidence: ee };
                }));
                semanticResults = withConf.filter(e => confLevels.indexOf(e.confidence) >= minIdx);
              }
            }

            return NextResponse.json({
              entities: semanticResults,
              results: semanticResults,
              total: semanticResults.length,
              query: q,
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
      // Text search fallback
      query = query.or(`display_name.ilike.%${q}%,description.ilike.%${q}%,entity_id.ilike.%${q}%`);
    }

    const { data: results, error } = await query;

    if (error) {
      console.error('Entity search error:', error);
      return NextResponse.json({ error: 'Search failed' }, { status: 500 });
    }

    let filtered = results || [];
    const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];

    // Always enrich with confidence and effective evidence
    if (filtered.length > 0) {
      filtered = await Promise.all(filtered.map(async (e) => {
        let effectiveEvidence = 0;
        try {
          const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: e.id });
          if (estData && estData[0]) effectiveEvidence = estData[0].effective_evidence;
        } catch {}
        let conf;
        if (effectiveEvidence === 0) conf = 'pending';
        else if (effectiveEvidence < 1.0) conf = 'insufficient';
        else if (effectiveEvidence < 5.0) conf = 'provisional';
        else if (effectiveEvidence < 20.0) conf = 'emerging';
        else conf = 'confident';
        return { ...e, confidence: conf, effective_evidence: effectiveEvidence };
      }));
    }

    // Filter by min_confidence
    if (minConfidence) {
      const minIdx = confLevels.indexOf(minConfidence);
      if (minIdx >= 0) {
        filtered = filtered.filter(e => confLevels.indexOf(e.confidence) >= minIdx);
      }
    }

    // Re-rank by selected criterion
    if (rankBy === 'evidence') {
      filtered.sort((a, b) => b.effective_evidence - a.effective_evidence);
    } else if (rankBy === 'confidence') {
      filtered.sort((a, b) => {
        const ca = confLevels.indexOf(a.confidence);
        const cb = confLevels.indexOf(b.confidence);
        if (cb !== ca) return cb - ca;
        return b.effective_evidence - a.effective_evidence;
      });
    }
    // Default 'score' keeps DB ordering

    return NextResponse.json({
      entities: filtered,
      results: filtered,
      total: filtered.length,
      query: q,
      rank_by: rankBy,
    });
  } catch (err) {
    console.error('Entity search error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
