import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/entities/search
 * 
 * Search entities by capability, category, type, or semantic query.
 * Results ranked by match relevance * EMILIA Score.
 * 
 * No auth required — entity directory is public.
 * 
 * Query params:
 *   q          - semantic search query (uses embeddings)
 *   type       - filter by entity_type: agent, merchant, service_provider
 *   category   - filter by category: salon, legal, etc.
 *   capability - filter by capability keyword
 *   min_score  - minimum EMILIA Score (default 0)
 *   limit      - max results (default 20, max 50)
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const q = searchParams.get('q');
    const type = searchParams.get('type');
    const category = searchParams.get('category');
    const capability = searchParams.get('capability');
    const minScore = parseFloat(searchParams.get('min_score')) || 0;
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
            return NextResponse.json({
              results: results.map(r => ({
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
              })),
              total: results.length,
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
        entity_id, display_name, entity_type, description,
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

    return NextResponse.json({
      results: results || [],
      total: (results || []).length,
      query: q,
    });
  } catch (err) {
    console.error('Entity search error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
