import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import crypto from 'crypto';

/**
 * POST /api/needs/broadcast
 * 
 * Broadcast a need to the EMILIA network.
 * Agents declare what capability they need, and the network
 * matches them with entities that have the right skills + reputation.
 * 
 * Auth: Bearer ep_live_...
 * 
 * Body: {
 *   capability_needed: "price_comparison",
 *   context: "Need to compare prices for a Sony WH-1000XM5 across 5 retailers",
 *   input_data: { product_id: "...", max_results: 5 },
 *   budget_cents: 50,
 *   deadline_ms: 30000,
 *   min_emilia_score: 70,
 *   trust_policy: "standard",    // optional: "strict", "standard", "permissive", "discovery" or custom JSON
 * }
 */
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return NextResponse.json({ error: auth.error }, { status: 401 });
    }

    const body = await request.json();
    const supabase = getServiceClient();

    if (!body.capability_needed) {
      return NextResponse.json({ error: 'capability_needed is required' }, { status: 400 });
    }

    // Generate embedding for semantic matching
    let embedding = null;
    if (process.env.OPENAI_API_KEY) {
      const embeddingText = [
        body.capability_needed,
        body.context,
      ].filter(Boolean).join('. ');

      try {
        const embRes = await fetch('https://api.openai.com/v1/embeddings', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'text-embedding-3-small',
            input: embeddingText,
          }),
        });

        if (embRes.ok) {
          const embData = await embRes.json();
          embedding = embData.data[0].embedding;
        }
      } catch (e) {
        // Embedding generation failed — continue without it
        console.warn('Embedding generation failed:', e.message);
      }
    }

    const needId = `ep_need_${crypto.randomBytes(16).toString('hex')}`;

    const { data: need, error: insertError } = await supabase
      .from('needs')
      .insert({
        need_id: needId,
        from_entity_id: auth.entity.id,
        capability_needed: body.capability_needed,
        context: body.context || null,
        input_data: body.input_data || null,
        budget_cents: body.budget_cents || null,
        deadline_ms: body.deadline_ms || null,
        min_emilia_score: body.min_emilia_score || 0,
        trust_policy: body.trust_policy || null,
        need_embedding: embedding,
        expires_at: body.expires_at || null, // trigger will default to 24h
      })
      .select()
      .single();

    if (insertError) {
      console.error('Need broadcast error:', insertError);
      return NextResponse.json({ error: 'Failed to broadcast need' }, { status: 500 });
    }

    // Find suggested entities (legacy: ranked by relevance × compatibility score)
    // These are compatibility suggestions only. For trust-native routing,
    // set trust_policy on the need and claim evaluation will use it.
    let matches = [];
    if (embedding) {
      const { data: candidates } = await supabase.rpc('match_entities_to_need', {
        query_embedding: embedding,
        min_score: body.min_emilia_score || 0,
        match_limit: 10,
        exclude_entity: auth.entity.id,
      });
      matches = candidates || [];
    }

    return NextResponse.json({
      need: {
        need_id: need.need_id,
        capability_needed: need.capability_needed,
        status: need.status,
        min_emilia_score: need.min_emilia_score,
        trust_policy: need.trust_policy || null,
        expires_at: need.expires_at,
        created_at: need.created_at,
      },
      suggested_entities: matches.map(m => ({
        entity_id: m.entity_id,
        display_name: m.display_name,
        compat_score: m.emilia_score,
        match_score: m.match_score,
        _note: 'Ranked by compatibility score. Use trust_policy on the need for policy-native claim evaluation.',
      })),
    }, { status: 201 });
  } catch (err) {
    console.error('Need broadcast error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
