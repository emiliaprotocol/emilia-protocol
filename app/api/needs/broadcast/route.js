import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import crypto from 'crypto';

/**
 * POST /api/needs/broadcast
 * 
 * Broadcast a need to the EMILIA network.
 * Agents declare what capability they need, and the network
 * matches them with entities that have the right skills + trust profile.
 * 
 * Auth: Bearer ep_live_...
 * 
 * Body: {
 *   capability_needed: "price_comparison",
 *   context: { "task_type": "purchase", "category": "electronics", "geo": "US-CA" },
 *   input_data: { product_id: "...", max_results: 5 },
 *   budget_cents: 50,
 *   deadline_ms: 30000,
 *   min_emilia_score: 70,
 *   trust_policy: "standard",
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
      // Serialize context for embedding — avoid [object Object] coercion
      const contextText = body.context
        ? (typeof body.context === 'object'
          ? Object.entries(body.context).map(([k, v]) => `${k}: ${v}`).join(', ')
          : String(body.context))
        : null;

      const embeddingText = [
        body.capability_needed,
        contextText,
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

    // Validate context — must be a structured object, not a freeform string
    let needContext = null;
    if (body.context) {
      if (typeof body.context === 'object' && body.context !== null) {
        needContext = body.context;
      } else if (typeof body.context === 'string') {
        // Attempt to parse JSON string; reject freeform text
        try {
          const parsed = JSON.parse(body.context);
          if (typeof parsed === 'object') needContext = parsed;
        } catch {
          return NextResponse.json({
            error: 'context must be a structured object (e.g. { "category": "electronics", "geo": "US-CA" }), not freeform text.',
          }, { status: 400 });
        }
      }
    }

    const needId = `ep_need_${crypto.randomBytes(16).toString('hex')}`;

    const { data: need, error: insertError } = await supabase
      .from('needs')
      .insert({
        need_id: needId,
        from_entity_id: auth.entity.id,
        capability_needed: body.capability_needed,
        context: needContext,
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

    // Find suggested entities
    let matches = [];
    if (embedding) {
      const { data: candidates } = await supabase.rpc('match_entities_to_need', {
        query_embedding: embedding,
        min_score: body.min_emilia_score || 0,
        match_limit: 20, // Fetch extra for post-filtering
        exclude_entity: auth.entity.id,
      });
      matches = candidates || [];
    }

    // If need has a trust_policy, evaluate each candidate and filter
    const needPolicy = need.trust_policy;
    let suggestions;

    if (needPolicy && matches.length > 0) {
      // Evaluate each candidate against the canonical trust evaluator — same trust brain as trust/profile and needs/claim
      const evaluated = await Promise.all(matches.map(async (m) => {
        const evaluation = await canonicalEvaluate(m.entity_id, {
          context: needContext,
          policy: needPolicy,
          includeDisputes: false,
          includeEstablishment: true,
        });

        return {
          entity_id: m.entity_id,
          display_name: m.display_name,
          compat_score: evaluation.score ?? m.emilia_score,
          match_score: m.match_score,
          trust_pass: evaluation.policyResult?.pass ?? false,
          confidence: evaluation.confidence || 'pending',
          effective_evidence: evaluation.effectiveEvidence || 0,
          context_used: evaluation.contextUsed || (needContext ? needContext : 'global'),
          failures: evaluation.policyResult?.failures || [],
          warnings: evaluation.policyResult?.warnings || [],
        };
      }));

      // Policy-passing entities first, then by match relevance
      suggestions = evaluated
        .sort((a, b) => {
          if (a.trust_pass !== b.trust_pass) return a.trust_pass ? -1 : 1;
          return (b.match_score || 0) - (a.match_score || 0);
        })
        .slice(0, 10);
    } else {
      // Legacy fallback: ranked by relevance × compatibility score
      suggestions = matches.slice(0, 10).map(m => ({
        entity_id: m.entity_id,
        display_name: m.display_name,
        compat_score: m.emilia_score,
        match_score: m.match_score,
      }));
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
      suggested_entities: suggestions,
      _suggestion_mode: needPolicy ? 'policy_evaluated' : 'legacy_compat',
    }, { status: 201 });
  } catch (err) {
    console.error('Need broadcast error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
