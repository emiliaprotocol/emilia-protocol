import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { computeTrustProfile, evaluateTrustPolicy, TRUST_POLICIES } from '@/lib/scoring-v2';

/**
 * POST /api/trust/evaluate
 *
 * Evaluate an entity against a trust policy.
 * This is how agents CONSUME EP — not "check score > 70" but
 * "does this entity pass my trust policy for high-value purchases?"
 *
 * Body: {
 *   entity_id: "merchant-xyz",
 *   policy: "strict" | "standard" | "permissive" | "discovery" | { custom policy object }
 * }
 *
 * Returns: {
 *   entity_id, pass, score, confidence, profile, failures, warnings
 * }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id) {
      return NextResponse.json({ error: 'entity_id is required' }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Look up entity
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.entity_id);
    const { data: entity } = await supabase
      .from('entities')
      .select('*')
      .eq(isUuid ? 'id' : 'entity_id', body.entity_id)
      .single();

    if (!entity || entity.status !== 'active') {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    // Get receipts — optionally filtered by context
    let receiptQuery = supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entity.id)
      .order('created_at', { ascending: false })
      .limit(200);

    // If context provided, filter receipts to matching context
    // This makes trust evaluation context-specific rather than global
    const requestContext = body.context || null;
    if (requestContext) {
      // Filter by matching context fields using JSONB containment
      receiptQuery = receiptQuery.contains('context', requestContext);
    }

    const { data: contextReceipts } = await receiptQuery;

    // If context filtering produced too few receipts, fall back to global
    let receipts = contextReceipts || [];
    let contextUsed = null;
    if (requestContext && receipts.length < 3) {
      // Not enough context-specific data — fall back to global receipts
      const { data: globalReceipts } = await supabase
        .from('receipts')
        .select('*')
        .eq('entity_id', entity.id)
        .order('created_at', { ascending: false })
        .limit(200);
      receipts = globalReceipts || [];
      contextUsed = 'global_fallback';
    } else if (requestContext) {
      contextUsed = requestContext;
    } else {
      contextUsed = 'global';
    }

    // Compute trust profile
    const profile = computeTrustProfile(receipts, entity);

    // Resolve policy
    let policy;
    if (typeof body.policy === 'string') {
      policy = TRUST_POLICIES[body.policy];
      if (!policy) {
        return NextResponse.json({
          error: `Unknown policy: ${body.policy}. Available: ${Object.keys(TRUST_POLICIES).join(', ')}`,
        }, { status: 400 });
      }
    } else if (typeof body.policy === 'object') {
      policy = body.policy;
    } else {
      policy = TRUST_POLICIES.standard;
    }

    // Evaluate
    const result = evaluateTrustPolicy(profile, policy);

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      pass: result.pass,
      policy_used: typeof body.policy === 'string' ? body.policy : 'custom',
      context_used: contextUsed,
      receipts_evaluated: receipts.length,
      score: profile.score,
      confidence: profile.confidence,
      effective_evidence: profile.effectiveEvidence,
      profile: profile.profile,
      anomaly: profile.anomaly,
      failures: result.failures,
      warnings: result.warnings,
    });
  } catch (err) {
    console.error('Trust evaluation error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
