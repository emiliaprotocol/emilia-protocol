import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';

/**
 * POST /api/trust/evaluate
 *
 * Evaluate an entity against a trust policy with optional context.
 * Routes through the canonical evaluator — same trust brain as profile and install-preflight.
 *
 * Body: { entity_id, policy, context }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id) {
      return NextResponse.json({ error: 'entity_id is required' }, { status: 400 });
    }

    const result = await canonicalEvaluate(body.entity_id, {
      context: body.context || null,
      policy: body.policy || 'standard',
      includeDisputes: false,
      includeEstablishment: true,
    });

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 404 });
    }

    const pr = result.policyResult;

    return NextResponse.json({
      entity_id: result.entity_id,
      display_name: result.display_name,
      entity_type: result.entity_type,

      pass: pr?.pass ?? null,
      policy_used: pr?.policyName || 'standard',
      context_used: result.contextUsed,

      score: result.score,
      confidence: result.confidence,
      effective_evidence: result.effectiveEvidence,

      profile: result.profile,
      anomaly: result.anomaly,

      failures: pr?.failures || [],
      warnings: pr?.warnings || [],

      _protocol_version: 'EP/1.1-v2',
    });
  } catch (err) {
    console.error('Trust evaluate error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
