import { NextResponse } from 'next/server';
import { EP_ERRORS } from '@/lib/errors';
import { getGuardedClient } from '@/lib/write-guard';
import { authenticateRequest } from '@/lib/supabase';
import { isDemoEntity } from '@/lib/demo-entities';
import { logger } from '../../../../lib/logger.js';

let canonicalEvaluate, buildTrustDecision, passToDecision;
try {
  ({ canonicalEvaluate } = await import('@/lib/canonical-evaluator'));
  ({ buildTrustDecision, passToDecision } = await import('@/lib/trust-decision'));
} catch { /* optional deps — federation operators may not have full schema */ }

/**
 * POST /api/trust/evaluate
 *
 * Evaluate an entity against a trust policy with optional context.
 * Full operators route through the canonical evaluator.
 * Federation operators with minimal schema use a simple score-based decision.
 *
 * Body: { entity_id, policy, context }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id) {
      return EP_ERRORS.BAD_REQUEST('entity_id is required');
    }

    // Public demo carve-out: the synthetic demo entity is evaluable without auth
    // so the public /demo page works end-to-end. Every OTHER entity requires
    // authentication — this allowlist is the recon boundary (a real entity can't
    // be evaluated anonymously).
    if (!isDemoEntity(body.entity_id)) {
      const auth = await authenticateRequest(request);
      if (auth.error) return EP_ERRORS.UNAUTHORIZED();
    }

    // Try full canonical evaluation first
    if (canonicalEvaluate && buildTrustDecision) {
      try {
        const result = await canonicalEvaluate(body.entity_id, {
          context: body.context || null,
          policy: body.policy || 'standard',
          includeDisputes: false,
          includeEstablishment: true,
        });

        if (!result.error) {
          const pr = result.policyResult;
          const pass = pr?.pass ?? null;

          return NextResponse.json(buildTrustDecision({
            decision: pass === null ? 'review' : passToDecision(pass),
            entityId: result.entity_id,
            policyUsed: pr?.policyName || 'standard',
            confidence: result.confidence,
            reasons: pass === false ? ['policy_not_satisfied'] : [],
            warnings: pr?.warnings?.length ? ['review_recommended'] : [],
            contextUsed: result.contextUsed,
            profileSummary: null,
            extensions: { _protocol_version: 'EP/1.1-v2' },
          }));
        }
      } catch { /* fall through to simple evaluation */ }
    }

    // Simple evaluation fallback — works with minimal federation schema
    const supabase = getGuardedClient();
    const { data: entity, error } = await supabase
      .from('entities')
      .select('entity_id, display_name, emilia_score, total_receipts')
      .eq('entity_id', body.entity_id)
      .single();

    if (error || !entity) {
      return EP_ERRORS.NOT_FOUND('Entity');
    }

    const score = entity.emilia_score / 100;
    const depth = entity.total_receipts || 0;
    let decision;
    if (depth === 0) decision = 'review';
    // Fail conservative: the fallback path does not have v2 quality-gated
    // evidence, concentration caps, dispute dampening, or software checks. It
    // can guide manual review, but it must never produce an allow decision.
    else if (score >= 0.3) decision = 'review';
    else decision = 'deny';

    return NextResponse.json({
      decision,
      entity_id: entity.entity_id,
      policy_used: body.policy || 'standard',
      confidence: depth === 0 ? 'none' : depth < 5 ? 'low' : depth < 20 ? 'medium' : 'high',
      reasons: decision === 'deny' ? ['policy_not_satisfied'] : [],
      protocol_version: 'EP-CORE-v1.0',
      degraded: true,
      warnings: ['canonical_evaluator_unavailable', ...(depth < 5 ? ['review_recommended'] : [])],
    });
  } catch (err) {
    logger.error('Trust evaluate error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
