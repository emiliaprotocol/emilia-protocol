import { NextResponse } from 'next/server';
import { EP_ERRORS } from '@/lib/errors';
import { getGuardedClient } from '@/lib/write-guard';
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
            reasons: pass === false ? (pr?.failures || []) : [],
            warnings: pr?.warnings || [],
            contextUsed: result.contextUsed,
            profileSummary: {
              confidence: result.confidence,
              evidence_level: result.effectiveEvidence,
              dispute_rate: result.profile?.behavioral?.dispute_rate ?? 0,
            },
            extensions: {
              pass,
              display_name: result.display_name,
              entity_type: result.entity_type,
              score: result.score,
              effective_evidence: result.effectiveEvidence,
              profile: result.profile,
              anomaly: result.anomaly,
              failures: pr?.failures || [],
              _protocol_version: 'EP/1.1-v2',
            },
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
    else if (score >= 0.6) decision = 'allow';
    else if (score >= 0.3) decision = 'review';
    else decision = 'deny';

    return NextResponse.json({
      decision,
      entity_id: entity.entity_id,
      policy_used: body.policy || 'standard',
      confidence: depth === 0 ? 'none' : depth < 5 ? 'low' : depth < 20 ? 'medium' : 'high',
      reasons: decision === 'deny' ? ['Trust score below threshold'] : [],
      warnings: depth < 5 ? ['Insufficient evidence depth'] : [],
      protocol_version: 'EP-CORE-v1.0',
    });
  } catch (err) {
    logger.error('Trust evaluate error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
