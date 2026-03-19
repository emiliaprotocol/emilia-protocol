import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';
import { buildTrustDecision, passToDecision } from '@/lib/trust-decision';

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
      return EP_ERRORS.BAD_REQUEST('entity_id is required');
    }

    const result = await canonicalEvaluate(body.entity_id, {
      context: body.context || null,
      policy: body.policy || 'standard',
      includeDisputes: false,
      includeEstablishment: true,
    });

    if (result.error) {
      return EP_ERRORS.NOT_FOUND('Entity');
    }

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
        // Backward compatibility
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
  } catch (err) {
    console.error('Trust evaluate error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
