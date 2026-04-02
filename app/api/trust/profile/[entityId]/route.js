import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/trust/profile/:entityId
 *
 * The PRIMARY canonical read surface for EP trust data.
 * Routes through the canonical evaluator — same trust brain
 * used by evaluate, pre-action enforcement, needs/claim, and MCP.
 *
 * No auth required. Public endpoint.
 *
 * Optional query parameter:
 *   ?weights=<JSON> — Custom scoring weights. When provided, returns both
 *     canonical_score (protocol defaults) and policy_score (custom weights)
 *     in a `policy_scoring` block. Weights must pass validation (sum to 1.0,
 *     within hard bounds). See docs/architecture/ADAPTIVE_SCORING.md.
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;

    // Parse optional custom scoring weights from query string
    let scoringWeights = null;
    const weightsParam = request.nextUrl.searchParams.get('weights');
    if (weightsParam) {
      try {
        // Guard payload size — prevent DoS via deeply nested JSON
        if (weightsParam.length > 512) {
          return epProblem(400, 'weights_too_large', 'Weights JSON must be < 512 bytes');
        }
        scoringWeights = JSON.parse(weightsParam);
      } catch {
        return epProblem(400, 'invalid_weights_json', 'weights parameter must be valid JSON');
      }
    }

    const result = await canonicalEvaluate(entityId, {
      includeDisputes: true,
      includeEstablishment: true,
      scoringWeights,
    });

    if (result.error) {
      if (result.status === 400) {
        return epProblem(400, 'invalid_scoring_weights', result.error, { details: result.details });
      }
      return EP_ERRORS.NOT_FOUND('Entity');
    }

    return NextResponse.json({
      entity_id: result.entity_id,
      display_name: result.display_name,
      entity_type: result.entity_type,
      description: result._entity.description,
      category: result.category,
      capabilities: result._entity.capabilities,

      trust_profile: result.profile,
      anomaly: result.anomaly,

      current_confidence: result.confidence,
      effective_evidence_current: result.effectiveEvidence,
      quality_gated_evidence_current: result.qualityGatedEvidence,

      historical_establishment: result.establishment?.established || false,
      effective_evidence_historical: result.establishment?.effective_evidence || 0,
      unique_submitters: result.uniqueSubmitters,
      receipt_count: result.receiptCount,

      disputes: result.disputes,
      disputesDampened: result.dispute_dampened_count,

      // Scoring metadata
      weights_version: result.weights_version,
      policy_scoring: result.policyScoring,

      compat_score: result.score,
      _compat_score_legacy: true,
      _compat_note: 'DEPRECATED: compat_score is a legacy sort key on 0-100 scale. New trust-critical features MUST use trust_profile, policy evaluation, or confidence state — never raw score. See PROTOCOL-STANDARD.md §20.',

      member_since: result._entity.created_at,
      _protocol_version: 'EP/1.1-v2',
    });
  } catch (err) {
    logger.error('Trust profile error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
