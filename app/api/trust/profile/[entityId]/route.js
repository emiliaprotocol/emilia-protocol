import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/trust/profile/:entityId
 *
 * The PRIMARY canonical read surface for EP trust data.
 * Routes through the canonical evaluator — same trust brain
 * used by evaluate, install-preflight, needs/claim, and MCP.
 *
 * No auth required. Public endpoint.
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;

    const result = await canonicalEvaluate(entityId, {
      includeDisputes: true,
      includeEstablishment: true,
    });

    if (result.error) {
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

      compat_score: result.score,
      _compat_score_legacy: true,
      _compat_note: 'DEPRECATED: compat_score is a legacy sort key on 0-100 scale. New trust-critical features MUST use trust_profile, policy evaluation, or confidence state — never raw score. See PROTOCOL-STANDARD.md §20.',

      member_since: result._entity.created_at,
      _protocol_version: 'EP/1.1-v2',
    });
  } catch (err) {
    console.error('Trust profile error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
