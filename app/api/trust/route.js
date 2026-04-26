import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';

/**
 * GET /api/trust?entity_id=ep_entity_...
 *
 * Protocol-standard trust profile endpoint.
 * Returns the trust profile for a given entity in conformance-standard format.
 *
 * Conformance-required fields: entity_id, score, confidence, evidence_depth.
 *
 * @public — no authentication required. Trust profiles are public by design.
 */
export async function GET(request) {
  try {
    const url = new URL(request.url);
    const entityId = url.searchParams.get('entity_id');

    if (!entityId) {
      return epProblem(400, 'missing_entity_id', 'entity_id query parameter is required');
    }

    const supabase = getGuardedClient();

    const { data: entity, error } = await supabase
      .from('entities')
      .select('entity_id, display_name, emilia_score, total_receipts, successful_receipts, dispute_count, created_at')
      .eq('entity_id', entityId)
      .single();

    if (error || !entity) {
      return epProblem(404, 'entity_not_found', 'Entity not found');
    }

    // Compute conformance-standard trust profile fields
    const score = entity.emilia_score / 100; // normalize to 0-1
    const evidenceDepth = entity.total_receipts || 0;
    let confidence;
    if (evidenceDepth === 0) confidence = 'none';
    else if (evidenceDepth < 5) confidence = 'low';
    else if (evidenceDepth < 20) confidence = 'medium';
    else confidence = 'high';

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      score: Math.round(score * 100) / 100,
      confidence,
      evidence_depth: evidenceDepth,
      successful_interactions: entity.successful_receipts || 0,
      dispute_count: entity.dispute_count || 0,
      first_seen: entity.created_at,
      protocol_version: 'EP-CORE-v1.0',
    });
  } catch (err) {
    return epProblem(500, 'internal_error', 'Failed to fetch trust profile');
  }
}
