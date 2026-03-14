import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/score/[entityId]
 * 
 * Look up an entity's EMILIA Score. This is the public API.
 * No authentication required — scores are public by design.
 * 
 * "Check their EMILIA Score."
 * 
 * Returns: {
 *   entity_id: "rex-booking-v2",
 *   display_name: "Rex — Inbound AI Receptionist",
 *   emilia_score: 94.2,
 *   established: true,
 *   total_receipts: 1284,
 *   breakdown: { delivery_accuracy: 96.1, product_accuracy: 92.3, ... },
 *   verified: true,
 *   entity_type: "agent",
 * }
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;
    const supabase = getServiceClient();

    // Look up by entity_id (slug) or uuid
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityId);

    const { data: entity, error } = await supabase
      .from('entities')
      .select(`
        id, entity_id, display_name, entity_type, description,
        category, service_area, capabilities,
        emilia_score, total_receipts, successful_receipts,
        avg_delivery_accuracy, avg_product_accuracy,
        avg_price_integrity, avg_return_processing,
        avg_agent_satisfaction, score_consistency,
        verified, verified_at,
        a2a_endpoint, ucp_profile_url,
        status, created_at
      `)
      .eq(isUuid ? 'id' : 'entity_id', entityId)
      .single();

    if (error || !entity) {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    if (entity.status !== 'active') {
      return NextResponse.json({ error: 'Entity is not active' }, { status: 404 });
    }

    // CANONICAL ESTABLISHMENT via DB function
    let established = false;
    let uniqueSubmitters = 0;
    let effectiveEvidence = 0;
    try {
      const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: entity.id });
      if (estData && estData[0]) {
        established = estData[0].established;
        uniqueSubmitters = estData[0].unique_submitters;
        effectiveEvidence = estData[0].effective_evidence;
      }
    } catch {
      established = false;
    }

    // Confidence is driven by EFFECTIVE EVIDENCE, not raw receipt count.
    // Establishment is HISTORICAL (has this entity ever been credible?).
    // Confidence is CURRENT (how much should you trust this score right now?).
    let confidence, confidence_message;
    if (effectiveEvidence === 0) {
      confidence = 'pending';
      confidence_message = 'No meaningful evidence yet. Score is default.';
    } else if (effectiveEvidence < 1.0) {
      confidence = 'insufficient';
      confidence_message = `Effective evidence: ${effectiveEvidence}. Receipts exist but carry very low credibility weight. Needs receipts from established entities.`;
    } else if (effectiveEvidence < 5.0) {
      confidence = 'provisional';
      confidence_message = `Effective evidence: ${effectiveEvidence}/5.0 needed. Building credible history.`;
    } else if (effectiveEvidence < 20.0) {
      confidence = 'emerging';
      confidence_message = `Effective evidence: ${effectiveEvidence}. Score is meaningful and building depth.`;
    } else {
      confidence = 'confident';
      confidence_message = `Effective evidence: ${effectiveEvidence} from ${uniqueSubmitters} unique submitters. High confidence.`;
    }

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      entity_type: entity.entity_type,
      description: entity.description,
      category: entity.category,
      capabilities: entity.capabilities,
      
      // Compatibility score — use POST /api/trust/evaluate for full trust profiles
      emilia_score: entity.emilia_score,
      _score_note: 'Compatibility score. For trust decisions, use POST /api/trust/evaluate with a policy.',
      
      // Trust status
      established,
      effective_evidence: effectiveEvidence,
      confidence,
      confidence_message,
      total_receipts: entity.total_receipts,
      unique_submitters: uniqueSubmitters,
      successful_receipts: entity.successful_receipts,
      success_rate: entity.total_receipts > 0
        ? Math.round((entity.successful_receipts / entity.total_receipts) * 1000) / 10
        : null,
      
      // Score breakdown — only shown when confidence is emerging or higher
      breakdown: (confidence === 'emerging' || confidence === 'confident') ? {
        delivery_accuracy: entity.avg_delivery_accuracy,
        product_accuracy: entity.avg_product_accuracy,
        price_integrity: entity.avg_price_integrity,
        return_processing: entity.avg_return_processing,
        agent_satisfaction: entity.avg_agent_satisfaction,
        consistency: entity.score_consistency,
        _note: 'Historical unweighted averages. The emilia_score uses submitter-weighted, time-decayed computation.',
      } : null,
      
      verified: entity.verified,
      a2a_endpoint: entity.a2a_endpoint,
      ucp_profile_url: entity.ucp_profile_url,
      member_since: entity.created_at,
    });
  } catch (err) {
    console.error('Score lookup error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
