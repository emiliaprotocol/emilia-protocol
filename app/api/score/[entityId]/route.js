import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { computeTrustProfile } from '@/lib/scoring-v2';

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

    // HISTORICAL ESTABLISHMENT via DB function (all receipts, permanent)
    let historicalEstablished = false;
    let historicalEvidence = 0;
    let uniqueSubmitters = 0;
    try {
      const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: entity.id });
      if (estData && estData[0]) {
        historicalEstablished = estData[0].established;
        historicalEvidence = estData[0].effective_evidence;
        uniqueSubmitters = estData[0].unique_submitters;
      }
    } catch {
      historicalEstablished = false;
    }

    // CURRENT CONFIDENCE from rolling window (via computeTrustProfile)
    const { data: receipts } = await supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entity.id)
      .order('created_at', { ascending: false })
      .limit(200);

    const profile = computeTrustProfile(receipts || [], entity);

    // Current confidence from the windowed trust profile
    const confidence = profile.confidence;
    const currentEvidence = profile.effectiveEvidence;
    let confidence_message;
    if (currentEvidence === 0) {
      confidence_message = 'No meaningful evidence in current window.';
    } else if (currentEvidence < 1.0) {
      confidence_message = `Current effective evidence: ${currentEvidence}. Very low credibility weight.`;
    } else if (currentEvidence < 5.0) {
      confidence_message = `Current effective evidence: ${currentEvidence}/5.0 needed. Building history.`;
    } else if (currentEvidence < 20.0) {
      confidence_message = `Current effective evidence: ${currentEvidence}. Score is meaningful.`;
    } else {
      confidence_message = `Current effective evidence: ${currentEvidence} from ${profile.uniqueSubmitters} submitters. High confidence.`;
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
      _score_note: 'Compatibility score. For trust decisions, use GET /api/trust/profile/:entityId or POST /api/trust/evaluate.',
      
      // Historical establishment (permanent, all receipts)
      established: historicalEstablished,
      effective_evidence_historical: historicalEvidence,

      // Current confidence (rolling window)
      confidence,
      confidence_message,
      effective_evidence_current: currentEvidence,

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
