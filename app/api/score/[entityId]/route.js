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

    // CANONICAL DEFINITION: established = 5+ receipts AND 3+ unique submitters
    let uniqueSubmitters = 0;
    if (entity.total_receipts >= 5) {
      const { data: submitters } = await supabase
        .from('receipts')
        .select('submitted_by')
        .eq('entity_id', entity.id);
      uniqueSubmitters = new Set((submitters || []).map(r => r.submitted_by)).size;
    }
    const established = entity.total_receipts >= 5 && uniqueSubmitters >= 3;

    // Compute score confidence state
    // This tells consumers HOW MUCH to trust this score
    let confidence, confidence_message;
    if (entity.total_receipts === 0) {
      confidence = 'pending';
      confidence_message = 'No receipts yet. Score is default.';
    } else if (entity.emilia_score <= 55 && entity.total_receipts <= 10) {
      // Low score with few receipts = likely all from unestablished submitters
      confidence = 'insufficient';
      confidence_message = `${entity.total_receipts} receipt${entity.total_receipts === 1 ? '' : 's'} from unestablished submitters. Score reflects low credibility weight. Needs receipts from established entities to build a meaningful score.`;
    } else if (!established) {
      confidence = 'provisional';
      confidence_message = `${entity.total_receipts} receipt${entity.total_receipts === 1 ? '' : 's'} so far. Requires 5+ receipts from 3+ unique established submitters for full confidence.`;
    } else if (entity.total_receipts < 20) {
      confidence = 'emerging';
      confidence_message = `Established with ${entity.total_receipts} receipts. Score is meaningful but still building history.`;
    } else {
      confidence = 'confident';
      confidence_message = `${entity.total_receipts} receipts from multiple submitters. High confidence score.`;
    }

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      entity_type: entity.entity_type,
      description: entity.description,
      category: entity.category,
      capabilities: entity.capabilities,
      
      // The score
      emilia_score: entity.emilia_score,
      established,
      confidence,
      confidence_message,
      total_receipts: entity.total_receipts,
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
      } : null,
      
      // Verification
      verified: entity.verified,
      
      // Interoperability
      a2a_endpoint: entity.a2a_endpoint,
      ucp_profile_url: entity.ucp_profile_url,
      
      // Metadata
      member_since: entity.created_at,
    });
  } catch (err) {
    console.error('Score lookup error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
