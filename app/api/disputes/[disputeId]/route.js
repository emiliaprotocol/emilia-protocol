import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/disputes/[disputeId]
 * 
 * View the status and details of a dispute. Public — transparency is a protocol value.
 * 
 * The dispute lifecycle:
 *   open → under_review → upheld | reversed | superseded | dismissed
 * 
 * Reversed receipts have graph_weight = 0.0 (neutralized, never deleted).
 */
export async function GET(request, { params }) {
  try {
    const { disputeId } = await params;
    const supabase = getServiceClient();

    const { data: dispute, error } = await supabase
      .from('disputes')
      .select(`
        dispute_id, receipt_id, reason, description, evidence,
        status, filed_by_type,
        response, response_evidence, responded_at,
        resolution, resolution_rationale, resolved_by, resolved_at,
        response_deadline, created_at, updated_at,
        entity:entities!disputes_entity_id_fkey(entity_id, display_name),
        filer:entities!disputes_filed_by_fkey(entity_id, display_name)
      `)
      .eq('dispute_id', disputeId)
      .single();

    if (error || !dispute) {
      return NextResponse.json({ error: 'Dispute not found' }, { status: 404 });
    }

    return NextResponse.json({
      dispute_id: dispute.dispute_id,
      receipt_id: dispute.receipt_id,
      
      // Who is affected
      entity: dispute.entity,
      
      // Who filed
      filed_by: dispute.filer,
      filed_by_type: dispute.filed_by_type,
      
      // Dispute details
      reason: dispute.reason,
      description: dispute.description,
      evidence: dispute.evidence,
      
      // Lifecycle
      status: dispute.status,
      response_deadline: dispute.response_deadline,
      
      // Response (if any)
      response: dispute.response,
      response_evidence: dispute.response_evidence,
      responded_at: dispute.responded_at,
      
      // Resolution (if resolved)
      resolution: dispute.resolution,
      resolution_rationale: dispute.resolution_rationale,
      resolved_by: dispute.resolved_by,
      resolved_at: dispute.resolved_at,
      
      created_at: dispute.created_at,
      updated_at: dispute.updated_at,
    });
  } catch (err) {
    console.error('Dispute view error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
