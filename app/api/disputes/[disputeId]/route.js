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
        appeal_reason, appeal_evidence, appealed_at, appealed_by,
        appeal_resolution, appeal_rationale, appeal_resolved_by, appeal_resolved_at,
        response_deadline, created_at, updated_at,
        entity:entities!disputes_entity_id_fkey(entity_id, display_name),
        filer:entities!disputes_filed_by_fkey(entity_id, display_name)
      `)
      .eq('dispute_id', disputeId)
      .single();

    if (error || !dispute) {
      return NextResponse.json({ error: 'Dispute not found' }, { status: 404 });
    }

    // Redact evidence for public view — show field names but not raw values
    // Full evidence is restricted to dispute participants and operators
    function redactEvidence(evidence) {
      if (!evidence || typeof evidence !== 'object') return null;
      const redacted = {};
      for (const key of Object.keys(evidence)) {
        const val = evidence[key];
        if (typeof val === 'string' && val.length > 20) {
          redacted[key] = `[redacted — ${val.length} chars]`;
        } else if (typeof val === 'string') {
          redacted[key] = val; // Short values like status codes are safe
        } else if (typeof val === 'boolean' || typeof val === 'number') {
          redacted[key] = val;
        } else {
          redacted[key] = '[redacted]';
        }
      }
      return redacted;
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
      evidence_summary: redactEvidence(dispute.evidence),
      _evidence_note: 'Full evidence is restricted to dispute participants and operators.',
      
      // Lifecycle
      status: dispute.status,
      response_deadline: dispute.response_deadline,
      
      // Response (if any)
      has_response: !!dispute.response,
      responded_at: dispute.responded_at,
      
      // Resolution (if resolved)
      resolution: dispute.resolution,
      resolution_rationale: dispute.resolution_rationale,
      resolved_by: dispute.resolved_by,
      resolved_at: dispute.resolved_at,
      
      // Appeal details (if applicable)
      appeal_reason: dispute.appeal_reason,
      appealed_at: dispute.appealed_at,
      appeal_resolution: dispute.appeal_resolution,
      appeal_rationale: dispute.appeal_rationale,
      appeal_resolved_by: dispute.appeal_resolved_by,
      appeal_resolved_at: dispute.appeal_resolved_at,

      created_at: dispute.created_at,
      updated_at: dispute.updated_at,
    });
  } catch (err) {
    console.error('Dispute view error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
