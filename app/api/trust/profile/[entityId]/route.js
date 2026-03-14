import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { computeTrustProfile } from '@/lib/scoring-v2';

/**
 * GET /api/trust/profile/:entityId
 *
 * The PRIMARY canonical read surface for EP trust data.
 * Returns the full trust profile — behavioral rates, signal breakdowns,
 * consistency, anomaly alerts, confidence, and establishment status.
 *
 * The compatibility score (emilia_score) is included but is NOT the
 * canonical truth object. The profile is.
 *
 * No auth required. Public endpoint.
 */
export async function GET(request, { params }) {
  try {
    const { entityId } = await params;
    const supabase = getServiceClient();

    // Resolve entity
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityId);
    const { data: entity } = await supabase
      .from('entities')
      .select('*')
      .eq(isUuid ? 'id' : 'entity_id', entityId)
      .single();

    if (!entity || entity.status !== 'active') {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    // Get receipts for profile computation
    const { data: receipts } = await supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entity.id)
      .order('created_at', { ascending: false })
      .limit(200);

    // Get canonical establishment
    let historicalEstablishment = { established: false, effective_evidence: 0, unique_submitters: 0, total_receipts: 0 };
    try {
      const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: entity.id });
      if (estData && estData[0]) {
        historicalEstablishment = estData[0];
      }
    } catch {}

    // Compute trust profile (v2 behavioral-first)
    const profile = computeTrustProfile(receipts || [], entity);

    return NextResponse.json({
      entity_id: entity.entity_id,
      display_name: entity.display_name,
      entity_type: entity.entity_type,
      description: entity.description,
      category: entity.category,
      capabilities: entity.capabilities,

      // The canonical trust object
      trust_profile: profile.profile,
      anomaly: profile.anomaly,

      // Current confidence (from scoring window)
      current_confidence: profile.confidence,
      effective_evidence_current: profile.effectiveEvidence,

      // Historical establishment (from all receipts)
      historical_establishment: historicalEstablishment.established,
      effective_evidence_historical: historicalEstablishment.effective_evidence,

      // Shared metadata
      unique_submitters: profile.uniqueSubmitters,
      receipt_count: profile.receiptCount,

      // Due process — dispute summary
      disputes: await (async () => {
        const { data: disputeData } = await supabase
          .from('disputes')
          .select('dispute_id, status, reason, created_at, resolved_at')
          .eq('entity_id', entity.id)
          .order('created_at', { ascending: false })
          .limit(10);
        const active = (disputeData || []).filter(d => ['open', 'under_review'].includes(d.status));
        const reversed = (disputeData || []).filter(d => d.status === 'reversed');
        return {
          total: (disputeData || []).length,
          active: active.length,
          reversed: reversed.length,
          recent: (disputeData || []).slice(0, 3).map(d => ({
            dispute_id: d.dispute_id,
            status: d.status,
            reason: d.reason,
          })),
        };
      })(),

      // Compatibility score (NOT the canonical truth — use trust_profile)
      compat_score: profile.score,
      _compat_note: 'Use trust_profile for trust decisions. compat_score is for sorting/backward compatibility only.',

      member_since: entity.created_at,
    });
  } catch (err) {
    console.error('Trust profile error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
