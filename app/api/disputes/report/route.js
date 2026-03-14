import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import crypto from 'crypto';

/**
 * POST /api/disputes/report
 * 
 * Human appeal endpoint. No authentication required.
 * 
 * This exists because trust systems affect real people. A merchant wrongly
 * downgraded, a consumer harmed by a trusted-but-bad entity, or anyone
 * who sees something wrong should be able to raise their hand.
 * 
 * Reports are reviewed by operators. They can trigger formal disputes
 * against specific receipts.
 * 
 * "EP must never make trust more powerful than appeal."
 * 
 * Body: {
 *   entity_id: "merchant-xyz",       // the entity you're reporting about
 *   report_type: "wrongly_downgraded" | "harmed_by_trusted_entity" | 
 *                "fraudulent_entity" | "inaccurate_profile" | "other",
 *   description: "I am the merchant and my trust profile is wrong because...",
 *   contact_email: "merchant@example.com",  // optional, for follow-up
 *   evidence: { ... }                       // optional supporting data
 * }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id || !body.report_type || !body.description) {
      return NextResponse.json({
        error: 'entity_id, report_type, and description are required',
      }, { status: 400 });
    }

    const validTypes = [
      'wrongly_downgraded',
      'harmed_by_trusted_entity',
      'fraudulent_entity',
      'inaccurate_profile',
      'other',
    ];
    if (!validTypes.includes(body.report_type)) {
      return NextResponse.json({
        error: `Invalid report_type. Must be one of: ${validTypes.join(', ')}`,
      }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Verify the entity exists
    const { data: entity } = await supabase
      .from('entities')
      .select('id, entity_id, display_name')
      .eq('entity_id', body.entity_id)
      .single();

    if (!entity) {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    const reportId = `ep_rpt_${crypto.randomBytes(16).toString('hex')}`;

    const { error: insertError } = await supabase
      .from('trust_reports')
      .insert({
        report_id: reportId,
        entity_id: entity.id,
        report_type: body.report_type,
        description: body.description,
        contact_email: body.contact_email || null,
        evidence: body.evidence || null,
      });

    if (insertError) {
      console.error('Report filing error:', insertError);
      return NextResponse.json({ error: 'Failed to file report' }, { status: 500 });
    }

    return NextResponse.json({
      report_id: reportId,
      entity_id: body.entity_id,
      status: 'received',
      _message: 'Your report has been received and will be reviewed. If you provided a contact email, we will follow up.',
      _principle: 'EP must never make trust more powerful than appeal.',
    }, { status: 201 });
  } catch (err) {
    console.error('Report error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
