import { NextResponse } from 'next/server';
import { canonicalFileReport } from '@/lib/canonical-writer';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/disputes/report
 * 
 * Human appeal endpoint. No authentication required.
 * Routes through canonical writer.
 * 
 * "EP must never make trust more powerful than appeal."
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id || !body.report_type || !body.description) {
      return EP_ERRORS.BAD_REQUEST('entity_id, report_type, and description are required');
    }

    const validTypes = [
      'wrongly_downgraded', 'harmed_by_trusted_entity',
      'fraudulent_entity', 'inaccurate_profile', 'other',
    ];
    if (!validTypes.includes(body.report_type)) {
      return EP_ERRORS.BAD_REQUEST(`Invalid report_type. Must be one of: ${validTypes.join(', ')}`);
    }

    const result = await canonicalFileReport(body);

    if (result.error) {
      return NextResponse.json({ error: result.error }, { status: result.status || 500 });
    }

    return NextResponse.json({
      report_id: result.report_id,
      entity_id: result.entity_id,
      display_name: result.display_name,
      _message: 'Report received. An operator will review this.',
      _principle: 'Trust must never be more powerful than appeal.',
    }, { status: 201 });
  } catch (err) {
    console.error('Report filing error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
