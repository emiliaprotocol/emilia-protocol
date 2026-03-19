import { NextResponse } from 'next/server';
import { canonicalFileReport } from '@/lib/canonical-writer';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { checkAbuse } from '@/lib/procedural-justice';
import { getServiceClient } from '@/lib/supabase';

/**
 * POST /api/disputes/report
 * 
 * Human appeal endpoint. No authentication required.
 * Routes through canonical writer with abuse detection.
 * 
 * "EP must never make trust more powerful than appeal."
 */
export async function POST(request) {
  try {
    const body = await request.json();

    // Accept both field naming conventions
    const entityId = body.entity_id;
    const reportType = body.report_type || body.reason;
    const description = body.description || body.details;

    if (!entityId || !reportType) {
      return EP_ERRORS.BAD_REQUEST('entity_id and report_type (or reason) are required');
    }

    const validTypes = [
      'wrongly_downgraded', 'harmed_by_trusted_entity',
      'fraudulent_entity', 'inaccurate_profile', 'other',
      'fake_receipts', 'unsafe_software', 'misleading_identity',
      'terms_violation', 'demo_challenge',
    ];
    if (!validTypes.includes(reportType)) {
      return EP_ERRORS.BAD_REQUEST(`Invalid report_type. Must be one of: ${validTypes.join(', ')}`);
    }

    // Abuse detection
    const reporterIp = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
    const supabase = getServiceClient();
    const abuseCheck = await checkAbuse(supabase, 'report', {
      entity_id: entityId,
      reason: reportType,
      reporter_ip: reporterIp,
    });

    if (!abuseCheck.allowed) {
      return epProblem(429, 'report_throttled', `Report throttled: ${abuseCheck.pattern}. Try again later.`, {
        pattern: abuseCheck.pattern,
      });
    }

    const result = await canonicalFileReport({
      entity_id: entityId,
      report_type: reportType,
      description: description || '',
    });

    if (result.error) {
      return epProblem(result.status || 500, 'report_failed', result.error);
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
