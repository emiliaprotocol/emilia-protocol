/**
 * GET /api/trust-desk/status/[engagementId]
 *
 * @license Apache-2.0
 *
 * Poll an engagement's pipeline status. Returns a SANITIZED view — no
 * uploaded-file paths, no raw intake PII beyond company + status — so it's
 * safe for the submitting customer to poll from the browser.
 */

import { NextResponse } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getEngagement } from '@/lib/trust-desk/store';

export const dynamic = 'force-dynamic';

export async function GET(_request, { params }) {
  const { engagementId } = await params;
  const eng = getEngagement(engagementId);
  if (!eng) return epProblem(404, 'not_found', 'engagement not found');

  const published = eng.status === 'published';
  return NextResponse.json({
    engagement_id: eng.engagement_id,
    company: eng.intake?.company || null,
    status: eng.status,
    outcome: eng.outcome || null,
    status_history: eng.status_history || [],
    trust_url: published && eng.slug ? `/trust-desk/c/${eng.slug}` : null,
    escalation_reason: eng.status === 'escalated' ? eng.escalation_reason : null,
    updated_at: eng.updated_at,
  });
}
