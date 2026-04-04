import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/signoff/analytics?date_from=...&date_to=...
 *
 * Analytics data for signoff operations: completion rates,
 * approval rates, expiry rates, median resolution time, and
 * breakdowns by auth method and assurance level.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const url = new URL(request.url);
    const dateFrom = url.searchParams.get('date_from');
    const dateTo = url.searchParams.get('date_to');

    const supabase = getGuardedClient();

    // Query 1: challenges — provides status, timing, and volume
    // Tenant-scoped: only return data belonging to the authenticated tenant.
    let challengeQuery = supabase
      .from('signoff_challenges')
      .select('status, created_at, updated_at, expires_at')
      .eq('tenant_id', auth.tenantId);
    if (dateFrom) challengeQuery = challengeQuery.gte('created_at', dateFrom);
    if (dateTo) challengeQuery = challengeQuery.lte('created_at', dateTo);

    // Query 2: attestations — provides auth_method and assurance_level breakdowns
    let attestationQuery = supabase
      .from('signoff_attestations')
      .select('auth_method, assurance_level, approved_at, created_at')
      .eq('tenant_id', auth.tenantId);
    if (dateFrom) attestationQuery = attestationQuery.gte('created_at', dateFrom);
    if (dateTo) attestationQuery = attestationQuery.lte('created_at', dateTo);

    const [{ data: challenges, error: cErr }, { data: attestations, error: aErr }] =
      await Promise.all([challengeQuery, attestationQuery]);

    if (cErr) {
      logger.error('[cloud/signoff/analytics] Challenge query error:', cErr);
      return epProblem(500, 'signoff_analytics_query_failed', cErr.message);
    }
    if (aErr) {
      // Attestation table may not exist in older deployments; degrade gracefully.
      logger.warn('[cloud/signoff/analytics] Attestation query failed (degraded):', aErr.message);
    }

    const rows = challenges || [];
    const total = rows.length;

    // Status breakdown
    const byStatus = {};
    for (const c of rows) {
      byStatus[c.status] = (byStatus[c.status] || 0) + 1;
    }

    // Completion = resolved (approved + rejected) / total
    const completed = (byStatus['approved'] || 0) + (byStatus['rejected'] || 0);
    const expired = byStatus['expired'] || 0;
    const completionRate = total > 0 ? Math.round((completed / total) * 1000) / 10 : null;
    const approvalRate = completed > 0
      ? Math.round(((byStatus['approved'] || 0) / completed) * 1000) / 10
      : null;
    const expiryRate = total > 0 ? Math.round((expired / total) * 1000) / 10 : null;

    // Median resolution time in milliseconds (created_at → updated_at for resolved rows)
    const resolvedRows = rows.filter(
      (c) => ['approved', 'rejected'].includes(c.status) && c.created_at && c.updated_at,
    );
    let medianResolutionMs = null;
    if (resolvedRows.length > 0) {
      const durations = resolvedRows
        .map((c) => new Date(c.updated_at).getTime() - new Date(c.created_at).getTime())
        .filter((d) => d >= 0)
        .sort((a, b) => a - b);
      const mid = Math.floor(durations.length / 2);
      medianResolutionMs = durations.length % 2 === 0
        ? Math.round((durations[mid - 1] + durations[mid]) / 2)
        : durations[mid];
    }

    // Attestation breakdowns (if available)
    const attRows = attestations || [];
    const byAuthMethod = {};
    const byAssuranceLevel = {};
    for (const a of attRows) {
      if (a.auth_method) byAuthMethod[a.auth_method] = (byAuthMethod[a.auth_method] || 0) + 1;
      if (a.assurance_level) byAssuranceLevel[a.assurance_level] = (byAssuranceLevel[a.assurance_level] || 0) + 1;
    }

    return NextResponse.json({
      total,
      by_status: byStatus,
      completion_rate: completionRate,
      approval_rate: approvalRate,
      expiry_rate: expiryRate,
      median_resolution_ms: medianResolutionMs,
      by_auth_method: byAuthMethod,
      by_assurance_level: byAssuranceLevel,
      attestation_count: attRows.length,
      date_range: { from: dateFrom || null, to: dateTo || null },
      tenant_id: auth.tenantId,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    logger.error('[cloud/signoff/analytics] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
