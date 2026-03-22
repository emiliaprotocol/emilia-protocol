import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { requirePermission } from '@/lib/cloud/authorize';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem, EP_ERRORS } from '@/lib/errors';

/**
 * GET /api/cloud/signoff/dashboard
 *
 * Summary dashboard data for signoff operations:
 * counts by status, recent activity, and processing metrics.
 * Requires: read permission.
 */
export async function GET(request) {
  try {
    const auth = await authenticateCloudRequest(request);
    if (!auth) return EP_ERRORS.UNAUTHORIZED();
    requirePermission(auth, 'read');

    const supabase = getGuardedClient();

    const [pending, completed, expired, total] = await Promise.all([
      supabase
        .from('signoff_challenges')
        .select('id', { count: 'exact', head: true })
        .eq('status', 'pending'),
      supabase
        .from('signoff_challenges')
        .select('id', { count: 'exact', head: true })
        .eq('status', 'completed'),
      supabase
        .from('signoff_challenges')
        .select('id', { count: 'exact', head: true })
        .eq('status', 'expired'),
      supabase
        .from('signoff_challenges')
        .select('id', { count: 'exact', head: true }),
    ]);

    return NextResponse.json({
      summary: {
        pending: pending.count || 0,
        completed: completed.count || 0,
        expired: expired.count || 0,
        total: total.count || 0,
      },
      tenant_id: auth.tenantId,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    if (err.name === 'CloudAuthorizationError') {
      return epProblem(403, 'forbidden', err.message);
    }
    console.error('[cloud/signoff/dashboard] Error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
