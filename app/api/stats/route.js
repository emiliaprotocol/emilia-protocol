import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { TRUST_POLICIES } from '@/lib/scoring-v2';
import { readFileSync } from 'fs';
import { join } from 'path';
import { epProblem } from '@/lib/errors';
import { authenticateRequest } from '@/lib/supabase';

/**
 * GET /api/stats
 *
 * Auth-scoped stats for internal/operator dashboards.
 * Reads proof metrics from generated/proof-metrics.json (single source of truth).
 * Derives entity count live from DB, policy count from code.
 */

let proofMetrics = null;
try {
  const raw = readFileSync(join(process.cwd(), 'generated/proof-metrics.json'), 'utf8');
  proofMetrics = JSON.parse(raw);
} catch {
  proofMetrics = null;
}

// Bucket a precise count into a recon-safe floor: the public surface conveys
// scale/momentum without leaking exact system size. <100 -> nearest 10,
// <1000 -> nearest 100, else nearest 1000.
function bucketCount(n) {
  if (!n || n <= 0) return 0;
  const step = n < 100 ? 10 : n < 1000 ? 100 : 1000;
  return Math.floor(n / step) * step;
}

export async function GET(request) {
  const policyCount = Object.keys(TRUST_POLICIES).length;

  // Public, recon-safe projection for marketing surfaces (e.g. /network): the
  // entity count is bucketed (approximate) and only static proof metrics are
  // exposed. Exact live counts remain operator-only below. Uses new URL() (not
  // request.nextUrl) so it also resolves for a plain Request in tests.
  if (new URL(request.url).searchParams.get('view') === 'public') {
    let bucketedEntities = null;
    try {
      const supabase = getGuardedClient();
      const { count } = await supabase
        .from('entities')
        .select('id', { count: 'exact', head: true })
        .eq('status', 'active');
      bucketedEntities = bucketCount(count || 0);
    } catch {
      /* public surface degrades to marketing facts — never error */
    }
    return NextResponse.json({
      total_entities: bucketedEntities,
      total_entities_approx: true,
      trust_surfaces: proofMetrics?.trust_surfaces ?? null,
      automated_checks: proofMetrics?.automated_checks ?? null,
      trust_policies: policyCount,
      mcp_tools: proofMetrics?.mcp_tools ?? null,
      proof_metrics_status: proofMetrics ? 'ok' : 'missing',
      view: 'public',
    });
  }

  const auth = await authenticateRequest(request);
  if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);

  try {
    const supabase = getGuardedClient();

    const { count } = await supabase
      .from('entities')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'active');

    const total = count || 2;

    return NextResponse.json({
      total_entities: total,
      trust_surfaces: proofMetrics?.trust_surfaces ?? null,
      automated_checks: proofMetrics?.automated_checks ?? null,
      trust_policies: policyCount,
      mcp_tools: proofMetrics?.mcp_tools ?? null,
      proof_metrics_status: proofMetrics ? 'ok' : 'missing',
    });
  } catch (err) {
    return epProblem(500, 'stats_unavailable', 'Failed to retrieve system statistics');
  }
}
