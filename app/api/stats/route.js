import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { TRUST_POLICIES } from '@/lib/scoring-v2';
import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * GET /api/stats
 *
 * Public stats for the landing page.
 * Reads proof metrics from generated/proof-metrics.json (single source of truth).
 * Derives entity count live from DB, policy count from code.
 * No auth required.
 */

let proofMetrics = null;
try {
  const raw = readFileSync(join(process.cwd(), 'generated/proof-metrics.json'), 'utf8');
  proofMetrics = JSON.parse(raw);
} catch {
  proofMetrics = null;
}

export async function GET() {
  try {
    const supabase = getServiceClient();

    const { count } = await supabase
      .from('entities')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'active');

    const total = count || 2;
    const policyCount = Object.keys(TRUST_POLICIES).length;

    return NextResponse.json({
      total_entities: total,
      next_available: total + 1,
      trust_surfaces: proofMetrics?.trust_surfaces ?? null,
      automated_checks: proofMetrics?.automated_checks ?? null,
      trust_policies: policyCount,
      mcp_tools: proofMetrics?.mcp_tools ?? null,
      proof_metrics_status: proofMetrics ? 'ok' : 'missing',
    });
  } catch (err) {
    return NextResponse.json({
      total_entities: 2,
      next_available: 3,
      trust_surfaces: proofMetrics?.trust_surfaces ?? null,
      automated_checks: proofMetrics?.automated_checks ?? null,
      trust_policies: 8,
      mcp_tools: proofMetrics?.mcp_tools ?? null,
      proof_metrics_status: proofMetrics ? 'ok' : 'missing',
    });
  }
}
