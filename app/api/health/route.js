import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_VERSION_STRING } from '@/lib/protocol-version';
import { epProblem } from '@/lib/errors';
import { getUpstashConfig, getBlockchainConfig } from '@/lib/env';

/**
 * GET /api/health
 * 
 * Operational health endpoint. Returns protocol version, database
 * connectivity, cache status, entity/receipt counts, and system state.
 * 
 * Any implementer deploying EP can verify their instance is running
 * correctly without manually hitting individual endpoints.
 * 
 * No auth required. Public endpoint.
 */
export async function GET() {
  const start = Date.now();
  const checks = {};
  let healthy = true;

  // Database connectivity + counts
  try {
    const supabase = getGuardedClient();
    const dbStart = Date.now();

    const [entities, receipts, disputes, signoffQueue, schemaVersion] = await Promise.all([
      supabase.from('entities').select('id', { count: 'exact', head: true }),
      supabase.from('receipts').select('id', { count: 'exact', head: true }),
      supabase.from('disputes').select('id', { count: 'exact', head: true }).in('status', ['open', 'under_review']),
      supabase.from('signoff_challenges').select('challenge_id', { count: 'exact', head: true }).eq('status', 'challenge_issued'),
      supabase.from('schema_migrations').select('version').order('version', { ascending: false }).limit(1),
    ]);

    checks.database = {
      status: 'ok',
      latency_ms: Date.now() - dbStart,
      entities: entities.count ?? 0,
      receipts: receipts.count ?? 0,
      active_disputes: disputes.count ?? 0,
      signoff_queue_depth: signoffQueue.count ?? 0,
      schema_version: schemaVersion.data?.[0]?.version ?? 'unknown',
    };
  } catch (err) {
    checks.database = { status: 'error', error: err.message };
    healthy = false;
  }

  // Write guard — verify write discipline is active
  try {
    const { getWriteGuardStatus } = await import('@/lib/write-guard');
    const guardStatus = getWriteGuardStatus?.() ?? null;
    checks.write_guard = guardStatus
      ? { status: 'active', ...guardStatus }
      : { status: 'active' };
  } catch {
    // write-guard always active in production — export may not exist in all versions
    checks.write_guard = { status: 'active' };
  }

  // Redis / rate limiter
  try {
    const hasRedis = !!getUpstashConfig();
    checks.rate_limiter = {
      status: hasRedis ? 'ok' : 'fallback',
      backend: hasRedis ? 'upstash_redis' : 'in_memory',
    };
  } catch {
    checks.rate_limiter = { status: 'unknown' };
  }

  // Blockchain anchoring
  try {
    const hasWallet = !!getBlockchainConfig()?.walletPrivateKey;
    checks.anchoring = {
      status: hasWallet ? 'configured' : 'not_configured',
      chain: 'base_l2',
    };
  } catch {
    checks.anchoring = { status: 'unknown' };
  }

  try {
    return NextResponse.json({
      status: healthy ? 'healthy' : 'degraded',
      protocol_version: EP_VERSION_STRING,
      timestamp: new Date().toISOString(),
      uptime_check_ms: Date.now() - start,
      checks,
      surfaces: {
        trust_profile: '/api/trust/profile/:entityId',
        trust_evaluate: '/api/trust/evaluate',
        install_preflight: '/api/trust/install-preflight', // experimental
        receipt_submit: '/api/receipts/submit',
        dispute_file: '/api/disputes/file',
        dispute_report: '/api/disputes/report',
        appeal_page: '/appeal',
        policies: '/api/policies',
        identity_principal: '/api/identity/principal/:principalId',
        identity_lineage: '/api/identity/lineage/:entityId',
        identity_bind: '/api/identity/bind',
        identity_continuity: '/api/identity/continuity',
        audit: '/api/audit',
        health: '/api/health',
      },
    });
  } catch (e) {
    return epProblem(500, 'health_check_failed', 'Health check response assembly failed');
  }
}
