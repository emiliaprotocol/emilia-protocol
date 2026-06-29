import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { scanCollusion } from '@/lib/collusion-monitor';
import { appendSecurityEvent, sha256hex } from '@/lib/security-events';
import { epProblem } from '@/lib/errors';
import { authenticateOperator } from '@/lib/operator-auth';
import { logger } from '@/lib/logger.js';

export const runtime = 'nodejs';

/**
 * GET|POST /api/cron/collusion-scan
 *
 * @internal
 * @access cron — requires CRON_SECRET / operator token. Not public.
 *
 * Periodic graph analysis over the receipt-submission network to surface farmed-
 * trust patterns the v2 scoring caps make expensive but not impossible: rings,
 * submitter concentration, timing bursts. High/medium findings are written to
 * the tamper-evident security_events ledger for operator review. DETECTION ONLY
 * — no entity is penalized and trust scoring is unchanged (the economics half of
 * collusion resistance is policy, not this job).
 *
 *   ?dry_run=1  — scan + return findings without writing ledger events.
 *
 * Call via Vercel Cron (vercel.json) or an external scheduler.
 */
async function run(request) {
  const auth = authenticateOperator(request);
  if (!auth.valid) return epProblem(401, 'unauthorized', auth.error || 'Unauthorized');

  const dryRun = new URL(request.url).searchParams.get('dry_run') === '1';
  const supabase = getGuardedClient();

  // Pull the minimal graph projection (submitter -> target + time).
  const receipts = [];
  const PAGE = 1000;
  for (let from = 0; ; from += PAGE) {
    const { data, error } = await supabase
      .from('receipts')
      .select('submitted_by, entity_id, created_at')
      .range(from, from + PAGE - 1);
    if (error) return epProblem(500, 'scan_failed', `receipt fetch failed: ${error.message}`);
    receipts.push(...(data || []));
    if (!data || data.length < PAGE) break;
  }

  const findings = scanCollusion(receipts);
  const bySeverity = findings.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {});

  let written = 0;
  if (!dryRun) {
    for (const f of findings) {
      if (f.severity !== 'high' && f.severity !== 'medium') continue;
      const clusterId = 'col_' + sha256hex(`${f.type}:${[...f.members].sort().join(',')}`).slice(0, 16);
      try {
        await appendSecurityEvent({
          eventType: 'collusion_suspected',
          severity: f.severity,
          actorId: auth.operator_id,
          targetType: 'entity_cluster',
          targetId: clusterId,
          correlationId: clusterId,
          payload: { pattern: f.type, members: f.members, detail: f.detail || null },
        });
        written += 1;
      } catch (e) {
        logger.warn('[collusion-scan] ledger write failed:', e?.message);
      }
    }
  }

  return NextResponse.json({
    ok: true,
    dry_run: dryRun,
    receipts_scanned: receipts.length,
    findings_total: findings.length,
    by_severity: bySeverity,
    events_written: written,
    // Operator review payload (capped); full detail lands in security_events.
    findings: findings.slice(0, 100),
    note: 'Detection only — no entity penalized; trust scoring unchanged.',
  });
}

export const GET = run;
export const POST = run;
