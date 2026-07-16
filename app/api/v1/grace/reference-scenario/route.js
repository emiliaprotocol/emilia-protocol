// SPDX-License-Identifier: Apache-2.0
import { runGraceReferenceScenario } from '@/lib/grace/reference-scenario.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'protocol_read');
  if (!limited.allowed) {
    return Response.json({ ok: false, error: 'rate_limited' }, {
      status: 429,
      headers: { 'cache-control': 'no-store', 'retry-after': String(Math.max(1, Number(limited.reset) || 60)) },
    });
  }
  try {
    const scenario = await runGraceReferenceScenario();
    const proof = scenario.positive;
    return Response.json({
      ok: true,
      reference_only: scenario.reference_only,
      physical_claim: scenario.physical_claim,
      description: scenario.description,
      action: proof.bundle.action,
      action_hash: proof.action_hash,
      authorization: {
        valid: proof.authorization.valid,
        checks: proof.authorization.checks,
        members: proof.authorization.quorum.members,
      },
      acknowledgment: proof.acknowledgment,
      meter_statement: proof.meter_statement,
      compliance: proof.compliance,
      action_state: proof.action_state,
      settlement: {
        settled: proof.settlement.settled,
        key: proof.settlement.key,
        result: proof.settlement.result,
      },
      attacks: scenario.attacks,
      pins: scenario.pins,
    }, {
      status: 200,
      headers: {
        'cache-control': 'no-store',
        pragma: 'no-cache',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return Response.json({ ok: false, error: 'reference_scenario_failed' }, {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    });
  }
}
