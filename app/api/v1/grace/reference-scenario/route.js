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
    // The reference scenario's "positive" run is the built-in happy-path fixture
    // (matching approvals against the matching policy): executeGraceCurtailment
    // always reaches its `ok: true` branch here, which is the only branch that
    // populates `authorization.quorum` and `settlement`. TS infers a union across
    // all of that function's return branches, so it can't see that; these casts
    // just state the shape this call site already guarantees.
    const authorization = /** @type {{ valid: boolean, checks: object, quorum: { members: * } }} */ (proof.authorization);
    const settlement = /** @type {{ settled: boolean, key: *, result: * }} */ (proof.settlement);
    return Response.json({
      ok: true,
      reference_only: scenario.reference_only,
      physical_claim: scenario.physical_claim,
      description: scenario.description,
      action: proof.bundle.action,
      action_hash: proof.action_hash,
      authorization: {
        valid: authorization.valid,
        checks: authorization.checks,
        members: authorization.quorum.members,
      },
      acknowledgment: proof.acknowledgment,
      meter_statement: proof.meter_statement,
      compliance: proof.compliance,
      action_state: proof.action_state,
      settlement: {
        settled: settlement.settled,
        key: settlement.key,
        result: settlement.result,
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
