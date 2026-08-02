// SPDX-License-Identifier: Apache-2.0
import { buildCoverageReferenceScenario } from '@/lib/coverage-reference-scenario.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

export const dynamic = 'force-dynamic';

export async function GET(request: Request): Promise<Response> {
  const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'protocol_read');
  if (!limited.allowed) {
    return Response.json({ ok: false, error: 'rate_limited' }, {
      status: 429,
      headers: {
        'cache-control': 'no-store',
        'retry-after': String(Math.max(1, Number(limited.reset) || 60)),
      },
    });
  }
  try {
    return Response.json(buildCoverageReferenceScenario(), {
      status: 200,
      headers: {
        'cache-control': 'no-store',
        pragma: 'no-cache',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return Response.json({ ok: false, error: 'coverage_reference_scenario_failed' }, {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    });
  }
}
