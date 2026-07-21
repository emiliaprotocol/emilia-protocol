// SPDX-License-Identifier: Apache-2.0
import { runGateControlPlaneReference } from '@/lib/gate/control-plane-reference.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

export const dynamic = 'force-dynamic';

export async function GET(request: Request): Promise<Response> {
  const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'protocol_read');
  if (!limited.allowed) {
    return Response.json({ ok: false, error: 'rate_limited' }, {
      status: 429,
      headers: { 'cache-control': 'no-store', 'retry-after': String(Math.max(1, Number(limited.reset) || 60)) },
    });
  }
  const mode = new URL(request.url).searchParams.get('mode') || 'complete';
  if (!['complete', 'witness_only'].includes(mode)) {
    return Response.json({ ok: false, error: 'unknown_control_plane_mode' }, {
      status: 400,
      headers: { 'cache-control': 'no-store' },
    });
  }
  try {
    return Response.json(await runGateControlPlaneReference({ mode }), {
      status: 200,
      headers: {
        'cache-control': 'no-store',
        pragma: 'no-cache',
        'x-content-type-options': 'nosniff',
      },
    });
  } catch {
    return Response.json({ ok: false, error: 'control_plane_reference_failed' }, {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    });
  }
}
