/**
 * /api/orcarouter/connect/start
 *
 * @license Apache-2.0
 *
 * Begins an OAuth 2.0 + PKCE authorization using the out-of-band (Flow B)
 * delivery. Returns the authorization URL and the attempt id. The verifier is
 * sealed server-side; it is never part of this response.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getOrcaRouterEnv } from '@/lib/env';
import { resolveOrcaRouterOrigins } from '@/lib/providers/orcarouter';
import { startOrcaRouterAuthorization } from '@/lib/providers/orcarouter-pkce';
import { NO_STORE, crossOriginRefused, requireOrcaRouterAdmin } from '../../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function POST(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  try {
    const origins = resolveOrcaRouterOrigins(getOrcaRouterEnv());
    const started = await startOrcaRouterAuthorization({
      origins,
      appName: 'EMILIA Protocol',
      principalId: guard.admin.reviewerId,
    });
    return NextResponse.json(started, { status: 201, headers: NO_STORE });
  } catch (error: any) {
    return epProblem(503, 'connect_start_failed',
      error?.code === 'insecure_origin' || error?.code === 'invalid_origin'
        ? 'OrcaRouter origins are misconfigured'
        : 'Could not start the OrcaRouter connection');
  }
}
