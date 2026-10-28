/**
 * /api/orcarouter/credential
 *
 * POST   { api_key }  save an existing sk-orca-… key (API-key adapter)
 * DELETE              remove the stored credential
 *
 * @license Apache-2.0
 *
 * The key is sealed at rest by the credential store and never echoed back.
 * The response is the same masked status the status endpoint returns.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import {
  clearOrcaRouterCredential,
  looksLikeOrcaRouterKey,
  orcaRouterCredentialStatus,
  saveOrcaRouterApiKey,
} from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, crossOriginRefused, readJsonBody, requireOrcaRouterAdmin } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function POST(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return parsed.response;
  if (!looksLikeOrcaRouterKey(parsed.value?.api_key)) {
    return epProblem(400, 'invalid_key_format', 'Expected an sk-orca-… API key');
  }

  try {
    const credential = await saveOrcaRouterApiKey(parsed.value.api_key);
    return NextResponse.json({ credential }, { status: 201, headers: NO_STORE });
  } catch (error) {
    if (error instanceof Error && error.message === 'credential_write_locked') {
      return epProblem(409, 'credential_busy', 'Another credential update is in progress');
    }
    return epProblem(503, 'credential_write_failed', 'Could not store the OrcaRouter credential');
  }
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  try {
    const credential = await clearOrcaRouterCredential();
    return NextResponse.json({ credential }, { headers: NO_STORE });
  } catch (error) {
    if (error instanceof Error && error.message === 'credential_write_locked') {
      return epProblem(409, 'credential_busy', 'Another credential update is in progress');
    }
    return epProblem(503, 'credential_write_failed', 'Could not clear the OrcaRouter credential');
  }
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  return NextResponse.json({ credential: await orcaRouterCredentialStatus() }, { headers: NO_STORE });
}
