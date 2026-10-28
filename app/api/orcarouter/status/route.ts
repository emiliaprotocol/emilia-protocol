/**
 * GET /api/orcarouter/status
 *
 * @license Apache-2.0
 *
 * Credential and origin status for the OrcaRouter provider panel. Returns a
 * masked indicator only: the key never leaves the server. The caller must hold
 * an authenticated internal administrator session.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { getOrcaRouterEnv } from '@/lib/env';
import {
  ORCAROUTER_CYBER_MODELS,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_DISPLAY_NAME,
  ORCAROUTER_FALLBACK_MODEL,
  ORCAROUTER_PROVIDER_ID,
  resolveOrcaRouterOrigins,
} from '@/lib/providers/orcarouter';
import {
  ORCAROUTER_CAPABILITIES,
  getOrcaRouterModel,
  getOrcaRouterModelSelection,
  orcaRouterCredentialStatus,
} from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, requireOrcaRouterAdmin } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;

  let credential;
  let origins;
  try {
    credential = await orcaRouterCredentialStatus();
    origins = resolveOrcaRouterOrigins(getOrcaRouterEnv());
  } catch (error: any) {
    // Origin misconfiguration is an operator error, not a client error.
    return NextResponse.json(
      { error: 'provider_misconfigured', detail: String(error?.message || 'invalid OrcaRouter configuration') },
      { status: 503, headers: NO_STORE },
    );
  }

  // Selections are per capability, so switching the selector cannot show (or
  // save) another capability's model.
  const selections: Record<string, string | null> = {};
  for (const capability of ORCAROUTER_CAPABILITIES) {
    selections[capability] = await getOrcaRouterModelSelection(capability);
  }

  return NextResponse.json({
    provider: ORCAROUTER_PROVIDER_ID,
    display_name: ORCAROUTER_DISPLAY_NAME,
    credential,
    origins,
    models: {
      default: ORCAROUTER_DEFAULT_MODEL,
      cyber: [...ORCAROUTER_CYBER_MODELS],
      fallback: ORCAROUTER_FALLBACK_MODEL,
      selected: await getOrcaRouterModel(),
      selections,
    },
    catalog_source: `${origins.api}/models?capability=chat`,
    docs: {
      provider_page: 'https://www.orcarouter.ai/cyber',
      cyber_models: 'https://www.orcarouter.ai/models?tier=cyber',
    },
  }, { headers: NO_STORE });
}
