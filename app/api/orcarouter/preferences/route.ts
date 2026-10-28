/**
 * /api/orcarouter/preferences
 *
 * GET  ?capability=chat        the current selection for that capability
 * POST { capability, model }   only a model in that capability's live catalog
 *
 * @license Apache-2.0
 *
 * Selections are stored per capability, so a chat model can never become the
 * embedding model. Validation re-reads the catalog rather than trusting the
 * client, and refuses to persist a choice while the catalog is degraded: a
 * stale or invented model id must never be written. Requires an authenticated
 * internal administrator session.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { discoverOrcaRouterModels, type OrcaRoutCapability } from '@/lib/providers/orcarouter';
import {
  ORCAROUTER_CAPABILITIES,
  getOrcaRouterModelFor,
  resolveOrcaRouterCredential,
  setOrcaRouterModelFor,
} from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, crossOriginRefused, readJsonBody, requireOrcaRouterAdmin } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

function parseCapability(value: unknown): OrcaRoutCapability | null {
  if (value == null) return 'chat';
  return ORCAROUTER_CAPABILITIES.includes(value as OrcaRoutCapability)
    ? (value as OrcaRoutCapability)
    : null;
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const capability = parseCapability(request.nextUrl.searchParams.get('capability'));
  if (!capability) {
    return epProblem(400, 'invalid_capability', `capability must be one of: ${ORCAROUTER_CAPABILITIES.join(', ')}`);
  }
  return NextResponse.json({
    capability,
    model: await getOrcaRouterModelFor(capability),
  }, { headers: NO_STORE });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;
  const crossOrigin = crossOriginRefused(request);
  if (crossOrigin) return crossOrigin;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) return parsed.response;
  const capability = parseCapability(parsed.value?.capability);
  if (!capability) {
    return epProblem(400, 'invalid_capability', `capability must be one of: ${ORCAROUTER_CAPABILITIES.join(', ')}`);
  }
  const model = parsed.value?.model;
  if (typeof model !== 'string' || !model) {
    return epProblem(400, 'invalid_model', 'model is required');
  }

  const credential = await resolveOrcaRouterCredential();
  if (!credential.ok) {
    return epProblem(credential.reason === 'needs_reauth' ? 409 : 401, credential.reason,
      'Configure an OrcaRouter credential before choosing a model');
  }
  const catalog = await discoverOrcaRouterModels({ capability, credential });
  // A degraded catalog is a seed or last-known-good list. It may keep the
  // selector usable, but it must not become a persisted choice: only a model
  // verified against the live catalog may be stored.
  if (catalog.degraded) {
    return epProblem(503, 'catalog_unavailable', 'Cannot verify the model against the live catalog right now');
  }
  if (!catalog.models.some((entry) => entry.id === model)) {
    return epProblem(400, 'incompatible_model', `The selected model is not in the current ${capability} catalog`);
  }

  try {
    const settings = await setOrcaRouterModelFor(capability, model);
    return NextResponse.json(settings, { headers: NO_STORE });
  } catch {
    return epProblem(503, 'preferences_write_failed', 'Could not store the model selection');
  }
}
