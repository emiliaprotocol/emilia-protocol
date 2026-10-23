/**
 * GET /api/orcarouter/models?capability=chat&modality=image&refresh=1
 *
 * @license Apache-2.0
 *
 * Server-side catalogue proxy. The credential stays on the server; the browser
 * receives only the minimal model metadata it needs to render a selector.
 * Live discovery is authoritative; an outage falls back to the verified seed
 * and reports `degraded: true` rather than silently inventing options.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import {
  ORCAROUTER_MAX_CATALOG_ITEMS,
  discoverOrcaRouterModels,
  resetOrcaRouterCatalogCache,
  type OrcaInputModality,
  type OrcaRoutCapability,
} from '@/lib/providers/orcarouter';
import { resolveOrcaRouterCredential } from '@/lib/providers/orcarouter-credentials';
import { NO_STORE, requireOrcaRouterAdmin } from '../_shared';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const CAPABILITIES: OrcaRoutCapability[] = ['chat', 'embedding', 'image', 'video', 'rerank'];
const MODALITIES: OrcaInputModality[] = ['text', 'image', 'audio', 'video', 'file'];

export async function GET(request: NextRequest): Promise<NextResponse> {
  const guard = requireOrcaRouterAdmin(request);
  if (!guard.ok) return guard.response;

  const params = request.nextUrl.searchParams;
  const capability = (params.get('capability') || 'chat') as OrcaRoutCapability;
  if (!CAPABILITIES.includes(capability)) {
    return epProblem(400, 'invalid_capability', `capability must be one of: ${CAPABILITIES.join(', ')}`);
  }
  const rawModality = params.get('modality');
  if (rawModality && !MODALITIES.includes(rawModality as OrcaInputModality)) {
    return epProblem(400, 'invalid_modality', `modality must be one of: ${MODALITIES.join(', ')}`);
  }
  if (rawModality && rawModality !== 'text' && capability !== 'chat') {
    return epProblem(400, 'invalid_modality', 'a non-text input modality only applies to chat models');
  }

  const credential = await resolveOrcaRouterCredential();
  if (!credential.ok) {
    const code = credential.reason === 'needs_reauth' ? 'needs_reauth' : credential.reason;
    return epProblem(credential.reason === 'needs_reauth' ? 409 : 401, code,
      credential.reason === 'needs_reauth'
        ? 'The stored OrcaRouter credential was revoked or rejected; reconnect to continue'
        : credential.reason === 'unreadable'
          ? 'The stored OrcaRouter credential could not be read; reconnect to continue'
          : 'No OrcaRouter credential is configured');
  }

  const refresh = params.get('refresh') === '1';
  if (refresh) resetOrcaRouterCatalogCache();

  let catalog;
  try {
    catalog = await discoverOrcaRouterModels({
      capability,
      modality: (rawModality as OrcaInputModality) || null,
      credential,
      useCache: !refresh,
    });
  } catch (error: any) {
    return epProblem(503, 'catalog_unavailable', String(error?.message || 'OrcaRouter catalog unavailable'));
  }

  return NextResponse.json({
    capability,
    modality: rawModality || 'text',
    source: catalog.source,
    degraded: catalog.degraded,
    error: catalog.error,
    catalog_source: catalog.catalog_source,
    count: catalog.models.length,
    models: catalog.models.slice(0, ORCAROUTER_MAX_CATALOG_ITEMS),
  }, { headers: NO_STORE });
}
