// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';
import { authEntityObserveProfile } from '@/lib/auth-projections';
import { epProblem } from '@/lib/errors';
import { authenticateRequest, authEntityDbId } from '@/lib/supabase';
import type { StoreError } from '@/lib/works/store';
import { assertWorksSameOrigin, getWorksSessionActor } from '@/lib/works/session';

const ENTITY_DB_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type WorksWriteActor = {
  ownerEntityId: string;
  displayName: string | null;
};

export type WorksReadAccess = {
  viewerEntityId?: string;
  isAdmin?: boolean;
};

function authProblem(status: number | undefined, code: string | undefined): NextResponse {
  const unavailable = status === 503;
  return epProblem(
    unavailable ? 503 : 401,
    unavailable ? 'auth_service_unavailable' : (code || 'unauthorized'),
    unavailable
      ? 'Authentication service unavailable'
      : 'Sign in to EMILIA Works or use a valid entity API key',
  );
}

export async function authenticateWorksRead(
  request: NextRequest,
): Promise<{ ok: true; access: WorksReadAccess } | { ok: false; response: NextResponse }> {
  if (!request.headers.has('authorization')) {
    try {
      const actor = await getWorksSessionActor(request);
      if (!actor) return { ok: true, access: {} };
      if (!ENTITY_DB_ID.test(actor.ownerEntityId)) return { ok: false, response: authProblem(401, 'invalid_actor') };
      return { ok: true, access: { viewerEntityId: actor.ownerEntityId, isAdmin: false } };
    } catch { return { ok: false, response: authProblem(503, 'auth_service_unavailable') }; }
  }
  const auth = await authenticateRequest(request);
  if (auth.error) {
    return { ok: false, response: authProblem(auth.status, auth.code) };
  }
  const viewerEntityId = authEntityDbId(auth);
  if (!ENTITY_DB_ID.test(viewerEntityId)) {
    return {
      ok: false,
      response: epProblem(401, 'invalid_actor', 'The API key must resolve to a stable entity DB id'),
    };
  }
  const permissions = Array.isArray(auth.permissions) ? auth.permissions : [];
  return {
    ok: true,
    access: { viewerEntityId, isAdmin: permissions.includes('admin') },
  };
}

export async function authenticateWorksWrite(
  request: NextRequest,
): Promise<{ ok: true; actor: WorksWriteActor } | { ok: false; response: NextResponse }> {
  // An explicit bearer selects the legacy developer identity. Never silently
  // substitute a different ambient browser account when that bearer fails.
  if (!request.headers.has('authorization')) {
    try {
      const actor = await getWorksSessionActor(request);
      if (!actor || !ENTITY_DB_ID.test(actor.ownerEntityId)) return { ok: false, response: authProblem(401, 'unauthorized') };
      if (!['GET', 'HEAD'].includes(request.method) && !assertWorksSameOrigin(request)) {
        return { ok: false, response: epProblem(403, 'works_origin_refused', 'This account action must start on the EMILIA site.') };
      }
      return { ok: true, actor: { ownerEntityId: actor.ownerEntityId, displayName: actor.displayName } };
    } catch { return { ok: false, response: authProblem(503, 'auth_service_unavailable') }; }
  }
  const auth = await authenticateRequest(request);
  if (auth.error) {
    return { ok: false, response: authProblem(auth.status, auth.code) };
  }

  const ownerEntityId = authEntityDbId(auth);
  if (!ENTITY_DB_ID.test(ownerEntityId)) {
    return {
      ok: false,
      response: epProblem(401, 'invalid_actor', 'The API key must resolve to a stable entity DB id'),
    };
  }
  const rawDisplayName = authEntityObserveProfile(auth)?.display_name;
  const displayName = typeof rawDisplayName === 'string'
    && rawDisplayName.trim().length > 0
    && rawDisplayName.trim().length <= 200
    ? rawDisplayName.trim()
    : null;
  return { ok: true, actor: { ownerEntityId, displayName } };
}

export function bindAuthenticatedWriteFields(
  collection: string,
  value: unknown,
  actor: WorksWriteActor,
): { ok: true; value: unknown } | { ok: false; response: NextResponse } {
  if (collection !== 'opportunities') return { ok: true, value };
  if (!actor.displayName) {
    return {
      ok: false,
      response: epProblem(
        400,
        'entity_display_name_required',
        'The authenticated entity needs a display name to post an opportunity',
      ),
    };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { ok: true, value };
  }
  return {
    ok: true,
    value: { ...(value as Record<string, unknown>), posted_by: actor.displayName },
  };
}

export function worksWriteProblem(error: StoreError): NextResponse | null {
  if (error.code !== 'forbidden_reference_owner') return null;
  return epProblem(403, error.code, error.detail);
}
