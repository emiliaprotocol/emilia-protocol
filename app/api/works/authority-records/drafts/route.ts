// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { authEntityDbId } from '@/lib/auth-projections';
import { epProblem } from '@/lib/errors';
import { authenticateRequest } from '@/lib/supabase';
import { createAuthorityRecordDraft } from '@/lib/works/authority-record-service';
import {
  authorityRecordBody,
  authorityRecordFailure,
  authorityRecordNotFound,
  authorityRecordStore,
  authorityRecordsEnabled,
  json,
} from '../_shared';

const ENTITY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function POST(request: NextRequest) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(auth.status === 503 ? 503 : 401, auth.code || 'unauthorized',
        auth.status === 503 ? 'Authentication service unavailable' : 'Administrator authentication required');
    }
    const entityId = authEntityDbId(auth);
    const isAdmin = Array.isArray(auth.permissions) && auth.permissions.includes('admin');
    if (!ENTITY_ID.test(entityId) || !isAdmin) {
      return epProblem(403, 'authority_record_admin_required', 'Administrator authority is required.');
    }
    const parsed = await authorityRecordBody(request);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as Record<string, unknown>;
    const result = await createAuthorityRecordDraft({
      actor: { entityId, isAdmin },
      input: { projection: body.projection, contact_route: body.contact_route },
      store: authorityRecordStore(),
      siteOrigin: process.env.NEXT_PUBLIC_APP_URL
        || process.env.NEXT_PUBLIC_SITE_URL
        || 'https://www.emiliaprotocol.ai',
    });
    return json(result, 201);
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
