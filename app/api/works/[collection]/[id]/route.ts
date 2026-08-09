// SPDX-License-Identifier: Apache-2.0
//
// /api/works/[collection]/[id] — read one record (GET, public while
// WORKS_V0=1) and edit (PATCH, regular entity API key + record ownership).

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { readEpJson } from '@/lib/http/route-body';
import {
  WORKS_READ_HEADERS,
  worksDisabledProblem,
  worksEnabled,
  worksProblem,
} from '@/lib/works/api';
import { getWorksRecord, updateWorksRecord } from '@/lib/works/store';
import {
  authenticateWorksRead,
  authenticateWorksWrite,
  bindAuthenticatedWriteFields,
  worksWriteProblem,
} from '../../_write-auth';

export const dynamic = 'force-dynamic';

const MAX_WORKS_BODY_BYTES = 256 * 1024;

type RouteContext = { params: Promise<{ collection: string; id: string }> };

export async function GET(request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return worksDisabledProblem();
    const auth = await authenticateWorksRead(request);
    if (!auth.ok) return auth.response;
    const { collection, id } = await params;
    const result = await getWorksRecord(collection, id, auth.access);
    if (!result.ok) return worksProblem(result);
    return NextResponse.json(
      { collection, record: result.record },
      { headers: WORKS_READ_HEADERS },
    );
  } catch (error) {
    logger.error('[works] read failed:', error);
    return epProblem(500, 'internal_error', 'Works read failed');
  }
}

export async function PATCH(request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return worksDisabledProblem();
    const auth = await authenticateWorksWrite(request);
    if (!auth.ok) return auth.response;
    const { collection, id } = await params;
    const parsed = await readEpJson(request, MAX_WORKS_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const bound = bindAuthenticatedWriteFields(collection, parsed.value, auth.actor);
    if (!bound.ok) return bound.response;
    const result = await updateWorksRecord(collection, id, bound.value, {
      ownerEntityId: auth.actor.ownerEntityId,
    });
    if (!result.ok) return worksWriteProblem(result) || worksProblem(result);
    return NextResponse.json({ collection, record: result.record });
  } catch (error) {
    logger.error('[works] edit failed:', error);
    return epProblem(500, 'internal_error', 'Works edit failed');
  }
}
