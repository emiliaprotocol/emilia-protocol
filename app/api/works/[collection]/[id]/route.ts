// SPDX-License-Identifier: Apache-2.0
//
// /api/works/[collection]/[id] — read one record (GET, public while
// WORKS_V0=1) and edit (PATCH, cloud API key + record ownership). Ownership
// is enforced inside updateWorksRecord: the record's owner_tenant_id must
// equal auth.tenantId, and read-only example seeds refuse edits entirely.

import { NextResponse, type NextRequest } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { readEpJson } from '@/lib/http/route-body';
import {
  WORKS_READ_HEADERS,
  worksDisabledProblem,
  worksEnabled,
  worksProblem,
  worksUnauthorized,
} from '@/lib/works/api';
import { getWorksRecord, updateWorksRecord } from '@/lib/works/store';

export const dynamic = 'force-dynamic';

const MAX_WORKS_BODY_BYTES = 256 * 1024;

type RouteContext = { params: Promise<{ collection: string; id: string }> };

export async function GET(_request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return worksDisabledProblem();
    const { collection, id } = await params;
    const result = await getWorksRecord(collection, id);
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
    const auth = await authenticateCloudRequest(request);
    if (!auth) return worksUnauthorized();
    const { collection, id } = await params;
    const parsed = await readEpJson(request, MAX_WORKS_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const result = await updateWorksRecord(collection, id, parsed.value, {
      ownerTenantId: auth.tenantId,
    });
    if (!result.ok) return worksProblem(result);
    return NextResponse.json({ collection, record: result.record });
  } catch (error) {
    logger.error('[works] edit failed:', error);
    return epProblem(500, 'internal_error', 'Works edit failed');
  }
}
