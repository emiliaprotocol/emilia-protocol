// SPDX-License-Identifier: Apache-2.0
//
// /api/works/[collection] — list (GET, public while WORKS_V0=1) and create
// (POST, cloud API key required). Collections: builders, listings, cards,
// activity, opportunities, submissions. Everything 404s when the flag is off.

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
import { createWorksRecord, listWorksRecords } from '@/lib/works/store';

export const dynamic = 'force-dynamic';

const MAX_WORKS_BODY_BYTES = 256 * 1024;

type RouteContext = { params: Promise<{ collection: string }> };

export async function GET(_request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return worksDisabledProblem();
    const { collection } = await params;
    const result = await listWorksRecords(collection);
    if (!result.ok) return worksProblem(result);
    return NextResponse.json(
      { collection, records: result.records },
      { headers: WORKS_READ_HEADERS },
    );
  } catch (error) {
    logger.error('[works] list failed:', error);
    return epProblem(500, 'internal_error', 'Works listing failed');
  }
}

export async function POST(request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return worksDisabledProblem();
    const auth = await authenticateCloudRequest(request);
    if (!auth) return worksUnauthorized();
    const { collection } = await params;
    const parsed = await readEpJson(request, MAX_WORKS_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const result = await createWorksRecord(collection, parsed.value, {
      ownerTenantId: auth.tenantId,
    });
    if (!result.ok) return worksProblem(result);
    return NextResponse.json({ collection, record: result.record }, { status: 201 });
  } catch (error) {
    logger.error('[works] create failed:', error);
    return epProblem(500, 'internal_error', 'Works create failed');
  }
}
