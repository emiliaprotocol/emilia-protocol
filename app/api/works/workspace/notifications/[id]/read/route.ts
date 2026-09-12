// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { worksDisabledProblem, worksEnabled } from '@/lib/works/api';
import { validateNotificationRead } from '@/lib/works/workflow-model';
import { createSupabaseWorksWorkflowStore } from '@/lib/works/workflow-store';
import { privateWorksResponse, WORKS_PRIVATE_HEADERS, worksWorkflowProblem } from '@/lib/works/workflow-api';
import { authenticateWorksWrite } from '../../../../_write-auth';

export const dynamic = 'force-dynamic';
const MAX_BODY_BYTES = 8 * 1024;
type RouteContext = { params: Promise<{ id: string }> };

export async function POST(request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return privateWorksResponse(worksDisabledProblem());
    const auth = await authenticateWorksWrite(request);
    if (!auth.ok) return privateWorksResponse(auth.response);
    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return privateWorksResponse(parsed.response);
    const command = validateNotificationRead(parsed.value);
    if (!command.ok) return privateWorksResponse(epProblem(400, command.code, command.detail));
    const { id } = await params;
    const result = await createSupabaseWorksWorkflowStore()
      .markNotificationRead(auth.actor.ownerEntityId, id, command.value);
    if (!result.ok) return privateWorksResponse(worksWorkflowProblem(result));
    return NextResponse.json(result.result, { headers: WORKS_PRIVATE_HEADERS });
  } catch {
    return privateWorksResponse(epProblem(503, 'store_unavailable', 'Works workflow storage is unavailable.'));
  }
}
