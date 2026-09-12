// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { worksDisabledProblem, worksEnabled } from '@/lib/works/api';
import { createSupabaseWorksWorkflowStore } from '@/lib/works/workflow-store';
import { privateWorksResponse, WORKS_PRIVATE_HEADERS, worksWorkflowProblem } from '@/lib/works/workflow-api';
import { authenticateWorksWrite } from '../_write-auth';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  try {
    if (!worksEnabled()) return privateWorksResponse(worksDisabledProblem());
    const auth = await authenticateWorksWrite(request);
    if (!auth.ok) return privateWorksResponse(auth.response);
    const result = await createSupabaseWorksWorkflowStore().readWorkspace(auth.actor.ownerEntityId);
    if (!result.ok) return privateWorksResponse(worksWorkflowProblem(result));
    return NextResponse.json(result.workspace, { headers: WORKS_PRIVATE_HEADERS });
  } catch {
    return privateWorksResponse(epProblem(503, 'store_unavailable', 'Works workspace is unavailable.'));
  }
}
