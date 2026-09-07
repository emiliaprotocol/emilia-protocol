// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { getOwnedWorksRecord } from '@/lib/works/store';
import { worksDisabledProblem, worksEnabled, worksProblem } from '@/lib/works/api';
import { authenticateWorksWrite } from '../../../_write-auth';

export const dynamic = 'force-dynamic';
type RouteContext = { params: Promise<{ collection: string; id: string }> };
const HEADERS = { 'cache-control': 'private, no-store', vary: 'Authorization' };
function privateResponse(response: NextResponse): NextResponse {
  for (const [name, value] of Object.entries(HEADERS)) response.headers.set(name, value);
  return response;
}

/** This read proves only that the current API key owns the stored profile/listing. */
export async function GET(request: NextRequest, { params }: RouteContext) {
  try {
    if (!worksEnabled()) return privateResponse(worksDisabledProblem());
    const auth = await authenticateWorksWrite(request);
    if (!auth.ok) return privateResponse(auth.response);
    const { collection, id } = await params;
    const result = await getOwnedWorksRecord(collection, id, { ownerEntityId: auth.actor.ownerEntityId });
    if (!result.ok) return privateResponse(worksProblem(result));
    return NextResponse.json({ collection, owned: true, record: result.record }, { headers: HEADERS });
  } catch {
    // Never include a key, raw auth error, database record or owner identifier.
    return privateResponse(epProblem(503, 'store_unavailable', 'Owned record could not be read.'));
  }
}
