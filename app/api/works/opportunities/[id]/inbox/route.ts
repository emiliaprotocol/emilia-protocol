// SPDX-License-Identifier: Apache-2.0
import { NextResponse, type NextRequest } from 'next/server';
import { epProblem } from '@/lib/errors';
import { worksDisabledProblem, worksEnabled, worksProblem } from '@/lib/works/api';
import { listOpportunityInbox } from '@/lib/works/store';
import { authenticateWorksRead } from '../../../_write-auth';

export const dynamic = 'force-dynamic';

function privateResponse(response: NextResponse) {
  response.headers.set('cache-control', 'private, no-store');
  response.headers.set('vary', 'Authorization');
  response.headers.set('x-robots-tag', 'noindex, nofollow');
  return response;
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    if (!worksEnabled()) return privateResponse(worksDisabledProblem());
    if (!request.headers.get('authorization')) return privateResponse(epProblem(401, 'owner_required', 'Use the API key that posted this opportunity.'));
    const auth = await authenticateWorksRead(request);
    if (!auth.ok) return privateResponse(auth.response);
    const { id } = await params;
    const query = new URL(request.url).searchParams;
    const rawOffset = query.get('offset') ?? '0';
    if (query.getAll('offset').length > 1 || !/^(0|[1-9][0-9]{0,5})$/.test(rawOffset)) {
      return privateResponse(epProblem(400, 'invalid_offset', 'Choose a valid inbox page.'));
    }
    const result = await listOpportunityInbox(id, { ...auth.access, offset: Number(rawOffset) });
    if (!result.ok) return privateResponse(worksProblem(result));
    return privateResponse(NextResponse.json({ collection: 'submissions', opportunity_id: result.opportunity_id,
      access: result.access, records: result.records, offset: result.offset, limit: result.limit, has_more: result.has_more,
    }));
  } catch {
    return privateResponse(epProblem(503, 'inbox_unavailable', 'The private inbox could not be loaded.'));
  }
}
