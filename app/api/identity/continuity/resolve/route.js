import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { resolveContinuity } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.continuity_id) return EP_ERRORS.BAD_REQUEST('continuity_id is required');
    if (!body.decision) return EP_ERRORS.BAD_REQUEST('decision is required (approved_full, approved_partial, rejected, rejected_laundering)');

    const result = await resolveContinuity(body.continuity_id, body.decision, body.reasoning, auth.entity?.entity_id || 'operator');
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result);
  } catch (err) {
    console.error('Continuity resolve error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
