import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { fileContinuityClaim } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.principal_id) return EP_ERRORS.BAD_REQUEST('principal_id is required');
    if (!body.old_entity_id) return EP_ERRORS.BAD_REQUEST('old_entity_id is required');
    if (!body.new_entity_id) return EP_ERRORS.BAD_REQUEST('new_entity_id is required');
    if (!body.reason) return EP_ERRORS.BAD_REQUEST('reason is required');

    const result = await fileContinuityClaim(body);
    if (result.error) {
      return NextResponse.json({ error: result.error, frozen: result.frozen, active_disputes: result.active_disputes }, { status: result.status || 500 });
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Continuity claim error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
