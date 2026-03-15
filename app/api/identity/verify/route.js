import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { verifyBinding } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.binding_id) return EP_ERRORS.BAD_REQUEST('binding_id is required');

    const result = await verifyBinding(body.binding_id, auth.entity?.entity_id || 'operator');
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result);
  } catch (err) {
    console.error('Identity verify error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
