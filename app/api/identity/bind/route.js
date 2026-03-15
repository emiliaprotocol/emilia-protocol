import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { createBinding } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.principal_id) return EP_ERRORS.BAD_REQUEST('principal_id is required');
    if (!body.binding_type) return EP_ERRORS.BAD_REQUEST('binding_type is required');
    if (!body.binding_target) return EP_ERRORS.BAD_REQUEST('binding_target is required');

    const result = await createBinding(body);
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    console.error('Identity bind error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
