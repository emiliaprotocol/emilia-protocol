import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { createBinding } from '@/lib/ep-ix';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readLimitedJson } from '@/lib/http/body-limit';
import { logger } from '../../../../lib/logger.js';

const MAX_BODY_BYTES = 10 * 1024;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readLimitedJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.principal_id) return EP_ERRORS.BAD_REQUEST('principal_id is required');
    if (!body.binding_type) return EP_ERRORS.BAD_REQUEST('binding_type is required');
    if (!body.binding_target) return EP_ERRORS.BAD_REQUEST('binding_target is required');

    const result = await createBinding(body);
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Identity bind error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
