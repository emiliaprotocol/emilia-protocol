import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { createBinding } from '@/lib/ep-ix';
import { EP_ERRORS, epProblem, epDbError } from '@/lib/errors';
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
    if (body.principal_id !== authEntityId(auth)) {
      return epProblem(403, 'not_authorized', 'principal_id must match authenticated entity');
    }

    const result = await createBinding(body);
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_bind_failed', result.error, 'identity/bind');
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Identity bind error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
