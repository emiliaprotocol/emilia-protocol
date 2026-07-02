import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { verifyBinding } from '@/lib/ep-ix';
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
    if (!body.binding_id) return EP_ERRORS.BAD_REQUEST('binding_id is required');

    const result = await verifyBinding(body.binding_id, auth.entity?.entity_id || 'operator');
    if (result.error) {
      if ((result.status || 500) >= 500) return epDbError(result.status || 500, 'identity_verify_failed', result.error, 'identity/verify');
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Identity verify error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
