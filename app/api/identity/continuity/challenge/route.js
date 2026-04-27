import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { challengeContinuity } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

// This route is auth-gated per middleware.js (useAuth: true,
// dispute_write category). The route was previously NOT calling
// authenticateRequest(), making it an auth-bypass — middleware does the
// rate-limiting + write-guard check but the actual handler accepted
// arbitrary challenger_id from the body. Sibling routes
// (/identity/continuity, .../resolve) authenticate; this one must too.
export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json();
    if (!body.continuity_id) return EP_ERRORS.BAD_REQUEST('continuity_id is required');
    if (!body.challenger_type) return EP_ERRORS.BAD_REQUEST('challenger_type is required');
    if (!body.reason) return EP_ERRORS.BAD_REQUEST('reason is required');

    // Force challenger_id to come from authenticated context — never the
    // request body. Without this, an authenticated entity could file a
    // challenge masquerading as a different challenger.
    const result = await challengeContinuity({
      ...body,
      challenger_id: auth.entity,
    });
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Continuity challenge error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
