import { NextResponse } from 'next/server';
import { challengeContinuity } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

export async function POST(request) {
  try {
    const body = await request.json();
    if (!body.continuity_id) return EP_ERRORS.BAD_REQUEST('continuity_id is required');
    if (!body.challenger_type) return EP_ERRORS.BAD_REQUEST('challenger_type is required');
    if (!body.reason) return EP_ERRORS.BAD_REQUEST('reason is required');

    const result = await challengeContinuity(body);
    if (result.error) return NextResponse.json({ error: result.error }, { status: result.status || 500 });

    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    logger.error('Continuity challenge error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
