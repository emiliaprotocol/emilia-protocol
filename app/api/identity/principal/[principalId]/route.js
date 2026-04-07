import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getPrincipal } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { principalId } = await params;

    // Restrict to the authenticated principal or operators only
    if (auth.entity.entity_id !== principalId && !auth.entity.is_operator) {
      return EP_ERRORS.FORBIDDEN('You may only view your own principal record');
    }

    const result = await getPrincipal(principalId);
    if (result.error) return EP_ERRORS.NOT_FOUND('Principal');

    return NextResponse.json(result);
  } catch (err) {
    logger.error('Principal lookup error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
