import { NextResponse, NextRequest } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId, authEntityIsOperator } from '@/lib/auth-projections.js';
import { getLineage } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ entityId: string }> }
): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { entityId } = await params;

    // Restrict to the authenticated entity or operators only
    if (authEntityId(auth) !== entityId && !authEntityIsOperator(auth)) {
      return EP_ERRORS.FORBIDDEN('You may only view your own entity lineage');
    }

    const result = await getLineage(entityId);
    return NextResponse.json(result);
  } catch (err) {
    logger.error('Lineage lookup error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
