import { NextResponse } from 'next/server';
import { getLineage } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

export async function GET(request, { params }) {
  try {
    const { entityId } = await params;
    const result = await getLineage(entityId);
    return NextResponse.json(result);
  } catch (err) {
    logger.error('Lineage lookup error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
