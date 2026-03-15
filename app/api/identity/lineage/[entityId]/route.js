import { NextResponse } from 'next/server';
import { getLineage } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function GET(request, { params }) {
  try {
    const { entityId } = await params;
    const result = await getLineage(entityId);
    return NextResponse.json(result);
  } catch (err) {
    console.error('Lineage lookup error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
