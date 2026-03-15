import { NextResponse } from 'next/server';
import { getPrincipal } from '@/lib/ep-ix';
import { EP_ERRORS } from '@/lib/errors';

export async function GET(request, { params }) {
  try {
    const { principalId } = await params;
    const result = await getPrincipal(principalId);
    if (result.error) return EP_ERRORS.NOT_FOUND('Principal');

    return NextResponse.json(result);
  } catch (err) {
    console.error('Principal lookup error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
