// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — GET /api/delegations/[delegationId]/verify

import { NextResponse } from 'next/server';
import { verifyDelegation } from '@/lib/delegation';
import { EP_ERRORS } from '@/lib/errors';

export async function GET(request, { params }) {
  try {
    const { delegationId } = params;
    const url = new URL(request.url);
    const actionType = url.searchParams.get('action_type') || null;

    const result = await verifyDelegation(delegationId, actionType);
    return NextResponse.json(result);
  } catch (err) {
    console.error('[delegations/verify] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}
