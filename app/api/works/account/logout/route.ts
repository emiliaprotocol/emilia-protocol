// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';

import { clearWorksSessionCookieHeader, revokeWorksSession } from '@/lib/works/session';
import {
  ACCOUNT_HEADERS,
  accountEnabled,
  accountFailure,
  accountMutationAllowed,
  accountNotFound,
} from '../_shared';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  if (!accountEnabled()) return accountNotFound();
  const refused = accountMutationAllowed(request);
  if (refused) return refused;
  try {
    await revokeWorksSession(request);
    const response = new NextResponse(null, { status: 204, headers: ACCOUNT_HEADERS });
    response.headers.set('set-cookie', clearWorksSessionCookieHeader());
    return response;
  } catch (error) {
    return accountFailure(error);
  }
}
