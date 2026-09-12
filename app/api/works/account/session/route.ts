// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { getWorksSessionActor } from '@/lib/works/session';
import {
  accountEnabled,
  accountFailure,
  accountJson,
  accountNotFound,
  publicAccount,
} from '../_shared';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  if (!accountEnabled()) return accountNotFound();
  try {
    const actor = await getWorksSessionActor(request);
    return actor
      ? accountJson({ authenticated: true, account: publicAccount(actor) })
      : accountJson({ authenticated: false });
  } catch (error) {
    return accountFailure(error);
  }
}
