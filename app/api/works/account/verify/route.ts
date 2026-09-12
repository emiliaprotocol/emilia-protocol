// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { readEpJson } from '@/lib/http/route-body';
import { verifyWorksAccountChallenge } from '@/lib/works/account-service';
import { createSupabaseWorksAccountStore } from '@/lib/works/account-store';
import { serializeWorksSessionCookie } from '@/lib/works/session';
import {
  ACCOUNT_BODY_BYTES,
  accountEnabled,
  accountFailure,
  accountJson,
  accountInvalidBody,
  accountMutationAllowed,
  accountNotFound,
  accountObject,
  accountPrivate,
  accountSecret,
  publicAccount,
} from '../_shared';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: NextRequest) {
  if (!accountEnabled()) return accountNotFound();
  const refused = accountMutationAllowed(request);
  if (refused) return refused;
  try {
    const parsed = await readEpJson(request, ACCOUNT_BODY_BYTES);
    if (!parsed.ok) return accountPrivate(parsed.response);
    const body = accountObject(parsed.value);
    if (!body) return accountInvalidBody();
    const result = await verifyWorksAccountChallenge({
      input: { email: body.email, challengeId: body.challengeId, code: body.code },
      secret: accountSecret(),
      store: createSupabaseWorksAccountStore(),
    });
    const response = accountJson({ authenticated: true, account: publicAccount(result.actor) });
    response.headers.set('set-cookie', serializeWorksSessionCookie(result.sessionToken, result.sessionExpiresAt));
    return response;
  } catch (error) {
    return accountFailure(error);
  }
}
