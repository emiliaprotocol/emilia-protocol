// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { readEpJson } from '@/lib/http/route-body';
import { getClientIP } from '@/lib/rate-limit';
import { sendWorksAccountCodeEmail } from '@/lib/works/account-email';
import { startWorksAccountChallenge } from '@/lib/works/account-service';
import { createSupabaseWorksAccountStore } from '@/lib/works/account-store';
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
    const result = await startWorksAccountChallenge({
      input: {
        email: body.email,
        name: body.name,
        consent: body.consent,
        emailNotifications: body.emailNotifications,
      },
      clientAddress: getClientIP(request),
      secret: accountSecret(),
      store: createSupabaseWorksAccountStore(),
      sendEmail: sendWorksAccountCodeEmail,
    });
    return accountJson(result, 202);
  } catch (error) {
    return accountFailure(error);
  }
}
