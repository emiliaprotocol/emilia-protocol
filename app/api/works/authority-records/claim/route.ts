// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { claimAuthorityRecord } from '@/lib/works/authority-record-service';
import {
  authorityRecordBody,
  authorityRecordFailure,
  authorityRecordNotFound,
  authorityRecordStore,
  authorityRecordsEnabled,
  json,
} from '../_shared';

export async function POST(request: NextRequest) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  try {
    const parsed = await authorityRecordBody(request);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as Record<string, unknown>;
    const result = await claimAuthorityRecord({
      input: {
        invitation_token: body.invitation_token,
        proof_url: body.proof_url,
      },
      store: authorityRecordStore(),
    });
    return json(result);
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
