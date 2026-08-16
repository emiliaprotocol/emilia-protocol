// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { approveAuthorityRecord } from '@/lib/works/authority-record-service';
import {
  authorityRecordBody,
  authorityRecordFailure,
  authorityRecordNotFound,
  authorityRecordStore,
  authorityRecordsEnabled,
  json,
  ownerBearer,
} from '../../_shared';

type Context = { params: Promise<{ recordId: string }> };

export async function POST(request: NextRequest, { params }: Context) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  const token = ownerBearer(request);
  if (!token) return authorityRecordNotFound();
  try {
    const parsed = await authorityRecordBody(request);
    if (!parsed.ok) return parsed.response;
    const { recordId } = await params;
    return json({ record: await approveAuthorityRecord({
      recordId,
      ownerToken: token,
      recordDigest: (parsed.value as Record<string, unknown>).record_digest as string,
      store: authorityRecordStore(),
    }) });
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
