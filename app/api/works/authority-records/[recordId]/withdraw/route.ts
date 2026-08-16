// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { withdrawAuthorityRecord } from '@/lib/works/authority-record-service';
import {
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
    const { recordId } = await params;
    return json({ record: await withdrawAuthorityRecord({
      recordId, ownerToken: token, store: authorityRecordStore(),
    }) });
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
