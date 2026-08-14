// SPDX-License-Identifier: Apache-2.0

import type { NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import {
  getOwnerAuthorityRecord,
  getPublicAuthorityRecord,
  reviseAuthorityRecord,
} from '@/lib/works/authority-record-service';
import {
  authorityRecordBody,
  authorityRecordFailure,
  authorityRecordNotFound,
  authorityRecordStore,
  authorityRecordsEnabled,
  json,
  ownerBearer,
} from '../_shared';

type Context = { params: Promise<{ recordId: string }> };

export async function GET(_request: NextRequest, { params }: Context) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  try {
    const { recordId } = await params;
    const record = await getPublicAuthorityRecord({ recordId, store: authorityRecordStore() });
    return record ? json({ record }) : authorityRecordNotFound();
  } catch (error) {
    return authorityRecordFailure(error);
  }
}

/** Owner-only private read. POST avoids caching and keeps the credential in a header. */
export async function POST(request: NextRequest, { params }: Context) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  const token = ownerBearer(request);
  if (!token) return authorityRecordNotFound();
  try {
    const { recordId } = await params;
    return json({ record: await getOwnerAuthorityRecord({
      recordId, ownerToken: token, store: authorityRecordStore(),
    }) });
  } catch (error) {
    return authorityRecordFailure(error);
  }
}

export async function PATCH(request: NextRequest, { params }: Context) {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  const token = ownerBearer(request);
  if (!token) return authorityRecordNotFound();
  try {
    const parsed = await authorityRecordBody(request);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value as Record<string, unknown>;
    if (Object.hasOwn(body, 'owner_token')) {
      return epProblem(400, 'authority_record_owner_token_in_body', 'Owner credential belongs only in Authorization.');
    }
    const { recordId } = await params;
    return json({ record: await reviseAuthorityRecord({
      recordId, ownerToken: token, projection: body.projection, store: authorityRecordStore(),
    }) });
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
