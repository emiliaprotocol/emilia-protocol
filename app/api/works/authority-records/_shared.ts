// SPDX-License-Identifier: Apache-2.0

import { NextResponse, type NextRequest } from 'next/server';

import { epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { AuthorityRecordServiceError } from '@/lib/works/authority-record-service';
import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { isWorksV0Enabled } from '@/lib/works/env';

export const AUTHORITY_RECORD_BODY_BYTES = 160 * 1024;
export const AUTHORITY_RECORD_HEADERS = Object.freeze({
  'cache-control': 'no-store, max-age=0',
  'x-content-type-options': 'nosniff',
});

export function authorityRecordStore() {
  return createSupabaseAuthorityRecordStore();
}

export function authorityRecordsEnabled(): boolean {
  return isWorksV0Enabled();
}

export function authorityRecordNotFound(): NextResponse {
  return epProblem(404, 'not_found', 'Not found');
}

export async function authorityRecordBody(request: NextRequest) {
  return readEpJson(request, AUTHORITY_RECORD_BODY_BYTES);
}

export function ownerBearer(request: NextRequest): string | null {
  const value = request.headers.get('authorization') || '';
  const match = /^Bearer (aro1_[0-9a-f]{64})$/.exec(value);
  return match?.[1] ?? null;
}

export function authorityRecordFailure(error: unknown): NextResponse {
  if (error instanceof AuthorityRecordServiceError) {
    return epProblem(error.status, error.code, error.message);
  }
  return epProblem(500, 'authority_record_internal_error', 'Authority Record request failed.');
}

export function json(value: unknown, status = 200): NextResponse {
  return NextResponse.json(value, { status, headers: AUTHORITY_RECORD_HEADERS });
}
