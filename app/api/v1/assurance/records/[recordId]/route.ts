// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';

import { getClaimAssuranceReferenceRecord } from '@/lib/assurance-reference';

const RECORD_HEADERS = Object.freeze({
  'Cache-Control': 'public, max-age=31536000, immutable',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-EMILIA-Reference-Only': 'true',
});

const NOT_FOUND_HEADERS = Object.freeze({
  ...RECORD_HEADERS,
  'Cache-Control': 'no-store, max-age=0',
  'Content-Type': 'application/problem+json',
});

function notFound(): NextResponse {
  return NextResponse.json({
    type: 'about:blank',
    title: 'Assurance Record not found',
    status: 404,
  }, { status: 404, headers: NOT_FOUND_HEADERS });
}

export async function GET(
  request: Request,
  context: { params: Promise<{ recordId: string }> | { recordId: string } },
): Promise<NextResponse> {
  // Reject non-canonical double encoding at the HTTP boundary. Next decodes the
  // dynamic parameter once before handing it to us, so decoding the parameter
  // again without checking the raw URL would make `%253A` alias `%3A`.
  let rawRecordId = '';
  try {
    rawRecordId = new URL(request.url).pathname.split('/').at(-1) ?? '';
  } catch {
    return notFound();
  }
  if (/%25/i.test(rawRecordId)) return notFound();

  const { recordId } = await context.params;
  const record = getClaimAssuranceReferenceRecord(recordId);
  if (!record) return notFound();

  return NextResponse.json(record, {
    headers: {
      ...RECORD_HEADERS,
      ETag: `"${record.record_digest}"`,
    },
  });
}
