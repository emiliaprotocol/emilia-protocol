// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from 'next/server';

import { createSupabaseAuthorityRecordStore } from '@/lib/works/authority-record-store';
import { getPublicAuthorityRecord } from '@/lib/works/authority-record-service';
import { isWorksV0Enabled } from '@/lib/works/env';

type Context = { params: Promise<{ recordId: string }> };

function escapeXml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
  })[char] || char);
}

export async function GET(_request: Request, { params }: Context) {
  if (!isWorksV0Enabled()) return new NextResponse('Not found', { status: 404 });
  const { recordId } = await params;
  const record = await getPublicAuthorityRecord({
    recordId, store: createSupabaseAuthorityRecordStore(),
  });
  if (!record) return new NextResponse('Not found', { status: 404 });
  const date = record.projection.provenance.observed_at.slice(0, 10);
  const revision = record.projection.provenance.resolved_revision.slice(0, 12);
  const label = `Mapped by EMILIA · ${date} against commit ${revision}`;
  const width = Math.min(620, Math.max(320, label.length * 7 + 32));
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="34" role="img" aria-label="${escapeXml(label)}"><rect width="100%" height="100%" rx="7" fill="#111827"/><text x="16" y="22" fill="#f9fafb" font-family="ui-monospace,monospace" font-size="12">${escapeXml(label)}</text></svg>`;
  return new NextResponse(svg, {
    status: 200,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=300, stale-while-revalidate=3600',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; style-src 'none'; sandbox",
    },
  });
}
