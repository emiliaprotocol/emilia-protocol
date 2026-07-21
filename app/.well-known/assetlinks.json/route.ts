// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

const FINGERPRINT = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

export const dynamic = 'force-dynamic';

export function GET() {
  const fingerprints = (process.env.MOBILE_ANDROID_ASSETLINKS_CERT_SHA256 || '')
    .split(',')
    .map((value) => value.trim().toUpperCase())
    .filter((value) => FINGERPRINT.test(value));
  if (fingerprints.length === 0) {
    return NextResponse.json({ error: 'android_association_not_configured' }, {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    });
  }
  return NextResponse.json([{
    relation: [
      'delegate_permission/common.get_login_creds',
      'delegate_permission/common.handle_all_urls',
    ],
    target: {
      namespace: 'android_app',
      package_name: 'ai.emiliaprotocol.approver',
      sha256_cert_fingerprints: fingerprints,
    },
  }], {
    headers: { 'cache-control': 'public, max-age=300, s-maxage=300' },
  });
}
