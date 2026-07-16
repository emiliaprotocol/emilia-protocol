// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from 'next/server';

export function GET() {
  return NextResponse.json({
    applinks: {
      details: [{
        appIDs: ['5M2Z48UQQY.ai.emiliaprotocol.approver'],
        components: [{
          '/': '/mobile/pair',
          '?': { code: '?*' },
          comment: 'Open one-time EMILIA Approver pairing links',
        }],
      }],
    },
    webcredentials: {
      apps: ['5M2Z48UQQY.ai.emiliaprotocol.approver'],
    },
  }, {
    headers: { 'cache-control': 'public, max-age=300, s-maxage=300' },
  });
}
