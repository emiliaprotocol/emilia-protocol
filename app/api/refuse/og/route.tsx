// SPDX-License-Identifier: Apache-2.0
//
// GET /api/refuse/og — Watch It Refuse share card (Open Graph image).
//
// Renders the verdict card for link unfurls and downloads: the action in the
// user's words, the decision, and the plain-English reason. Pure rendering of
// query-string inputs (capped and sanitized); no evaluation happens here and
// no state is read. 404 unless WATCH_IT_REFUSE=1.

import { ImageResponse } from 'next/og';
import type { NextRequest } from 'next/server';

import { isWatchItRefuseEnabled } from '@/lib/env';

export const dynamic = 'force-dynamic';

const INK = '#0C0A09';
const PAPER = '#FAFAF9';
const MUTED = '#A8A29E';
const GOLD = '#B08D35';
const RED = '#DC2626';
const GREEN = '#16A34A';

function cap(value: string | null, max: number, fallback: string): string {
  const clean = (value || '').replace(/\s+/g, ' ').trim().slice(0, max);
  return clean || fallback;
}

export async function GET(request: NextRequest): Promise<Response> {
  if (!isWatchItRefuseEnabled()) {
    return new Response('Not found', { status: 404 });
  }
  const params = request.nextUrl.searchParams;
  const text = cap(params.get('t'), 140, 'Wire $40,000 to this account');
  const verdictParam = params.get('v') === 'authorized' ? 'authorized' : 'refused';
  const refused = verdictParam === 'refused';
  const verdict = refused ? 'REFUSED' : 'AUTHORIZED, ONCE';
  const reason = cap(
    params.get('r'),
    120,
    refused
      ? 'No human authorization evidence was presented for this exact action.'
      : 'A verified receipt authorized exactly one execution. A replay was refused.',
  );

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          background: INK,
          color: PAPER,
          padding: '64px 72px',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 16,
              color: MUTED,
              fontSize: 22,
              letterSpacing: 6,
            }}
          >
            <div style={{ width: 34, height: 4, background: GOLD, display: 'flex' }} />
            AN AGENT WAS TOLD TO
          </div>
          <div
            style={{
              marginTop: 28,
              fontSize: 54,
              lineHeight: 1.15,
              fontWeight: 700,
              maxWidth: 1000,
              display: 'flex',
            }}
          >
            {`“${text}”`}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div
            style={{
              fontSize: 96,
              fontWeight: 800,
              letterSpacing: 4,
              color: refused ? RED : GREEN,
              display: 'flex',
            }}
          >
            {verdict}
          </div>
          <div
            style={{
              marginTop: 18,
              fontSize: 28,
              lineHeight: 1.4,
              color: PAPER,
              maxWidth: 1000,
              display: 'flex',
            }}
          >
            {reason}
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderTop: `2px solid #292524`,
            paddingTop: 28,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 14 }}>
            <div style={{ fontSize: 30, fontWeight: 800, letterSpacing: 8, color: PAPER, display: 'flex' }}>
              EMILIA
            </div>
            <div style={{ fontSize: 22, color: GOLD, letterSpacing: 3, display: 'flex' }}>
              WATCH IT REFUSE
            </div>
          </div>
          <div style={{ fontSize: 20, color: MUTED, display: 'flex' }}>
            No action performed. Authorization decision layer demo
          </div>
        </div>
      </div>
    ),
    { width: 1200, height: 630 },
  );
}
