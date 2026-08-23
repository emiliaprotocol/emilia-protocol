// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';

export const alt = 'Portfolio Authority Control for agentic AI at a customer-owned finance boundary';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function OpenGraphImage(): ImageResponse {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          background: '#f3eee5',
          color: '#171412',
          fontFamily: 'Arial, sans-serif',
          padding: '58px 64px',
        }}
      >
        <div
          style={{
            width: '64%',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            paddingRight: 58,
          }}
        >
          <div style={{ display: 'flex', color: '#71521d', fontSize: 19, letterSpacing: 2.4 }}>
            EMILIA GATE / PRIVATE EQUITY
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', fontSize: 70, fontWeight: 700, lineHeight: .98, letterSpacing: -3.5 }}>
              Portfolio Authority Control for agentic AI.
            </div>
            <div style={{ display: 'flex', marginTop: 28, color: '#625d56', fontSize: 25, lineHeight: 1.4 }}>
              Sponsor-scale control. Company-owned authority.
            </div>
          </div>
          <div style={{ display: 'flex', color: '#625d56', fontSize: 17 }}>
            One finance workflow / 90 days / $25K / observe first
          </div>
        </div>

        <div
          style={{
            width: '36%',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            padding: 30,
            border: '1px solid #bda871',
            background: '#fffaf0',
          }}
        >
          <div style={{ display: 'flex', color: '#71521d', fontSize: 16, letterSpacing: 2 }}>COVERED ACTION</div>
          <div style={{ display: 'flex', marginTop: 15, fontSize: 29, fontWeight: 700 }}>payment.release</div>
          <div style={{ display: 'flex', height: 62, justifyContent: 'center', alignItems: 'center', color: '#926f2d', fontSize: 30 }}>↓</div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '22px 20px',
              border: '2px solid #926f2d',
              background: '#f8e8be',
            }}
          >
            <div style={{ display: 'flex', fontSize: 28, fontWeight: 800 }}>GATE</div>
            <div style={{ display: 'flex', color: '#71521d', fontSize: 17, fontWeight: 700 }}>HOLD</div>
          </div>
          <div style={{ display: 'flex', height: 62, justifyContent: 'center', alignItems: 'center', color: '#926f2d', fontSize: 30 }}>↓</div>
          <div style={{ display: 'flex', color: '#625d56', fontSize: 16, lineHeight: 1.4 }}>
            Provider entry only after accepted exact-action authority and required evidence.
          </div>
        </div>
      </div>
    ),
    size,
  );
}
