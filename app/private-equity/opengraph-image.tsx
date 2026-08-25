// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';

export const alt = 'An illustrative EMILIA Portfolio Authority Scan mapping consequential AI actions';
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
            PORTFOLIO AUTHORITY SCAN / PRIVATE EQUITY
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', fontSize: 64, fontWeight: 700, lineHeight: .98, letterSpacing: -3.2 }}>
              See what AI can change before it changes the company.
            </div>
            <div style={{ display: 'flex', marginTop: 28, color: '#625d56', fontSize: 25, lineHeight: 1.4 }}>
              One company. Seven consequence lanes. One first boundary.
            </div>
          </div>
          <div style={{ display: 'flex', color: '#625d56', fontSize: 17 }}>
            Source-linked map / owner review / blind spots visible
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
          <div style={{ display: 'flex', color: '#71521d', fontSize: 16, letterSpacing: 2 }}>COMPANY WORKSPACE</div>
          <div style={{ display: 'flex', marginTop: 15, fontSize: 29, fontWeight: 700 }}>Existing materials</div>
          <div style={{ display: 'flex', height: 48, justifyContent: 'center', alignItems: 'center', color: '#926f2d', fontSize: 26 }}>↓</div>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              padding: '18px 20px',
              border: '2px solid #926f2d',
              background: '#f8e8be',
            }}
          >
            <div style={{ display: 'flex', fontSize: 24, fontWeight: 800 }}>ACTION MAP</div>
            <div style={{ display: 'flex', marginTop: 8, color: '#71521d', fontSize: 15, fontWeight: 700 }}>
              Money · Access · Systems · Data
            </div>
          </div>
          <div style={{ display: 'flex', height: 48, justifyContent: 'center', alignItems: 'center', color: '#926f2d', fontSize: 26 }}>↓</div>
          <div style={{ display: 'flex', color: '#625d56', fontSize: 16, lineHeight: 1.4 }}>
            Source-linked candidates, explicit blind spots, and one recommended Gate boundary.
          </div>
        </div>
      </div>
    ),
    size,
  );
}
