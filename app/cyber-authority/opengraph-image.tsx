// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';

export const alt = 'Let AI defend the system. Keep the authority to change it.';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function CyberAuthorityOpenGraphImage(): ImageResponse {
  return new ImageResponse(
    <div style={{
      width: '100%',
      height: '100%',
      display: 'flex',
      background: '#f5f5f4',
      color: '#0c0a09',
      fontFamily: 'Arial, sans-serif',
      padding: 58,
    }}>
      <div style={{ width: '59%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 18, letterSpacing: 3, color: '#765a13' }}>
          <div style={{ width: 20, height: 20, borderRadius: 3, background: '#b08d35' }} />
          EMILIA / AUTHORITY FOR AI DEFENDERS
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: 66, lineHeight: 0.98, letterSpacing: -3.2, fontWeight: 700, maxWidth: 660 }}>
            Let AI defend the system.
          </div>
          <div style={{ marginTop: 14, fontSize: 66, lineHeight: 0.98, letterSpacing: -3.2, fontWeight: 700, color: '#876a24', maxWidth: 660 }}>
            Keep the authority to change it.
          </div>
        </div>
        <div style={{ fontSize: 18, color: '#57534e' }}>
          Exact-action control for automated security remediation.
        </div>
      </div>

      <div style={{ width: '41%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ width: 390, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', padding: '18px 20px', border: '2px solid #d6d3d1', borderRadius: 8, background: '#fff' }}>
            <div style={{ fontSize: 13, letterSpacing: 2, color: '#876a24' }}>AI DEFENDER</div>
            <div style={{ marginTop: 8, fontSize: 22, fontWeight: 700 }}>Disable svc-billing-prod</div>
          </div>
          <div style={{ fontSize: 26, color: '#a8a29e' }}>↓</div>
          <div style={{ width: '100%', display: 'flex', flexDirection: 'column', padding: 22, border: '2px solid #b08d35', borderRadius: 8, background: '#1c1917', color: '#fafaf9' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#d6b75d', fontSize: 13, letterSpacing: 2 }}>
              <span>EMILIA GATE</span><span>EXACT ACTION</span>
            </div>
            <div style={{ marginTop: 20, fontSize: 25, fontWeight: 700 }}>ADMIT · REFUSE</div>
            <div style={{ marginTop: 6, fontSize: 18, color: '#d6d3d1' }}>or hold uncertainty</div>
          </div>
          <div style={{ fontSize: 26, color: '#a8a29e' }}>↓</div>
          <div style={{ width: '100%', padding: '18px 20px', border: '2px solid #d6d3d1', borderRadius: 8, background: '#fff', fontSize: 19, fontWeight: 700 }}>
            Credential-owning provider
          </div>
        </div>
      </div>
    </div>,
    size,
  );
}
