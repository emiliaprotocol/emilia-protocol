// SPDX-License-Identifier: Apache-2.0

export default function SocialCard(): React.ReactElement {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '52px 68px',
        background: '#0E0F0C',
        color: '#F2EFE6',
        fontFamily: 'Arial, Helvetica, sans-serif',
        borderLeft: '14px solid #E8581C',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 26, fontWeight: 800, letterSpacing: 4 }}>EMILIA</div>
        <div style={{ fontSize: 20, color: '#8F8B80', letterSpacing: 2 }}>THE NEW HIRE IS AN AI</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 92, lineHeight: 0.98, letterSpacing: -1, fontWeight: 800, maxWidth: 1000, textTransform: 'uppercase' }}>
          Hire the AI. Keep your rules.
        </div>
        <div style={{ fontSize: 32, lineHeight: 1.35, color: '#D9D4C7', marginTop: 28, maxWidth: 960 }}>
          The rules every new hire gets, checked at a gate the AI can’t go around.
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '2px solid #E8581C', paddingTop: 22, fontSize: 21, color: '#8F8B80' }}>
        <div>Nobody grades their own homework</div>
        <div>Open protocol. Apache-2.0.</div>
      </div>
    </div>
  );
}
