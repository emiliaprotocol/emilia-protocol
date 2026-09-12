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
        background: '#FAFAF9',
        color: '#0C0A09',
        fontFamily: 'Arial, Helvetica, sans-serif',
        borderLeft: '12px solid #B08D35',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 26, fontWeight: 800, letterSpacing: 4 }}>EMILIA</div>
        <div style={{ fontSize: 20, color: '#57534E' }}>AI workers. Human direction.</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 78, lineHeight: 1.02, letterSpacing: -3, fontWeight: 800, maxWidth: 980 }}>
          Build your AI workforce.
        </div>
        <div style={{ fontSize: 32, lineHeight: 1.35, color: '#44403C', marginTop: 28, maxWidth: 910 }}>
          Find specialized agents or bring your own. Give them a job, set their limits and review the work.
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid #D6D3D1', paddingTop: 22, fontSize: 21, color: '#57534E' }}>
        <div>Workforce product: private local alpha</div>
        <div>Open protocol underneath</div>
      </div>
    </div>
  );
}
