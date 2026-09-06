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
        background: '#FAF8F2',
        color: '#202923',
        fontFamily: 'Arial, Helvetica, sans-serif',
        borderLeft: '12px solid #B48A31',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 26, fontWeight: 800, letterSpacing: 4 }}>EMILIA</div>
        <div style={{ fontSize: 20, color: '#586157' }}>Authorization infrastructure for agentic AI</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ fontSize: 78, lineHeight: 1.02, letterSpacing: -3, fontWeight: 800, maxWidth: 980 }}>
          Your AI workforce needs management.
        </div>
        <div style={{ fontSize: 32, lineHeight: 1.35, color: '#475348', marginTop: 28, maxWidth: 910 }}>
          Give every agent a job, set its authority, and know what happened.
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid #D7DACE', paddingTop: 22, fontSize: 21, color: '#586157' }}>
        <div>Workforce product: private local alpha</div>
        <div>Open protocol underneath</div>
      </div>
    </div>
  );
}
