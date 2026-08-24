// SPDX-License-Identifier: Apache-2.0

export default function SocialCard(): React.ReactElement {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        position: 'relative',
        overflow: 'hidden',
        background: '#0b0d12',
        color: '#f7f4ed',
        fontFamily: 'Arial, Helvetica, sans-serif',
      }}
    >
      <div
        style={{
          position: 'absolute',
          width: 680,
          height: 680,
          right: -250,
          top: -260,
          borderRadius: 680,
          background: 'rgba(202, 155, 45, 0.18)',
        }}
      />
      <div
        style={{
          width: '62%',
          padding: '62px 0 54px 68px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 38,
              height: 38,
              border: '3px solid #d6a83f',
              borderRadius: 38,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 17,
              fontWeight: 800,
              color: '#d6a83f',
            }}
          >
            E
          </div>
          <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: 3 }}>EMILIA PROTOCOL</div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: 20, color: '#d6a83f', letterSpacing: 2.2, marginBottom: 18 }}>
            AUTHORITY FOR AUTONOMOUS WORK
          </div>
          <div style={{ fontSize: 59, lineHeight: 1.02, letterSpacing: -2.4, fontWeight: 800 }}>
            The authority tollgate for AI agents.
          </div>
          <div style={{ fontSize: 25, lineHeight: 1.35, color: '#b7bbc6', marginTop: 24 }}>
            Protocol proves. Gate prevents.
          </div>
        </div>

        <div style={{ display: 'flex', gap: 12, fontSize: 17, color: '#d9dbe2' }}>
          <div style={{ padding: '10px 15px', border: '1px solid #454956', borderRadius: 20 }}>Open protocol</div>
          <div style={{ padding: '10px 15px', border: '1px solid #454956', borderRadius: 20 }}>Rerunnable evidence</div>
        </div>
      </div>

      <div
        style={{
          width: '38%',
          padding: '75px 65px 70px 34px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {[
            ['01', 'Agent proposes', '#9297a5'],
            ['02', 'Authority checked', '#d6a83f'],
            ['03', 'Admit, refuse, or reconcile', '#f7f4ed'],
          ].map(([step, label, accent]) => (
            <div
              key={step}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 17,
                padding: '19px 20px',
                background: 'rgba(255,255,255,0.055)',
                border: `1px solid ${accent}55`,
                borderRadius: 16,
              }}
            >
              <div style={{ color: accent, fontSize: 16, fontWeight: 800 }}>{step}</div>
              <div style={{ fontSize: 20, lineHeight: 1.2, fontWeight: 700 }}>{label}</div>
            </div>
          ))}
        </div>
        <div style={{ height: 4, width: '100%', background: '#d6a83f', marginTop: 25, borderRadius: 4 }} />
      </div>
    </div>
  );
}
