'use client';

import SiteNav from '@/components/SiteNav';

export default function GovernancePage() {
  const s = {
    page: { minHeight: '100vh', background: '#05060a', color: '#e8eaf0', fontFamily: "'Space Grotesk', -apple-system, sans-serif" },
    section: { maxWidth: 680, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0a0c18', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    h1: { fontFamily: "'Outfit', sans-serif", fontSize: 'clamp(32px, 5vw, 44px)', fontWeight: 900, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'Outfit', sans-serif", fontSize: 24, fontWeight: 800, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#7a809a', lineHeight: 1.75, marginBottom: 24 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', background: '#00d4ff', color: '#05060a' },
  };

  const LANES = [
    'Technical review',
    'Pilot participation',
    'Policy feedback',
    'Conformance discussion',
    'Governance participation',
    'Ecosystem partnership',
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#00d4ff', marginBottom: 16 }}>Governance</div>
        <h1 style={s.h1}>Governance at EMILIA</h1>
        <p style={{ ...s.body, maxWidth: 560 }}>
          EMILIA is being developed as open trust infrastructure. The protocol layer should become stronger through inspectability, conformance, ecosystem participation, and broader governance over time.
        </p>
      </section>

      {/* Protocol and company */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Open protocol, clear execution</h2>
          <p style={s.body}>
            We believe the protocol layer and the commercial layer should be clearly legible. The protocol can remain open and portable while companies build products, services, and implementation support on top.
          </p>
        </div>
      </section>

      {/* Direction */}
      <section style={s.section}>
        <h2 style={s.h2}>Direction of travel</h2>
        <p style={s.body}>
          Our long-term direction is to support broader participation in governance, conformance expectations, and policy discussion as the ecosystem matures.
        </p>
      </section>

      {/* Participation lanes */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Ways to participate</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {LANES.map((lane, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <span style={{ color: '#00d4ff', fontSize: 14, flexShrink: 0 }}>+</span>
                <span style={{ fontSize: 15, color: '#7a809a' }}>{lane}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ ...s.section, textAlign: 'center', paddingBottom: 100 }}>
        <h2 style={{ ...s.h2, fontSize: 28 }}>Want to help shape the trust layer?</h2>
        <a href="mailto:team@emiliaprotocol.ai" style={s.cta}>Contact the Team</a>
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
