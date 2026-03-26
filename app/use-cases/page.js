'use client';

import SiteNav from '@/components/SiteNav';

const USE_CASES = [
  {
    title: 'Government Fraud Prevention',
    desc: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.',
    href: '/use-cases/government',
  },
  {
    title: 'Financial Infrastructure Controls',
    desc: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.',
    href: '/use-cases/financial',
  },
  {
    title: 'Enterprise Privileged Actions',
    desc: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.',
    href: '/use-cases/enterprise',
  },
  {
    title: 'AI/Agent Execution Governance',
    desc: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.',
    href: '/use-cases/ai-agent',
  },
];

const s = {
  page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
  section: { maxWidth: 900, margin: '0 auto', padding: '100px 24px 80px' },
  eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#22C55E', marginBottom: 16 },
  h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
  body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 48, maxWidth: 620 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 20 },
  card: {
    background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10,
    padding: '32px 28px', textDecoration: 'none', color: '#F8FAFC',
    transition: 'all 0.25s', display: 'block', borderTop: '2px solid transparent',
  },
  cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 18, fontWeight: 700, marginBottom: 10 },
  cardDesc: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65, marginBottom: 16 },
  cardLink: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 13, fontWeight: 500, color: '#22C55E' },
};

export default function UseCasesPage() {
  return (
    <div style={s.page}>
      <SiteNav activePage="Use Cases" />
      <div style={s.section}>
        <div style={s.eyebrow}>Control Surfaces</div>
        <h1 style={s.h1}>Built for workflows where weak<br />authorization causes real damage</h1>
        <p style={s.body}>EP enforces trust at the action level -- not the session level. These are the domains where that distinction matters most.</p>
        <div style={s.grid}>
          {USE_CASES.map(uc => (
            <a key={uc.href} href={uc.href} style={s.card}
              onMouseEnter={e => { e.currentTarget.style.background = '#1a2238'; e.currentTarget.style.borderTopColor = '#22C55E'; e.currentTarget.style.transform = 'translateY(-2px)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = '#0F172A'; e.currentTarget.style.borderTopColor = 'transparent'; e.currentTarget.style.transform = 'translateY(0)'; }}
            >
              <div style={s.cardTitle}>{uc.title}</div>
              <div style={s.cardDesc}>{uc.desc}</div>
              <span style={s.cardLink}>See architecture &#8594;</span>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
