'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

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

export default function UseCasesPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Use Cases" />
      <div style={{ ...styles.section, maxWidth: 900, padding: '100px 24px 80px' }}>
        <div style={styles.eyebrow}>Control Surfaces</div>
        <h1 style={styles.h1}>Built for workflows where weak<br />authorization causes real damage</h1>
        <p style={{ ...styles.body, maxWidth: 620, marginBottom: 48 }}>EP enforces trust at the action level -- not the session level. These are the domains where that distinction matters most.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 20 }}>
          {USE_CASES.map(uc => (
            <a key={uc.href} href={uc.href}
              className="ep-card-accent"
              style={{ ...styles.card, textDecoration: 'none', color: color.t1, display: 'block', borderTop: '2px solid transparent' }}
            >
              <div style={{ fontFamily: font.sans, fontSize: 18, fontWeight: 700, marginBottom: 10 }}>{uc.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>{uc.desc}</div>
              <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: color.green }}>See architecture &#8594;</span>
            </a>
          ))}
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
