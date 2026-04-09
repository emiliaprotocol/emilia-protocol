'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const USE_CASES = [
  {
    title: 'Government Fraud Prevention',
    desc: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.',
    href: '/use-cases/government',
    accent: color.green,
    tag: 'Government',
  },
  {
    title: 'Financial Infrastructure Controls',
    desc: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.',
    href: '/use-cases/financial',
    accent: color.blue,
    tag: 'Financial',
  },
  {
    title: 'Enterprise Privileged Actions',
    desc: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.',
    href: '/use-cases/enterprise',
    accent: color.gold,
    tag: 'Enterprise',
  },
  {
    title: 'AI and Agent Execution Governance',
    desc: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.',
    href: '/use-cases/ai-agent',
    accent: color.blue,
    tag: 'AI / Agent',
  },
];

export default function UseCasesPage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  return (
    <div style={styles.page}>
      <SiteNav activePage="Use Cases" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 80 }}>
        <div className="ep-tag ep-hero-badge">Control Surfaces</div>
        <h1 className="ep-hero-text" style={styles.h1}>Built for workflows where weak authorization causes real damage</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620, marginBottom: 48 }}>
          EP enforces trust at the action level — not the session level. These are the domains where that distinction matters most.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 12 }}>
          {USE_CASES.map((uc, i) => (
            <a key={uc.href} href={uc.href}
              className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
              style={{
                border: `1px solid ${color.border}`,
                borderTop: `2px solid ${uc.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                background: '#FAFAF9',
                textDecoration: 'none',
                color: color.t1,
                display: 'block',
              }}
            >
              <div style={{ fontFamily: font.mono, fontSize: 10, color: uc.accent, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>{uc.tag}</div>
              <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, marginBottom: 10, color: color.t1 }}>{uc.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>{uc.desc}</div>
              <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: uc.accent }}>See architecture →</span>
            </a>
          ))}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
