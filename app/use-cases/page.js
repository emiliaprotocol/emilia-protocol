'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const USE_CASES = [
  {
    title: 'MCP and agent tool calls',
    desc: 'Put Gate immediately before a configured consequential tool and require action-bound evidence before invocation.',
    href: '/mcp',
    accent: color.green,
    tag: 'Developer on-ramp',
  },
  {
    title: 'Government workflows',
    desc: 'Apply action and evidence profiles to configured disbursements, benefit routing, enrollment changes, and overrides.',
    href: '/govguard',
    accent: color.blue,
    tag: 'GovGuard profile',
  },
  {
    title: 'Financial operations',
    desc: 'Bind beneficiary changes, payment release, and treasury actions to explicit policy and relying-party trust inputs.',
    href: '/finguard',
    accent: color.gold,
    tag: 'FinGuard profile',
  },
  {
    title: 'Energy controls',
    desc: 'Compose authorization, execution, and measurement evidence at a configured demand-response or facility-control boundary.',
    href: '/grace',
    accent: color.blue,
    tag: 'GRACE profile',
  },
  {
    title: 'Enterprise privileged actions',
    desc: 'Require portable evidence for configured infrastructure changes, data exports, permission changes, and deployments.',
    href: '/use-cases/enterprise',
    accent: color.green,
    tag: 'Enterprise profile',
  },
  {
    title: 'Multi-party approval',
    desc: 'Require distinct-human, initiator-excluded approval evidence where a consequential action needs more than one person.',
    href: '/quorum',
    accent: color.gold,
    tag: 'Quorum profile',
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
      <SiteNav activePage="Solutions" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 80 }}>
        <div className="ep-tag ep-hero-badge">EMILIA Gate solution profiles</div>
        <h1 className="ep-hero-text" style={styles.h1}>One consequence firewall, adapted to the action boundary</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620, marginBottom: 48 }}>
          These profiles package action schemas, policy templates, and integration guidance around Gate. They are
          not separate products, and they protect only the paths integrated through the relevant executor.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
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
