'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const COMPARISONS = [
  {
    title: 'EMILIA Protocol vs OAuth',
    desc: 'Why scoped tokens authorize the session but not the action — and what to layer on top for AI agents and high-value workflows.',
    href: '/compare/oauth',
    accent: color.blue,
    tag: 'OAuth',
  },
  {
    title: 'MCP authorization is necessary but not sufficient',
    desc: 'MCP authorization gates which tools an agent can call. EP gates whether the specific call about to execute was approved by a named human.',
    href: '/compare/mcp-auth-alone',
    accent: color.gold,
    tag: 'MCP Authorization',
  },
  {
    title: 'Trust receipts vs audit logs',
    desc: 'Audit logs detect after the breach. EP trust receipts prove authorization before the action executes — cryptographic, offline-verifiable.',
    href: '/compare/audit-logs',
    accent: color.green,
    tag: 'Audit Logs',
  },
  {
    title: 'Pre-action authorization vs post-action fraud detection',
    desc: 'Detection finds bad actions after they execute. Pre-action authorization stops them before. Why detection alone is the wrong primitive for irreversible actions.',
    href: '/compare/fraud-detection',
    accent: color.red,
    tag: 'Fraud Detection',
  },
];

export default function ComparePage() {
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
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 80 }}>
        <div className="ep-tag ep-hero-badge">Comparisons</div>
        <h1 className="ep-hero-text" style={styles.h1}>How EMILIA Protocol compares</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620, marginBottom: 48 }}>
          Procurement teams evaluating pre-action authorization controls ask the same handful of questions. Direct comparisons against the controls EP layers on top of, or replaces.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 12 }}>
          {COMPARISONS.map((c, i) => (
            <a key={c.href} href={c.href}
              className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
              style={{
                border: `1px solid ${color.border}`,
                borderTop: `2px solid ${c.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                background: '#FAFAF9',
                textDecoration: 'none',
                color: color.t1,
                display: 'block',
              }}
            >
              <div style={{ fontFamily: font.mono, fontSize: 10, color: c.accent, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>{c.tag}</div>
              <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, marginBottom: 10, color: color.t1 }}>{c.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>{c.desc}</div>
              <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: c.accent }}>Read comparison →</span>
            </a>
          ))}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
