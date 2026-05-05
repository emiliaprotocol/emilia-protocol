'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

const POSTS = [
  {
    title: 'AI voice cloning fraud — defense by action binding',
    desc: 'Voice authentication broke. The fix isn\'t a better voice model — it\'s moving the trust check off the voice channel entirely. Field guide for treasury, wire desks, and fraud ops.',
    href: '/blog/ai-voice-cloning-fraud-defense',
    date: '2026-04',
    tag: 'Financial',
    accent: color.red,
  },
  {
    title: 'How formal verification works for protocols',
    desc: 'TLA+ proves temporal properties across runs. Alloy bounds-checks structural invariants. A primer with worked examples from the EP spec.',
    href: '/blog/how-formal-verification-works-for-protocols',
    date: '2026-04',
    tag: 'Formal Methods',
    accent: color.gold,
  },
  {
    title: 'MCP authorization best practices in 2026',
    desc: 'Scope-level OAuth gets you to the door. For tools that move money, change infrastructure, or trigger irreversible state, you need the next layer.',
    href: '/blog/mcp-authorization-best-practices',
    date: '2026-04',
    tag: 'MCP',
    accent: color.gold,
  },
  {
    title: 'What is pre-action authorization?',
    desc: 'Sessions and scopes authorize the actor. Pre-action authorization authorizes the action — the destination, the amount, the exact parameters, before execution.',
    href: '/blog/what-is-pre-action-authorization',
    date: '2026-04',
    tag: 'Concepts',
    accent: color.blue,
  },
];

export default function BlogIndexPage() {
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
        <div className="ep-tag ep-hero-badge">Blog</div>
        <h1 className="ep-hero-text" style={styles.h1}>Field notes</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620, marginBottom: 48 }}>
          Working notes on AI agent authorization, MCP, formal verification, and fraud defense by action binding.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 12 }}>
          {POSTS.map((p, i) => (
            <a key={p.href} href={p.href}
              className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
              style={{
                border: `1px solid ${color.border}`,
                borderTop: `2px solid ${p.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                background: '#FAFAF9',
                textDecoration: 'none',
                color: color.t1,
                display: 'block',
              }}
            >
              <div style={{ fontFamily: font.mono, fontSize: 10, color: p.accent, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>{p.tag} · {p.date}</div>
              <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, marginBottom: 10, color: color.t1 }}>{p.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>{p.desc}</div>
              <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: p.accent }}>Read post →</span>
            </a>
          ))}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
