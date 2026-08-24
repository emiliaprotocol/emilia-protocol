'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const DOCS = [
  {
    title: 'Privacy Policy',
    desc: 'What data we collect, how it is used, where it lives, and how to exercise data-subject rights under GDPR, CCPA, and equivalent regimes.',
    href: '/legal/privacy',
    accent: color.blue,
  },
  {
    title: 'Terms of Service',
    desc: 'Use of the website, public prototypes, documentation, and inquiry surfaces. Open-source artifacts remain governed by their own licences.',
    href: '/legal/terms',
    accent: color.gold,
  },
  {
    title: 'Acceptable Use',
    desc: 'What EMILIA Protocol services and SDKs may not be used for. Aligned with standard prohibited-use policies for security infrastructure.',
    href: '/legal/acceptable-use',
    accent: color.green,
  },
  {
    title: 'Sub-processors',
    desc: 'Third-party vendors used for the current website and inquiry flows, with the scope and status of each data flow stated explicitly.',
    href: '/legal/sub-processors',
    accent: color.t1,
  },
];

export default function LegalIndexPage() {
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

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge">Legal</div>
        <h1 className="ep-hero-text" style={styles.h1}>Legal documents</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          These documents describe the current website, public prototypes, and inquiry flows. EMILIA does not represent that a generally available hosted Gate or assurance service is operating today. Any future paid implementation or hosted service requires a separately signed agreement. For procurement or contract questions, contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a>.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 12 }}>
          {DOCS.map((d, i) => (
            <a key={d.href} href={d.href}
              className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
              style={{
                border: `1px solid ${color.border}`,
                borderTop: `2px solid ${d.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                background: '#FAFAF9',
                textDecoration: 'none',
                color: color.t1,
                display: 'block',
              }}
            >
              <div style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, marginBottom: 10, color: color.t1 }}>{d.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>{d.desc}</div>
              <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: d.accent }}>Read →</span>
            </a>
          ))}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
