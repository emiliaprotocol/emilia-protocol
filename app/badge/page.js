'use client';

import Image from 'next/image';
import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const BADGE = 'https://www.emiliaprotocol.ai/badge/works-with-emilia.svg';
const LINK = 'https://www.emiliaprotocol.ai';

const SNIPPETS = [
  { k: 'Markdown', code: `[![Works with EMILIA](${BADGE})](${LINK})` },
  { k: 'HTML', code: `<a href="${LINK}"><img src="${BADGE}" alt="Works with EMILIA"></a>` },
  { k: 'reStructuredText', code: `.. image:: ${BADGE}\n   :target: ${LINK}\n   :alt: Works with EMILIA` },
];

export default function BadgePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  /** @type {React.CSSProperties} */
  const codeBox = {
    fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.7, color: '#D6D3D1',
    background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base,
    padding: '14px 16px', margin: '8px 0 0', overflowX: 'auto', whiteSpace: 'pre',
  };

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 40 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Badge</div>
        <h1 className="ep-hero-text" style={styles.h1}>Works with EMILIA</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Wired EMILIA into your agent, app, or platform? Add the badge so your users can see that irreversible actions require a named human&rsquo;s signoff — and that every approval mints a receipt they can verify offline.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <div className="ep-reveal" style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '32px', background: '#FAFAF9', display: 'flex', justifyContent: 'center' }}>
          <Image src="/badge/works-with-emilia.svg" alt="Works with EMILIA" width={300} height={40} unoptimized priority />
        </div>

        <div style={{ marginTop: 28, display: 'flex', flexDirection: 'column', gap: 18 }}>
          {SNIPPETS.map((s) => (
            <div key={s.k} className="ep-reveal">
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 14, color: color.t1 }}>{s.k}</div>
              <pre style={codeBox}>{s.code}</pre>
            </div>
          ))}
        </div>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>What the badge means — and what it doesn&rsquo;t</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li>It means your project integrates EMILIA to gate real, consequential actions behind a human signoff. Use it when that is actually true.</li>
          <li>It is <strong>not</strong> a certification, audit, or endorsement by us. It is a way for builders to signal they put a named human in the loop.</li>
          <li>Please link the badge to <code style={{ fontFamily: font.mono, fontSize: 13, color: color.blue }}>https://www.emiliaprotocol.ai</code>, and don&rsquo;t alter the mark&rsquo;s colors or wording.</li>
        </ul>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>Not integrated yet?</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Add it to your agent</a>
          <a href="/badge/works-with-emilia.svg" target="_blank" rel="noopener noreferrer" className="ep-cta-secondary" style={cta.secondary}>Get the SVG</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
