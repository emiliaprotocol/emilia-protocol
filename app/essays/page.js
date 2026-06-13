// SPDX-License-Identifier: Apache-2.0
// EP Essays — index of long-form essays on agent accountability.
// @license Apache-2.0

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import EmailCapture from '@/components/EmailCapture';
import { styles, color, font, radius } from '@/lib/tokens';
import { ESSAYS } from '@/lib/essays';

export const metadata = {
  title: 'Essays — EMILIA Protocol',
  description:
    'Long-form essays on AI agent accountability: why the model becomes the ' +
    'crumple zone, and why authorization is not proof.',
  alternates: { canonical: '/essays' },
  openGraph: {
    title: 'Essays — EMILIA Protocol',
    description:
      'Long-form essays on AI agent accountability from the EMILIA Protocol.',
    url: 'https://www.emiliaprotocol.ai/essays',
    type: 'website',
  },
};

const ACCENTS = [color.gold, color.blue];

export default function EssaysIndexPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Essays" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 48 }}>
        <div style={styles.eyebrow}>Essays</div>
        <h1 style={styles.h1}>Essays</h1>
        <p style={{ ...styles.body, maxWidth: 620, marginBottom: 0 }}>
          Long-form arguments on agent accountability — who is provable when an
          agent acts, and why a named human&rsquo;s signature is a different kind
          of object than a log.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 12 }}>
          {ESSAYS.map((essay, i) => {
            const accent = ACCENTS[i % ACCENTS.length];
            return (
              <a
                key={essay.slug}
                href={`/essays/${essay.slug}`}
                className="ep-card-lift"
                style={{
                  border: `1px solid ${color.border}`,
                  borderTop: `2px solid ${accent}`,
                  borderRadius: radius.base,
                  padding: '24px',
                  background: color.card,
                  textDecoration: 'none',
                  color: color.t1,
                  display: 'block',
                }}
              >
                <div style={{ fontFamily: font.mono, fontSize: 10, color: accent, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>
                  Essay · {essay.date}
                </div>
                <div style={{ fontFamily: font.sans, fontSize: 20, fontWeight: 700, marginBottom: 10, color: color.t1, letterSpacing: -0.3 }}>
                  {essay.title}
                </div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 16 }}>
                  {essay.hook}
                </div>
                <span style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: accent }}>Read essay →</span>
              </a>
            );
          })}
        </div>
      </section>

      <EmailCapture
        eyebrow="Follow the build"
        heading="New essays, in your inbox."
        sub="Long-form arguments on agent accountability — sent when a new one ships, and nothing else."
      />

      <SiteFooter />
    </div>
  );
}
