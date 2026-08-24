import type { Metadata } from 'next';
import { ArrowRight, ExternalLink, FileCheck2 } from 'lucide-react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { TRUST_INDEX } from '@/lib/assurance-catalog';
import { color, font, radius, styles } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Trust Center | EMILIA Protocol',
  description:
    'A public source index for EMILIA security, legal, privacy, open-source, engineering evidence, and assurance materials.',
  alternates: { canonical: '/trust' },
  openGraph: {
    title: 'EMILIA Trust Center',
    description: 'Inspect the public materials behind EMILIA security, legal, engineering, and assurance claims.',
    url: 'https://www.emiliaprotocol.ai/trust',
    type: 'website',
  },
};

const C = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) => (
  <div style={{ maxWidth: 1040, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

export default function TrustPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Trust" />
      <main>
        <section style={{ padding: '112px 0 76px', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={styles.eyebrow}>PUBLIC TRUST SOURCE INDEX</div>
            <h1 style={{ ...styles.h1Large, maxWidth: 820, marginTop: 18 }}>
              Trust should be inspectable before the call.
            </h1>
            <p style={{ ...styles.body, maxWidth: 730, marginTop: 24, fontSize: 18 }}>
              This page collects EMILIA&rsquo;s published security, legal, engineering, and
              assurance materials in one place. It is a procurement starting point, not a
              completed diligence room. Each link goes to the underlying public source.
            </p>
            <div style={{
              maxWidth: 790,
              marginTop: 28,
              padding: 20,
              border: `1px solid ${color.border}`,
              borderRadius: radius.base,
              background: color.cardHover,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: color.t1, fontWeight: 700 }}>
                <FileCheck2 size={18} color={color.gold} aria-hidden="true" /> Published material, bounded claims
              </div>
              <p style={{ ...styles.cardBody, margin: '10px 0 0' }}>
                No public certification or audit, compliance status, customer reference,
                live availability page, business-continuity or termination-export package,
                standard DPA or SLA, or deployed hosted assurance service is represented as
                available here.
              </p>
            </div>
          </C>
        </section>

        <section style={{ padding: '80px 0 96px' }}>
          <C>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 56 }}>
              {TRUST_INDEX.map((group) => (
                <section key={group.title} aria-labelledby={`trust-${group.title.toLowerCase().replaceAll(' ', '-')}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 20, flexWrap: 'wrap', marginBottom: 20 }}>
                    <h2 id={`trust-${group.title.toLowerCase().replaceAll(' ', '-')}`} style={{ ...styles.h2, margin: 0 }}>
                      {group.title}
                    </h2>
                    <span style={{ color: color.t2, fontFamily: font.mono, fontSize: 10, textTransform: 'uppercase', letterSpacing: 1.1 }}>
                      {group.items.length} public {group.items.length === 1 ? 'source' : 'sources'}
                    </span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: 14 }}>
                    {group.items.map((item) => (
                      <a
                        key={item.href}
                        href={item.href}
                        target={item.external ? '_blank' : undefined}
                        rel={item.external ? 'noopener noreferrer' : undefined}
                        aria-label={`${item.name}: ${item.status}${item.external ? ' (opens in a new tab)' : ''}`}
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          minHeight: 190,
                          padding: 24,
                          color: color.t1,
                          textDecoration: 'none',
                          border: `1px solid ${color.border}`,
                          borderRadius: radius.base,
                          background: color.card,
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                          <span style={{
                            display: 'inline-block',
                            padding: '5px 8px',
                            borderRadius: radius.sm,
                            background: color.cardHover,
                            color: color.t2,
                            fontFamily: font.mono,
                            fontSize: 10,
                            fontWeight: 600,
                            letterSpacing: 0.8,
                            textTransform: 'uppercase',
                          }}>
                            {item.status}
                          </span>
                          {item.external
                            ? <ExternalLink size={15} color={color.gold} aria-hidden="true" />
                            : <ArrowRight size={15} color={color.gold} aria-hidden="true" />}
                        </div>
                        <h3 style={{ ...styles.h3, marginTop: 20 }}>{item.name}</h3>
                        <p style={{ ...styles.cardBody, margin: 0 }}>{item.description}</p>
                      </a>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </C>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
