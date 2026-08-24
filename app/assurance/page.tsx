import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Link from 'next/link';
import { ArrowRight, CheckCircle2, CircleDashed, FileCheck2 } from 'lucide-react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import {
  ASSURANCE_BOUNDARY_LINE,
  ASSURANCE_CATALOGUE,
  ASSURANCE_COMMERCIAL_ENTRY,
  type AssuranceCatalogueStatus,
} from '@/lib/assurance-catalog';
import { cta, color, font, radius, styles } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Claim-to-Consequence Assurance Catalogue | EMILIA Protocol',
  description:
    'See what EMILIA Claim-to-Consequence Assurance implements today, what is available only as a scoped engagement, and what is not operating.',
  alternates: { canonical: '/assurance' },
  openGraph: {
    title: 'EMILIA Claim-to-Consequence Assurance',
    description:
      'Package claims, re-perform evidence, carry a portable record, and keep authority separate at the Gate.',
    url: 'https://www.emiliaprotocol.ai/assurance',
    type: 'website',
  },
};

const LIFECYCLE = [
  {
    step: '01',
    name: 'Claim',
    body: 'Name the assertion, subject, scope, predicate, and policy version. A claim begins as an assertion, not a fact.',
  },
  {
    step: '02',
    name: 'Evidence',
    body: 'Pin the supplied sources, trust roots, profiles, clocks, and digests needed to test that assertion.',
  },
  {
    step: '03',
    name: 'Assurance record',
    body: 'Preserve the procedure, result, divergence, exclusions, and derivation so another party can inspect it offline.',
  },
  {
    step: '04',
    name: 'Gate',
    body: 'Evaluate the exact proposed action against separate customer acceptance rules and finite customer authority.',
  },
  {
    step: '05',
    name: 'Outcome',
    body: 'Keep provider admission, observed effect, uncertainty, and reconciliation distinct from the original claim.',
  },
] as const;

const STATUS_STYLE: Record<AssuranceCatalogueStatus, { color: string; border: string; background: string }> = {
  Implemented: { color: color.greenDark, border: color.greenDark, background: color.card },
  'Scoped engagement': { color: color.goldDark, border: color.goldDark, background: color.card },
  'Not operating': { color: color.t2, border: color.borderHover, background: color.cardHover },
};

const PAGE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'CollectionPage',
  '@id': 'https://www.emiliaprotocol.ai/assurance#catalogue',
  name: 'EMILIA Claim-to-Consequence Assurance Catalogue',
  url: 'https://www.emiliaprotocol.ai/assurance',
  description:
    'A status-labelled catalogue of implemented open verification artifacts, scoped assurance engagements, and assurance capabilities that are not operating.',
  mainEntity: {
    '@type': 'ItemList',
    itemListElement: ASSURANCE_CATALOGUE.map((item, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: item.name,
      description: `${item.status}: ${item.summary}`,
    })),
  },
};

const C = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 clamp(20px, 6vw, 32px)', ...style }}>{children}</div>
);

export default async function AssurancePage() {
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <div style={styles.page}>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(PAGE_JSONLD) }}
        nonce={nonce}
      />
      <SiteNav activePage="Assurance" />

      <main>
        <section style={{ padding: '112px 0 84px', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={styles.eyebrow}>EMILIA CLAIM-TO-CONSEQUENCE ASSURANCE</div>
            <h1 style={{ ...styles.h1Large, maxWidth: 980, marginTop: 18 }}>
              Package the claim. Verify the evidence. Control the consequence.
            </h1>
            <p style={{ ...styles.body, maxWidth: 790, marginTop: 24, fontSize: 18 }}>
              The catalogue spans the trust lifecycle between what an agent, model, vendor, or
              system says and what a protected executor may do. Each surface below says whether
              it is implemented, available only as a scoped engagement, or not operating. The
              record stays portable. The customer keeps the authority. Gate remains the
              consequence boundary.
            </p>
            <p style={{
              maxWidth: 820,
              margin: '28px 0 0',
              padding: '16px 18px',
              borderLeft: `3px solid ${color.gold}`,
              background: color.cardHover,
              color: color.t1,
              fontFamily: font.mono,
              fontSize: 14,
              fontWeight: 600,
              lineHeight: 1.65,
            }}>
              {ASSURANCE_BOUNDARY_LINE}
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 34 }}>
              <a href="#catalogue" className="ep-cta" style={cta.primary}>
                See the catalogue <ArrowRight size={15} aria-hidden="true" />
              </a>
              <Link href="/trust" className="ep-cta-secondary" style={cta.secondary}>
                Open Trust Center
              </Link>
            </div>
          </C>
        </section>

        <section style={{ padding: '78px 0', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ maxWidth: 720, marginBottom: 36 }}>
              <div style={styles.eyebrow}>ONE CONTINUOUS CONTROL SURFACE</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>From assertion to independently inspectable consequence.</h2>
            </div>
            <ol style={{
              listStyle: 'none',
              margin: 0,
              padding: 0,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 190px), 1fr))',
              gap: 12,
            }}>
              {LIFECYCLE.map((item) => (
                <li key={item.step} style={{
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: 22,
                  background: color.card,
                }}>
                  <div style={{ fontFamily: font.mono, color: color.goldDark, fontSize: 11, fontWeight: 600 }}>{item.step}</div>
                  <h3 style={{ ...styles.h3, marginTop: 16 }}>{item.name}</h3>
                  <p style={{ ...styles.cardBody, margin: 0 }}>{item.body}</p>
                </li>
              ))}
            </ol>
            <p style={{ ...styles.body, fontSize: 14, margin: '24px 0 0', maxWidth: 820 }}>
              Synthetic or read-only evaluation is not production deployment, independent certification, or permission to act.
            </p>
          </C>
        </section>

        <section id="catalogue" style={{ padding: '88px 0', background: color.cardHover, borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ maxWidth: 800, marginBottom: 42 }}>
              <div style={styles.eyebrow}>ASSURANCE CATALOGUE</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>A product surface with visible status.</h2>
              <p style={{ ...styles.body, marginTop: 16 }}>
                Implemented means the public artifact and procedure exist now. Scoped engagement
                means delivery depends on a buyer-approved boundary and contract. Not operating
                means EMILIA is defining the category surface without representing it as live.
              </p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 16 }}>
              {ASSURANCE_CATALOGUE.map((item) => {
                const status = STATUS_STYLE[item.status];
                const StatusIcon = item.status === 'Implemented'
                  ? CheckCircle2
                  : item.status === 'Scoped engagement'
                    ? FileCheck2
                    : CircleDashed;
                return (
                  <article key={item.id} style={{
                    display: 'flex',
                    flexDirection: 'column',
                    minHeight: 270,
                    padding: 26,
                    border: `1px solid ${color.border}`,
                    borderRadius: radius.base,
                    background: color.card,
                  }}>
                    <div style={{
                      alignSelf: 'flex-start',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 7,
                      padding: '6px 9px',
                      border: `1px solid ${status.border}`,
                      borderRadius: radius.sm,
                      background: status.background,
                      color: status.color,
                      fontFamily: font.mono,
                      fontSize: 10,
                      fontWeight: 600,
                      letterSpacing: 0.8,
                      textTransform: 'uppercase',
                    }}>
                      <StatusIcon size={13} aria-hidden="true" /> {item.status}
                    </div>
                    <h3 style={{ ...styles.h3, marginTop: 20 }}>{item.name}</h3>
                    <p style={{ ...styles.cardBody, margin: '0 0 22px' }}>{item.summary}</p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 'auto' }}>
                      {item.evidence.map((evidence) => (
                        <a
                          key={evidence.label}
                          href={evidence.href}
                          target={evidence.href.startsWith('http') ? '_blank' : undefined}
                          rel={evidence.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                          style={{ color: color.goldDark, fontFamily: font.mono, fontSize: 11 }}
                        >
                          {evidence.label} <span aria-hidden="true">↗</span>
                        </a>
                      ))}
                    </div>
                  </article>
                );
              })}
            </div>
          </C>
        </section>

        <section id="operating-model" style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
          <C>
            <div style={{ maxWidth: 800, marginBottom: 42 }}>
              <div style={styles.eyebrow}>OPERATING MODEL</div>
              <h2 style={{ ...styles.h2, marginTop: 14 }}>EMILIA owns the rails. Conclusions stay independent.</h2>
              <p style={{ ...styles.body, marginTop: 16 }}>
                EMILIA stewards the public criteria, record formats, registry and resolver
                contracts, status, supersession, and revocation workflow, plus any future mark
                policy. EMILIA also owns the hosted evidence-operations product surface when it is
                delivered under a scoped engagement. Independent assessors retain their own
                evaluation and certification conclusions.
              </p>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 250px), 1fr))', gap: 16 }}>
              {[
                {
                  title: 'EMILIA',
                  body: 'Builds and stewards the open criteria, record rails, lifecycle contracts, hosted product operations, and Gate integration.',
                },
                {
                  title: 'Customer',
                  body: 'Pins trust roots and acceptance policy, grants finite authority, appoints relying parties, and controls each protected path.',
                },
                {
                  title: 'Independent assessor',
                  body: 'Chooses its procedures within the scheme, examines the evidence, and owns the conclusion it is qualified to issue.',
                },
              ].map((owner) => (
                <article key={owner.title} style={{ ...styles.card, padding: 26 }}>
                  <h3 style={styles.h3}>{owner.title}</h3>
                  <p style={{ ...styles.cardBody, margin: 0 }}>{owner.body}</p>
                </article>
              ))}
            </div>
            <div style={{ marginTop: 34, padding: 24, border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.cardHover }}>
              <h3 style={{ ...styles.h3, marginBottom: 8 }}>Public certification nonclaim</h3>
              <p style={{ ...styles.cardBody, margin: 0 }}>
                No public certification program or mark is operating today. No general-availability hosted assurance service is represented as deployed.
              </p>
            </div>
          </C>
        </section>

        <section style={{ padding: '88px 0', background: color.t1, color: color.bg }}>
          <C>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 290px), 1fr))', gap: 56, alignItems: 'center' }}>
              <div>
                <div style={{ ...styles.eyebrow, color: color.gold }}>ONE COMMERCIAL ENTRY</div>
                <h2 style={{ ...styles.h2, color: color.bg, marginTop: 14 }}>
                  Start at one consequence boundary.
                </h2>
                <p style={{ color: color.borderHover, fontSize: 16, lineHeight: 1.72, margin: '18px 0 0' }}>
                  Assurance does not create a second public pilot or a second price sheet. The
                  canonical entry remains the protected-workflow pilot, limited to synthetic,
                  read-only, sandbox, or shadow validation. Any production activation requires
                  a separately scoped Gate Implementation after buyer acceptance.
                </p>
              </div>
              <div style={{ border: `1px solid ${color.t3}`, borderRadius: radius.base, padding: 28, background: color.t2 }}>
                <div style={{ color: color.gold, fontFamily: font.mono, fontSize: 11, letterSpacing: 1.2, textTransform: 'uppercase' }}>
                  {ASSURANCE_COMMERCIAL_ENTRY.name}
                </div>
                <div style={{ marginTop: 14, color: color.bg, fontFamily: font.sans, fontSize: 34, fontWeight: 700 }}>
                  {ASSURANCE_COMMERCIAL_ENTRY.price}
                </div>
                <p style={{ color: color.borderHover, fontSize: 14, lineHeight: 1.65, margin: '12px 0 22px' }}>
                  {ASSURANCE_COMMERCIAL_ENTRY.duration} · {ASSURANCE_COMMERCIAL_ENTRY.scope}
                </p>
                <Link href={ASSURANCE_COMMERCIAL_ENTRY.href} className="ep-cta" style={{ ...cta.primary, background: color.bg, color: color.t1 }}>
                  Review the canonical offer <ArrowRight size={15} aria-hidden="true" />
                </Link>
              </div>
            </div>
          </C>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
