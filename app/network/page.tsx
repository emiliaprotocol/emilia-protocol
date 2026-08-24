import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius, styles } from '@/lib/tokens';

const SURFACE_NOTES = [
  {
    title: 'Reference registry records',
    body: 'Entries are experimental sandbox data. A registry record is not identity verification, endorsement, customer status, or proof that an entity is safe.',
  },
  {
    title: 'Supported receipt artifacts',
    body: 'The Explorer and verifier can inspect supported authorization-receipt fields and cryptographic evidence. They do not establish that the underlying business claim is true.',
  },
  {
    title: 'No network-effect claim',
    body: 'Counts or test activity on these surfaces are not evidence of adoption, counterparties, a founding cohort, or a global trust network.',
  },
];

export default function NetworkPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.sectionWide, paddingTop: 112, paddingBottom: 72 }}>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.goldDark, marginBottom: 24 }}>
            Experimental public registry concept
          </div>
          <h1 style={{ ...styles.h1, maxWidth: 820 }}>
            Inspect reference registry and receipt-verification paths.
          </h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            This nonproduction surface exists for protocol exploration. It is not a live trust
            network, verified-entity roster, production service, customer directory, adoption
            measure, or global authority registry.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
            <Link href="/explorer" className="ep-cta" style={cta.primary}>Inspect the experimental registry</Link>
            <Link href="/signup" className="ep-cta-secondary" style={cta.secondary}>Create a sandbox credential</Link>
          </div>
        </section>

        <section style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, background: color.cardHover }}>
          <div style={{ ...styles.sectionWide, paddingTop: 64, paddingBottom: 64 }}>
            <h2 style={styles.h2}>What this surface represents</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 260px), 1fr))', gap: 16, marginTop: 28 }}>
              {SURFACE_NOTES.map((item) => (
                <article key={item.title} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: 24 }}>
                  <h3 style={{ fontFamily: font.sans, fontSize: 17, fontWeight: 700, color: color.t1, margin: '0 0 10px' }}>{item.title}</h3>
                  <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 64, paddingBottom: 32 }}>
          <h2 style={styles.h2}>Offline verification has a precise boundary</h2>
          <p style={styles.body}>
            A supported, self-contained authorization receipt can be checked offline against the
            correct pinned key material for its signature, bound action fields, and included proof.
            That check establishes properties of the artifact. It does not verify the real-world
            identity of a registry subject, certify its controls, prove a claim true, or show that
            another organization has adopted EMILIA.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
            <Link href="/docs" className="ep-cta-secondary" style={cta.secondary}>Read the artifact documentation</Link>
            <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Review assurance scope</Link>
          </div>
        </section>

        <section style={{ ...styles.section, paddingTop: 32, paddingBottom: 96 }}>
          <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.card, padding: 28 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.goldDark, marginBottom: 12 }}>
              Commercial boundary
            </div>
            <h2 style={{ ...styles.h2, marginBottom: 12 }}>Sandbox exploration is not a production deployment.</h2>
            <p style={{ ...styles.body, margin: 0 }}>
              The current commercial entry point is the nonproduction Protected-workflow pilot
              described on Pricing. Any production deployment is a separate, buyer-approved Gate
              Implementation with its own scope and operating boundary.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 22 }}>
              <Link href="/pricing" className="ep-cta" style={cta.primary}>See the current offer</Link>
              <Link href="/pilot" className="ep-cta-secondary" style={cta.secondary}>Review pilot scope</Link>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
