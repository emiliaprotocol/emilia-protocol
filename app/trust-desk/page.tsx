import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius, styles } from '@/lib/tokens';

export default function TrustDeskArchivePage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, maxWidth: 820, paddingTop: 112, paddingBottom: 56 }}>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 600, letterSpacing: 2.2, textTransform: 'uppercase', color: color.blue, marginBottom: 22 }}>
            Historical evaluation surface · archived
          </div>
          <h1 style={styles.h1}>AI Trust Desk is archived as a product evaluation.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            This route preserves the shape of an evaluated questionnaire-drafting and trust-page
            concept. AI Trust Desk is not a current commercial service or a second EMILIA offer.
            We are not accepting Trust Desk orders, uploads, payments, delivery commitments, or
            service-level commitments.
          </p>

          <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.cardHover, padding: 24, marginTop: 28 }}>
            <h2 style={{ fontFamily: font.sans, fontSize: 20, fontWeight: 700, color: color.t1, margin: '0 0 10px' }}>
              Current commercial boundary
            </h2>
            <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.65, margin: 0 }}>
              EMILIA&rsquo;s current commercial entry point is the nonproduction Protected-workflow
              pilot described on Pricing. Any production deployment is a separate, buyer-approved
              Gate Implementation with its own scope and operating boundary.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 20 }}>
              <Link href="/pricing" className="ep-cta" style={cta.primary}>See the current offer</Link>
              <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Review assurance scope</Link>
            </div>
          </div>
        </section>

        <section style={{ borderTop: `1px solid ${color.border}`, background: color.cardHover }}>
          <div style={{ ...styles.section, maxWidth: 820, paddingTop: 56, paddingBottom: 72 }}>
            <h2 style={styles.h2}>What remains inspectable</h2>
            <p style={styles.body}>
              Historical code and fixtures may remain available so reviewers can inspect the
              evaluation&rsquo;s proposed workflow: draft questionnaire answers, require review where
              configured, publish a record, and bind stored claim text to a digest. Their presence
              does not establish a customer deployment, current reviewer coverage, an operating
              verification service, revenue, adoption, or a promise to deliver the evaluated product.
            </p>
            <p style={{ ...styles.body, marginBottom: 0 }}>
              A content hash can show whether stored text changed. By itself, it does not prove the
              underlying statement true, constitute an audit, or show that a buyer accepted it.
            </p>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
