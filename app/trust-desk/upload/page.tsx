import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius, styles } from '@/lib/tokens';

export default function TrustDeskUploadArchivePage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main style={{ ...styles.section, maxWidth: 720, paddingTop: 112, paddingBottom: 96 }}>
        <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 600, letterSpacing: 2.2, textTransform: 'uppercase', color: color.blue, marginBottom: 20 }}>
          Archived intake
        </div>
        <h1 style={styles.h1}>Trust Desk intake is closed.</h1>
        <p style={styles.body}>
          AI Trust Desk remains available only as a historical product evaluation. This page no
          longer accepts files, questionnaire submissions, orders, or payments, and it does not
          redirect to checkout. It is not a current commercial offer.
        </p>
        <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.cardHover, padding: 24, marginTop: 28 }}>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.65, margin: 0 }}>
            For EMILIA&rsquo;s current nonproduction Protected-workflow pilot and the separate
            buyer-approved production implementation boundary, use the current Pricing page.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
          <Link href="/trust-desk" className="ep-cta-secondary" style={cta.secondary}>Read the archive notice</Link>
          <Link href="/pricing" className="ep-cta" style={cta.primary}>See the current offer</Link>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}
