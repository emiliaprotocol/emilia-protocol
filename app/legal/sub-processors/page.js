'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { ENTITY, SUB_PROCESSORS } from '@/lib/site-config';

const EFFECTIVE = '2026-05-05';

export default function SubProcessorsPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Sub-processors</div>
        <h1 style={styles.h1}>Sub-processors</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE} · Updated whenever a data flow changes
        </div>
        <p style={styles.body}>
          The vendors below process customer data on behalf of {ENTITY.legalName} for the purposes described. Each vendor is contractually bound to data-protection terms equivalent to those we provide our customers. Customers can subscribe to change notifications by emailing <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>; we provide at least 30 days' advance notice of new sub-processors that handle customer data.
        </p>
      </section>

      <section style={{ ...styles.sectionWide, paddingTop: 0, paddingBottom: 72 }}>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead}>Sub-processor</th>
                <th style={styles.tableHead}>Purpose</th>
                <th style={styles.tableHead}>Region</th>
                <th style={styles.tableHead}>Data category</th>
              </tr>
            </thead>
            <tbody>
              {SUB_PROCESSORS.map((s, i) => (
                <tr key={i}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600, whiteSpace: 'nowrap' }}>{s.name}</td>
                  <td style={styles.tableCell}>{s.purpose}</td>
                  <td style={styles.tableCell}>{s.region}</td>
                  <td style={styles.tableCell}>{s.data}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>How we choose sub-processors</h2>
        <p style={styles.body}>
          Each sub-processor passes a vendor-due-diligence review covering data security, business continuity, sub-processor practices of their own, and contractual data-protection commitments equivalent to GDPR Article 28 standards. Vendors handling customer personal data are required to maintain SOC 2 Type II or ISO/IEC 27001 certification.
        </p>

        <h2 style={styles.h2}>What is not on this list</h2>
        <p style={styles.body}>
          We deliberately keep the data-flow surface small. The hosted service does not use third-party advertising, behavioral analytics, marketing automation, or session-replay tools. We do not share customer data with third parties for their marketing or AI-training purposes. If we ever add a vendor in those categories we will list it here and notify customers in advance per the change-notification process above.
        </p>

        <h2 style={styles.h2}>International transfers</h2>
        <p style={styles.body}>
          Where a sub-processor processes personal data outside the customer's region (typically EU/EEA/UK/Swiss data transferred to the United States), we rely on EU Standard Contractual Clauses and the UK addendum where applicable. Customers on EP Cloud Enterprise tiers may pin processing to specific regions — contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a> for the data-residency configuration.
        </p>

        <h2 style={styles.h2}>Contact</h2>
        <p style={styles.body}>
          Questions about a specific sub-processor or to subscribe to change notifications: <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>.
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
