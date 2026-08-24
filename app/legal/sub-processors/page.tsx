'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';
import { ENTITY, SUB_PROCESSORS } from '@/lib/site-config';

const EFFECTIVE = '2026-08-23';

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
        <p style={{ ...styles.body, marginBottom: 0, fontSize: 13, color: color.t3, fontStyle: 'italic' }}>
          No generally available hosted Gate or assurance service is operating today. This is a public vendor inventory, not a live customer DPA schedule.
        </p>
        <p style={styles.body}>
          The table records vendors referenced by the current website, public repository, or designed commercial components and the maximum data category associated with each stated role. An entry does not mean that vendor currently processes customer data or that the designed service is operating. Any future contracted service must include a verified sub-processor schedule and notice terms in its executed DPA.
        </p>
      </section>

      <section style={{ ...styles.sectionWide, paddingTop: 0, paddingBottom: 72 }}>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans }}>
            <thead>
              <tr>
                <th style={styles.tableHead as React.CSSProperties}>Vendor</th>
                <th style={styles.tableHead as React.CSSProperties}>Declared or designed purpose</th>
                <th style={styles.tableHead as React.CSSProperties}>Region</th>
                <th style={styles.tableHead as React.CSSProperties}>Data category</th>
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

        <h2 style={styles.h2}>Contract gate</h2>
        <p style={styles.body}>
          Before a vendor processes personal data for a contracted service, EMILIA must verify the actual data flow, security posture, retention, transfer mechanism, contractual terms, and customer notice obligations. This page does not claim that every listed vendor has completed that review or holds a named certification.
        </p>

        <h2 style={styles.h2}>What is not on this list</h2>
        <p style={styles.body}>
          The current website is designed without third-party advertising, behavioural analytics, marketing automation, or session-replay tools. We do not sell personal information. Data-use restrictions for any future contracted service must appear in its agreement and DPA.
        </p>

        <h2 style={styles.h2}>International transfers</h2>
        <p style={styles.body}>
          The actual processing region and transfer mechanism must be verified for each future contracted data flow. Where required, the applicable DPA must identify Standard Contractual Clauses, a UK addendum, or another lawful mechanism before processing begins. No generally available region-pinned hosted Gate service is offered today. Contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a> for diligence questions.
        </p>

        <h2 style={styles.h2}>Contact</h2>
        <p style={styles.body}>
          Questions about a vendor, current data flow, or future contract schedule: <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>.
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
