'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const EFFECTIVE = '2026-08-23';

export default function PrivacyPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Privacy</div>
        <h1 style={styles.h1}>Privacy Policy</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE}
        </div>
        <p style={styles.body}>
          This policy describes how {ENTITY.legalName} ("EMILIA Protocol", "we", "us") collects, uses, and protects personal information when you use the websites at <code style={{ fontFamily: font.mono, fontSize: 13 }}>emiliaprotocol.ai</code>, public prototypes, documentation, inquiry forms, or any related interface we operate. EMILIA does not currently offer a generally available hosted Gate or assurance service.
        </p>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>1. Roles</h2>
        <p style={styles.body}>
          For current website, prototype, and inquiry use, we act as the <strong style={{ color: color.t1 }}>controller</strong> of personal data we collect about you. If a future separately contracted implementation requires us to process personal data on a customer's behalf, the parties must define their roles and execute any required DPA before that processing begins.
        </p>

        <h2 style={styles.h2}>2. What we collect</h2>
        <p style={styles.body}>For website visitors and prospects:</p>
        <ul style={styles.list}>
          <li>Standard request metadata (IP address, user agent, referrer, requested URL, timestamp) processed by our hosting provider under the active account configuration and provider terms. We do not represent that a separate EMILIA cold-log archive is operating.</li>
          <li>Information you submit voluntarily (contact form, partner inquiry, investor inquiry, pilot request) — name, organization, role, email, free-text describing your interest.</li>
          <li>If a prototype requires access credentials: account email, organization name, and security metadata needed to operate that prototype. The current website does not offer a generally available paid hosted-service signup.</li>
        </ul>
        <p style={styles.body}>A future contracted implementation could process the following only if defined in its agreement and DPA:</p>
        <ul style={styles.list}>
          <li>Trust receipts (cryptographically signed records of authorized actions). Receipts contain action context and signatures — not raw PII unless the customer's policy explicitly includes it.</li>
          <li>Policy data (the rules a customer organization authors for its Gate implementation).</li>
          <li>Entity authority records (which principal authorities exist within the customer's tenant).</li>
        </ul>
        <p style={styles.body}>
          We do not run advertising trackers, third-party analytics that fingerprint users, or session replay. The site uses no third-party cookies.
        </p>

        <h2 style={styles.h2}>3. How we use it</h2>
        <ul style={styles.list}>
          <li>Operate, secure, and improve the websites and public prototypes.</li>
          <li>Respond to inquiries and fulfil pilot or partnership requests.</li>
          <li>Comply with legal obligations and respond to lawful requests.</li>
          <li>For any future data processed under contract: only for the purposes and instructions documented in the applicable agreement.</li>
        </ul>
        <p style={styles.body}>
          We do not sell or rent personal information. If we later process trust-receipt, policy, or entity-authority data under contract, we will not use it to train models or improve services for other customers unless the customer gives separate, explicit permission.
        </p>

        <h2 style={styles.h2}>4. Sub-processors</h2>
        <p style={styles.body}>
          We use a small number of vendors to run the current website and inquiry flows. The current list and each vendor's stated scope are published at <a href="/legal/sub-processors" style={{ color: color.blue }}>/legal/sub-processors</a>. A future contracted service may require a separate sub-processor schedule and notice process.
        </p>

        <h2 style={styles.h2}>5. International transfers</h2>
        <p style={styles.body}>
          Our primary processing region is the United States. For customers in the EU/EEA, UK, or Switzerland, we rely on the EU Standard Contractual Clauses (SCCs) and equivalent UK addendum where required. Any customer-controlled regional deployment would require a separately scoped Gate Implementation and contract; no generally available region-pinned hosted Gate service is offered today.
        </p>

        <h2 style={styles.h2}>6. Retention</h2>
        <ul style={styles.list}>
          <li>Inquiry / contact form submissions — retained while the relationship is active and for 24 months thereafter unless deletion is requested.</li>
          <li>Server access metadata — retained under the active hosting configuration only as needed for security, operations, and legal obligations. Contact us for the current provider-specific period.</li>
          <li>Data processed by any future contracted implementation — only under the retention and deletion terms in the applicable agreement and DPA.</li>
          <li>Agent Adoption — the user-supplied candidate label and optional source URL, passkey public material, Operating Bond, and synthetic event history are retained for up to 30 days, then removed by a scheduled purge. The source URL is never fetched and is excluded from the public projection. An unlisted public projection can disappear sooner if the creating browser session revokes it.</li>
        </ul>

        <h2 style={styles.h2}>7. Your rights</h2>
        <p style={styles.body}>
          Depending on jurisdiction (including under GDPR, UK GDPR, and CCPA), you may have the right to access, correct, port, delete, or restrict processing of your personal data, object to certain processing, and lodge a complaint with a supervisory authority. Exercise these rights by emailing <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>. We respond within the timeline required by applicable law.
        </p>

        <h2 style={styles.h2}>8. Security</h2>
        <p style={styles.body}>
          We take reasonable technical and organizational measures to protect personal data against unauthorized access, loss, and misuse. The current security posture is documented at <a href="/security" style={{ color: color.blue }}>/security</a>. No system is perfectly secure; if we become aware of a breach affecting personal information, we provide notice as required by applicable law and any executed contract.
        </p>

        <h2 style={styles.h2}>9. Children</h2>
        <p style={styles.body}>
          The website and services are not directed at children under 16 and we do not knowingly collect their personal information.
        </p>

        <h2 style={styles.h2}>10. Changes</h2>
        <p style={styles.body}>
          We may update this policy. The "Effective" date above changes when we do. If a future contracted service requires a notice period, its executed agreement or DPA will control.
        </p>

        <h2 style={styles.h2}>11. Contact</h2>
        <p style={styles.body}>
          {ENTITY.legalName}<br />
          {ENTITY.address}<br />
          Privacy: <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a><br />
          Legal: <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a>
        </p>

        <p style={{ ...styles.body, marginTop: 32, fontSize: 12, color: color.t3, fontStyle: 'italic' }}>
          This policy is reviewed as our practices change. It is not a DPA or production-services commitment. For a separately scoped implementation or contract review, contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.t3 }}>{ENTITY.legalEmail}</a>.
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
