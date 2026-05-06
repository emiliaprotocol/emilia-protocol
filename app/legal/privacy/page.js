'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const EFFECTIVE = '2026-05-05';

export default function PrivacyPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Privacy</div>
        <h1 style={styles.h1}>Privacy Policy</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE} · Working version pending final counsel review
        </div>
        <p style={styles.body}>
          This policy describes how {ENTITY.legalName} ("EMILIA Protocol", "we", "us") collects, uses, and protects personal information when you use the websites at <code style={{ fontFamily: font.mono, fontSize: 13 }}>emiliaprotocol.ai</code>, the EP Cloud service, the open-source reference runtime, the published SDKs, or any related interface.
        </p>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>1. Roles</h2>
        <p style={styles.body}>
          When you use this website or our hosted services, we act as the <strong style={{ color: color.t1 }}>controller</strong> of personal data we collect about you (a website visitor, prospect, or hosted-service customer). When a customer organization uses the EP Cloud service to authorize actions involving end-user data, we act as a <strong style={{ color: color.t1 }}>processor</strong> and the customer organization is the controller. The customer's DPA governs that processing.
        </p>

        <h2 style={styles.h2}>2. What we collect</h2>
        <p style={styles.body}>For website visitors and prospects:</p>
        <ul style={styles.list}>
          <li>Standard request metadata (IP address, user agent, referrer, requested URL, timestamp). Held by Vercel as our hosting provider; rotated on Vercel's standard schedule.</li>
          <li>Information you submit voluntarily (contact form, partner inquiry, investor inquiry, pilot request) — name, organization, role, email, free-text describing your interest.</li>
          <li>If you sign up for the hosted service: account email, organization name, billing details (handled by our payment processor; we do not store full card numbers).</li>
        </ul>
        <p style={styles.body}>For hosted-service customer data we process on the customer's behalf:</p>
        <ul style={styles.list}>
          <li>Trust receipts (cryptographically signed records of authorized actions). Receipts contain action context and signatures — not raw PII unless the customer's policy explicitly includes it.</li>
          <li>Policy data (the rules a customer organization authors and ships to EP Cloud).</li>
          <li>Entity authority records (which principal authorities exist within the customer's tenant).</li>
        </ul>
        <p style={styles.body}>
          We do not run advertising trackers, third-party analytics that fingerprint users, or session replay. The site uses no third-party cookies.
        </p>

        <h2 style={styles.h2}>3. How we use it</h2>
        <ul style={styles.list}>
          <li>Operate, secure, and improve the websites and hosted services.</li>
          <li>Respond to inquiries, fulfill pilot or partnership requests, send transactional service notices.</li>
          <li>Comply with legal obligations and respond to lawful requests.</li>
          <li>For hosted-service customer data: only as instructed by the customer through the documented service interfaces.</li>
        </ul>
        <p style={styles.body}>
          We do not sell or rent personal information. We do not use customer trust-receipt data, policy data, or entity authority data to train models or to improve services for other customers.
        </p>

        <h2 style={styles.h2}>4. Sub-processors</h2>
        <p style={styles.body}>
          We use a small number of vetted sub-processors to run the websites and hosted services. The current list is published at <a href="/legal/sub-processors" style={{ color: color.blue }}>/legal/sub-processors</a> and is updated whenever a data flow changes. Customers can subscribe to change notifications by emailing <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>.
        </p>

        <h2 style={styles.h2}>5. International transfers</h2>
        <p style={styles.body}>
          Our primary processing region is the United States. For customers in the EU/EEA, UK, or Switzerland, we rely on the EU Standard Contractual Clauses (SCCs) and equivalent UK addendum where required. Customer-data residency is configurable on EP Cloud Enterprise tiers.
        </p>

        <h2 style={styles.h2}>6. Retention</h2>
        <ul style={styles.list}>
          <li>Inquiry / contact form submissions — retained while the relationship is active and for 24 months thereafter unless deletion is requested.</li>
          <li>Server access logs — 30 days at the edge, 90 days in cold storage.</li>
          <li>Hosted-service customer trust receipts and policy data — for the duration of the customer relationship plus the period required to comply with legal obligations or as specified in the customer's contract.</li>
        </ul>

        <h2 style={styles.h2}>7. Your rights</h2>
        <p style={styles.body}>
          Depending on jurisdiction (including under GDPR, UK GDPR, and CCPA), you may have the right to access, correct, port, delete, or restrict processing of your personal data, object to certain processing, and lodge a complaint with a supervisory authority. Exercise these rights by emailing <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a>. We respond within the timeline required by the applicable law and at most within 30 days.
        </p>

        <h2 style={styles.h2}>8. Security</h2>
        <p style={styles.body}>
          We take reasonable technical and organizational measures to protect personal data against unauthorized access, loss, and misuse. The current security posture is documented at <a href="/security" style={{ color: color.blue }}>/security</a>. No system is perfectly secure; if we become aware of a breach affecting your personal information we notify affected parties as required by applicable law and at most within 72 hours of confirmation.
        </p>

        <h2 style={styles.h2}>9. Children</h2>
        <p style={styles.body}>
          The website and services are not directed at children under 16 and we do not knowingly collect their personal information.
        </p>

        <h2 style={styles.h2}>10. Changes</h2>
        <p style={styles.body}>
          We may update this policy. The "Effective" date above changes when we do. Material changes are announced by email to active customers and via a notice on this page for at least 30 days.
        </p>

        <h2 style={styles.h2}>11. Contact</h2>
        <p style={styles.body}>
          {ENTITY.legalName}<br />
          {ENTITY.address}<br />
          Privacy: <a href={`mailto:${ENTITY.privacyEmail}`} style={{ color: color.blue }}>{ENTITY.privacyEmail}</a><br />
          Legal: <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a>
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
