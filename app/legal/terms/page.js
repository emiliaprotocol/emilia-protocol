'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const EFFECTIVE = '2026-05-05';

export default function TermsPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Terms</div>
        <h1 style={styles.h1}>Terms of Service</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE} · Working version pending final counsel review
        </div>
        <p style={styles.body}>
          These Terms govern your use of the websites at <code style={{ fontFamily: font.mono, fontSize: 13 }}>emiliaprotocol.ai</code>, the hosted EP Cloud service, the documentation site, and any related interface operated by {ENTITY.legalName} ("EMILIA Protocol", "we", "us"). By using these services you agree to these Terms.
        </p>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>1. The open-source artifacts</h2>
        <p style={styles.body}>
          The reference runtime, the protocol specification, the SDKs (<code style={{ fontFamily: font.mono, fontSize: 13 }}>@emilia-protocol/sdk</code> and <code style={{ fontFamily: font.mono, fontSize: 13 }}>@emilia-protocol/verify</code>), and the conformance suite are licensed under <a href="https://www.apache.org/licenses/LICENSE-2.0" target="_blank" rel="noopener noreferrer" style={{ color: color.blue }}>Apache License 2.0</a>. Use of those artifacts is governed by that license, not by these Terms.
        </p>

        <h2 style={styles.h2}>2. The websites and hosted services</h2>
        <p style={styles.body}>
          The websites, the hosted EP Cloud service, the playground, and the explorer are provided under these Terms. You may use them for lawful purposes consistent with the Acceptable Use Policy at <a href="/legal/acceptable-use" style={{ color: color.blue }}>/legal/acceptable-use</a>.
        </p>

        <h2 style={styles.h2}>3. Accounts</h2>
        <p style={styles.body}>
          Some features require an account. You are responsible for maintaining the confidentiality of credentials issued to you and for activity under your account. Notify <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue }}>{ENTITY.securityEmail}</a> immediately if you suspect unauthorized access.
        </p>

        <h2 style={styles.h2}>4. Customer data and DPA</h2>
        <p style={styles.body}>
          For hosted-service customers, the customer is the controller of any personal data processed through the service and we are the processor. The Privacy Policy at <a href="/legal/privacy" style={{ color: color.blue }}>/legal/privacy</a> functions as the working data processing addendum and is supplemented by an executed DPA upon request for paid tiers and any tier processing personal data of EU/EEA, UK, or Swiss data subjects.
        </p>

        <h2 style={styles.h2}>5. Service levels</h2>
        <p style={styles.body}>
          Free, developer, and observer tiers are provided as-is with no service-level commitment. Paid tiers carry the SLA stated in the order form. Status, incidents, and post-incident reports are published at <code style={{ fontFamily: font.mono, fontSize: 13 }}>status.emiliaprotocol.ai</code> when launched.
        </p>

        <h2 style={styles.h2}>6. Fees</h2>
        <p style={styles.body}>
          Fees, billing periods, and renewal terms for paid tiers are stated at the point of purchase or in the order form. Taxes are your responsibility unless the order form expressly says otherwise. Disputes about charges must be raised in writing to <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a> within 60 days of the charge.
        </p>

        <h2 style={styles.h2}>7. Intellectual property</h2>
        <p style={styles.body}>
          We retain all rights in the websites, the hosted service code, the EMILIA Protocol trademark and brand, and any non-Apache-2.0 documentation. You retain all rights in your content. By submitting content for processing through the hosted service, you grant us a limited license to process it solely as needed to operate the service for you.
        </p>

        <h2 style={styles.h2}>8. Feedback</h2>
        <p style={styles.body}>
          If you submit feedback, suggestions, or ideas about the service or protocol, you grant us a perpetual, irrevocable, royalty-free license to use them without obligation. We commonly upstream good ideas into the open-source artifacts.
        </p>

        <h2 style={styles.h2}>9. Termination</h2>
        <p style={styles.body}>
          You may stop using the websites or hosted services at any time. We may suspend or terminate access for violations of these Terms or the Acceptable Use Policy, for non-payment of fees, or as required by law. On termination of a hosted-service contract, customer data is exported on request and then deleted in accordance with the retention schedule in the Privacy Policy.
        </p>

        <h2 style={styles.h2}>10. Disclaimers</h2>
        <p style={styles.body}>
          To the maximum extent permitted by law, the websites and hosted services are provided "as is" and "as available" without warranties of any kind. We do not warrant that the services are error-free, uninterrupted, or that they will meet specific requirements. The protocol is formally verified at the model level; that does not imply the operational service is free of bugs.
        </p>

        <h2 style={styles.h2}>11. Limitation of liability</h2>
        <p style={styles.body}>
          To the maximum extent permitted by law, neither party will be liable for indirect, incidental, special, consequential, or punitive damages arising out of or relating to these Terms, and our aggregate liability for direct damages is limited to fees you paid us for the hosted service in the twelve months preceding the claim, or one hundred US dollars (US$100) for free-tier users. Nothing in this section limits liability for fraud, gross negligence, or willful misconduct.
        </p>

        <h2 style={styles.h2}>12. Indemnification</h2>
        <p style={styles.body}>
          You agree to indemnify us against third-party claims arising out of your violation of these Terms, your unlawful use of the services, or your content. We agree to indemnify hosted-service customers against third-party claims that the unmodified service infringes a third party's intellectual property, subject to standard exclusions stated in the order form.
        </p>

        <h2 style={styles.h2}>13. Governing law and disputes</h2>
        <p style={styles.body}>
          These Terms are governed by the laws of {ENTITY.jurisdiction}, excluding conflicts-of-law principles. Disputes are resolved in the courts of {ENTITY.jurisdiction} unless an executed order form specifies binding arbitration. Nothing prevents either party from seeking injunctive relief in any court of competent jurisdiction to protect intellectual property or confidential information.
        </p>

        <h2 style={styles.h2}>14. Changes</h2>
        <p style={styles.body}>
          We may update these Terms. The "Effective" date changes when we do. Material changes affecting paid customers are announced by email at least 30 days before they take effect.
        </p>

        <h2 style={styles.h2}>15. Contact</h2>
        <p style={styles.body}>
          {ENTITY.legalName}<br />
          {ENTITY.address}<br />
          Legal: <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a><br />
          Security: <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue }}>{ENTITY.securityEmail}</a>
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
