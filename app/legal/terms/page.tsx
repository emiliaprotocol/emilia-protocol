'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const EFFECTIVE = '2026-08-23';

export default function TermsPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Terms</div>
        <h1 style={styles.h1}>Terms of Service</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE}
        </div>
        <p style={styles.body}>
          These Terms govern your use of the websites at <code style={{ fontFamily: font.mono, fontSize: 13 }}>emiliaprotocol.ai</code>, the documentation site, public prototypes, and inquiry interfaces operated by {ENTITY.legalName} ("EMILIA Protocol", "we", "us"). EMILIA does not currently offer a generally available hosted Gate or assurance service. Any future paid implementation or hosted service requires a separately signed agreement, which controls if it conflicts with these Terms.
        </p>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>1. The open-source artifacts</h2>
        <p style={styles.body}>
          The reference runtime, the protocol specification, the SDKs (<code style={{ fontFamily: font.mono, fontSize: 13 }}>@emilia-protocol/sdk</code> and <code style={{ fontFamily: font.mono, fontSize: 13 }}>@emilia-protocol/verify</code>), and the conformance suite are licensed under <a href="https://www.apache.org/licenses/LICENSE-2.0" target="_blank" rel="noopener noreferrer" style={{ color: color.blue }}>Apache License 2.0</a>. Use of those artifacts is governed by that license, not by these Terms.
        </p>

        <h2 style={styles.h2}>2. The websites and public prototypes</h2>
        <p style={styles.body}>
          The websites, documentation, playgrounds, explorers, synthetic demonstrations, and inquiry forms are provided under these Terms. They are evaluation surfaces, not a production deployment, certification, or service-level commitment. You may use them for lawful purposes consistent with the Acceptable Use Policy at <a href="/legal/acceptable-use" style={{ color: color.blue }}>/legal/acceptable-use</a>.
        </p>

        <h2 style={styles.h2}>3. Accounts</h2>
        <p style={styles.body}>
          A prototype or separately contracted implementation may require credentials. You are responsible for maintaining the confidentiality of credentials issued to you and for activity under them. Notify <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue }}>{ENTITY.securityEmail}</a> immediately if you suspect unauthorized access.
        </p>

        <h2 style={styles.h2}>4. Submitted information and future contracted data</h2>
        <p style={styles.body}>
          Information submitted through the current website is handled under the Privacy Policy at <a href="/legal/privacy" style={{ color: color.blue }}>/legal/privacy</a>. This page is not a data processing addendum. If a future contracted implementation requires EMILIA to process personal data on a customer's behalf, the parties must execute an appropriate agreement, including a DPA where required, before that processing begins.
        </p>

        <h2 style={styles.h2}>5. Availability and service levels</h2>
        <p style={styles.body}>
          Public website and prototype surfaces are provided as-is without a service-level commitment. No public pricing tier or availability target creates an SLA. Any future service level must be stated in a separately executed order form or agreement.
        </p>

        <h2 style={styles.h2}>6. Fees</h2>
        <p style={styles.body}>
          The current website does not create a paid subscription merely by displaying a price hypothesis, catalogue entry, or inquiry form. Fees, billing periods, taxes, and renewal terms for any future paid engagement must be stated in a separately executed agreement or order form.
        </p>

        <h2 style={styles.h2}>7. Intellectual property</h2>
        <p style={styles.body}>
          We retain all rights in the websites, non-open-source product code, the EMILIA Protocol trademark and brand, and any non-Apache-2.0 documentation. You retain all rights in content you submit. By submitting information through a current inquiry or prototype surface, you grant us a limited licence to process it only to provide that surface, respond to you, secure the service, and meet applicable legal obligations.
        </p>

        <h2 style={styles.h2}>8. Feedback</h2>
        <p style={styles.body}>
          If you submit feedback, suggestions, or ideas about the service or protocol, you grant us a perpetual, irrevocable, royalty-free license to use them without obligation. We commonly upstream good ideas into the open-source artifacts.
        </p>

        <h2 style={styles.h2}>9. Termination</h2>
        <p style={styles.body}>
          You may stop using the websites or public prototypes at any time. We may suspend or terminate access for violations of these Terms or the Acceptable Use Policy, security reasons, or as required by law. Data return and deletion for any future contracted service must be defined in the applicable agreement and DPA.
        </p>

        <h2 style={styles.h2}>10. Disclaimers</h2>
        <p style={styles.body}>
          To the maximum extent permitted by law, the websites and public prototypes are provided "as is" and "as available" without warranties of any kind. We do not warrant that they are error-free, uninterrupted, suitable for production use, or that they will meet specific requirements. Model checking or other repository evidence applies only to its stated model and scope; it does not establish an error-free operational service.
        </p>

        <h2 style={styles.h2}>11. Limitation of liability</h2>
        <p style={styles.body}>
          To the maximum extent permitted by law, neither party will be liable for indirect, incidental, special, consequential, or punitive damages arising out of or relating to these Terms. Our aggregate liability for direct damages under these Terms is limited to one hundred US dollars (US$100). Any separately contracted service is governed by the liability terms in its executed agreement. Nothing in this section limits liability where applicable law does not permit that limitation.
        </p>

        <h2 style={styles.h2}>12. Indemnification</h2>
        <p style={styles.body}>
          You agree to indemnify us against third-party claims arising out of your violation of these Terms, unlawful use of the public surfaces, or submitted content, to the extent permitted by law. Any EMILIA indemnity for a future contracted service must be stated in the executed agreement; none is created by this website.
        </p>

        <h2 style={styles.h2}>13. Governing law and disputes</h2>
        <p style={styles.body}>
          These Terms are governed by the laws of {ENTITY.jurisdiction}, excluding conflicts-of-law principles. Disputes are resolved in the courts of {ENTITY.jurisdiction} unless a separately executed agreement says otherwise. Nothing prevents either party from seeking injunctive relief in any court of competent jurisdiction to protect intellectual property or confidential information.
        </p>

        <h2 style={styles.h2}>14. Changes</h2>
        <p style={styles.body}>
          We may update these Terms. The "Effective" date changes when we do. Changes to a separately contracted service are governed by its executed agreement.
        </p>

        <h2 style={styles.h2}>15. Contact</h2>
        <p style={styles.body}>
          {ENTITY.legalName}<br />
          {ENTITY.address}<br />
          Legal: <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a><br />
          Security: <a href={`mailto:${ENTITY.securityEmail}`} style={{ color: color.blue }}>{ENTITY.securityEmail}</a>
        </p>

        <p style={{ ...styles.body, marginTop: 32, fontSize: 12, color: color.t3, fontStyle: 'italic' }}>
          These public Terms are not a production-services agreement, DPA, SLA, warranty, or order form. For a separately scoped implementation or contract review, contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.t3 }}>{ENTITY.legalEmail}</a>.
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
