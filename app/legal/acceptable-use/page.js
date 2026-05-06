'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const EFFECTIVE = '2026-05-05';

export default function AcceptableUsePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 32 }}>
        <div className="ep-tag ep-hero-badge">Legal · Acceptable Use</div>
        <h1 style={styles.h1}>Acceptable Use Policy</h1>
        <div style={{ fontFamily: font.mono, fontSize: 12, color: color.t3, marginBottom: 24 }}>
          Effective {EFFECTIVE} · Working version pending final counsel review
        </div>
        <p style={styles.body}>
          This policy describes what EMILIA Protocol services, SDKs, and brand may not be used for. It supplements the Terms of Service at <a href="/legal/terms" style={{ color: color.blue }}>/legal/terms</a>. Violations may result in suspension or termination of access, removal of content, and notice to law-enforcement or regulatory bodies where required.
        </p>
      </section>

      <article style={{ ...styles.section, paddingTop: 0, paddingBottom: 72 }}>

        <h2 style={styles.h2}>1. Prohibited use</h2>
        <p style={styles.body}>You may not use any EMILIA Protocol service, SDK, or interface to:</p>
        <ul style={styles.list}>
          <li>Violate any applicable law, regulation, or sanctions regime, including export controls administered by OFAC, BIS, or equivalent authorities.</li>
          <li>Infringe intellectual property, privacy, or publicity rights of any third party.</li>
          <li>Process or transmit information you do not have lawful authorization to process or transmit.</li>
          <li>Probe, scan, or test the vulnerability of any system or network without express written authorization from the owner; this includes systems run by us. Coordinated security research is welcomed via the policy at <a href="/security" style={{ color: color.blue }}>/security</a>.</li>
          <li>Bypass or attempt to bypass the protocol's authorization mechanisms, replay handshakes, forge signoffs, or otherwise undermine the integrity properties the protocol exists to enforce.</li>
          <li>Use the services to authorize, facilitate, or evade detection of fraud, money laundering, sanctions evasion, or terrorist financing.</li>
          <li>Operate the services on behalf of, or for the benefit of, parties subject to comprehensive sanctions in jurisdictions including Cuba, Iran, North Korea, Syria, the Crimea region of Ukraine, the so-called Donetsk and Luhansk People's Republics, or any individual or entity on the OFAC SDN list.</li>
          <li>Use the services to operate critical-safety systems where service degradation could cause physical harm — life support, transportation control, weapons-control systems — without an explicit written agreement covering that deployment.</li>
        </ul>

        <h2 style={styles.h2}>2. Restricted high-risk uses</h2>
        <p style={styles.body}>
          Some uses are permitted only with prior written agreement and additional safeguards. These include:
        </p>
        <ul style={styles.list}>
          <li>Authorization of state-sanctioned surveillance, mass-data-collection programs, or social-scoring systems prohibited under EU AI Act Article 5.</li>
          <li>Authorization of automated decisions producing legal or similarly significant effects on individuals where no meaningful human review is provided. (EP is designed to <em>support</em> human-in-the-loop accountability; using it to launder accountability away from a human is contrary to the protocol's purpose.)</li>
          <li>Use in the operation of weapons systems, autonomous lethal-force decisioning, or military targeting infrastructure.</li>
          <li>Use as a primary control in any setting where regulatory authority requires a different control (e.g., where bank regulations require a specific dual-control workflow that EP would replace rather than augment).</li>
        </ul>
        <p style={styles.body}>
          Contact <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a> before deploying any restricted use.
        </p>

        <h2 style={styles.h2}>3. Brand and trademark</h2>
        <p style={styles.body}>
          The EMILIA Protocol name, logos, and brand assets are owned by {ENTITY.legalName}. You may use them to refer to the protocol in good faith — for example, "powered by EMILIA Protocol", "EP-compliant", "EMILIA Protocol verifier" — provided you do not imply endorsement, partnership, or certification we have not given. Don't reuse our marks for products that compete with the hosted service or that misrepresent your relationship with us.
        </p>

        <h2 style={styles.h2}>4. Reporting violations</h2>
        <p style={styles.body}>
          If you become aware of a violation of this policy by any party using EMILIA Protocol services, please report it to <a href={`mailto:${ENTITY.legalEmail}`} style={{ color: color.blue }}>{ENTITY.legalEmail}</a>. For security vulnerabilities (including in third-party deployments of the open-source runtime) follow the disclosure process at <a href="/security" style={{ color: color.blue }}>/security</a>.
        </p>

        <h2 style={styles.h2}>5. Enforcement</h2>
        <p style={styles.body}>
          We may investigate, suspend, or terminate access in response to suspected violations. Where we identify content or activity that violates this policy on the hosted service, we may remove the content and notify the affected customer. We cooperate with lawful requests from competent authorities consistent with the Privacy Policy.
        </p>

        <h2 style={styles.h2}>6. Changes</h2>
        <p style={styles.body}>
          We update this policy as needed. The "Effective" date above changes when we do.
        </p>

      </article>

      <SiteFooter />
    </div>
  );
}
