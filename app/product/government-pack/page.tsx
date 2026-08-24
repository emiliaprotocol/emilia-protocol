// SPDX-License-Identifier: Apache-2.0

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { GATE_IMPLEMENTATION, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { color, cta, grid, styles } from '@/lib/tokens';

const IMPLEMENTED_ARTIFACTS = [
  {
    title: 'GovGuard reference adapters',
    body: 'Reference precheck routes cover named government action shapes such as payment-destination changes, releases, provider enrollment, eligibility overrides, and caseworker overrides.',
  },
  {
    title: 'Exact-action policy and signoff inputs',
    body: 'The reference paths bind organization, target, before and after state, policy, and configured signoff requirements. The agency remains responsible for authority, policy, identity, and legal sufficiency.',
  },
  {
    title: 'GG-1 reference conformance',
    body: 'Public tests and evidence exercise wrong-organization, wrong-approver, self-approval, replay, tamper, and execution-mismatch cases. This is reference conformance evidence, not deployment assurance.',
  },
  {
    title: 'Portable evidence fields',
    body: 'Reference outputs carry action, policy, execution-binding, and evidence status fields that can support later review. They do not issue an Inspector General, auditor, or regulator conclusion.',
  },
] as const;

const DESIGNED_NOT_IMPLEMENTED = [
  {
    title: 'PIV, CAC, and Login.gov integration',
    body: 'Designed as possible identity inputs for a future scoped implementation. No public artifact on this route establishes a completed integration.',
  },
  {
    title: 'FISMA, FedRAMP, and NIST 800-53 mappings',
    body: 'No published control mapping or authorization package is claimed here. EMILIA does not claim that the reference profile satisfies a framework or agency requirement.',
  },
  {
    title: 'Agency production operation',
    body: 'No integrated agency deployment, production provider boundary, operational authorization, managed availability, or customer adoption is evidenced.',
  },
] as const;

const PRODUCTION_REQUIREMENTS = [
  'A named mutating system and every covered route into it',
  'Agency-owned credentials, authority rules, trust roots, and approver directory',
  'Explicit bypass, emergency, retention, reconciliation, and operating procedures',
  'Buyer acceptance followed by a separately scoped Gate Implementation',
] as const;

export default function GovernmentPackPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 64 }}>
          <div style={styles.eyebrowBlue}>Reference solution profile / Government authority</div>
          <h1 style={styles.h1}>A reference authority boundary for consequential government actions.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            GovGuard reference adapters and conformance artifacts show how exact-action authority
            can be represented and tested. This page does not sell a Government Pack, claim an
            agency deployment, prevent fraud, or establish compliance.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 28 }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>
              Review the protected-workflow pilot
            </a>
            <a
              href="mailto:team@emiliaprotocol.ai?subject=Government%20Gate%20Implementation%20inquiry"
              className="ep-cta"
              style={cta.secondary}
            >
              Discuss a future implementation
            </a>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Commercial boundary</div>
            <h2 style={styles.h2}>There is one public pilot, not a Government Pack offer.</h2>
            <p style={{ ...styles.body, maxWidth: 780 }}>
              The canonical {PROTECTED_WORKFLOW_PILOT.name} is{' '}
              {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel}{' '}
              and {PROTECTED_WORKFLOW_PILOT.workflowLabel}. Finance operations is the first profile.
              Other consequential workflows may be evaluated through the same intake, but the pilot
              remains synthetic, sandbox, read-only, or shadow only.
            </p>
            <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
              <h3 style={styles.cardTitle}>During the pilot</h3>
              <p style={styles.cardBody}>
                EMILIA receives no production actuation authority or provider credentials. A buyer
                can inspect the proposed rule, evidence, refusal behavior, and uncovered paths before
                deciding whether to proceed.
              </p>
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Implemented in the repository</div>
          <h2 style={styles.h2}>Inspect the reference artifacts without inflating their status.</h2>
          <div style={grid.auto(280)}>
            {IMPLEMENTED_ARTIFACTS.map((artifact) => (
              <article key={artifact.title} className="ep-card-hover" style={styles.card}>
                <h3 style={styles.cardTitle}>{artifact.title}</h3>
                <p style={styles.cardBody}>{artifact.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Designed or future scope</div>
            <h2 style={styles.h2}>Named plainly because it is not shipped.</h2>
            <div style={grid.stack}>
              {DESIGNED_NOT_IMPLEMENTED.map((item) => (
                <article key={item.title} style={{ ...styles.card, opacity: 0.88 }}>
                  <h3 style={styles.cardTitle}>{item.title}</h3>
                  <p style={styles.cardBody}>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Production boundary</div>
          <h2 style={styles.h2}>{GATE_IMPLEMENTATION.name} starts after buyer acceptance.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            A production claim would require complete mediation at the agency&apos;s actual executor or
            system of record. Reference code and a nonproduction pilot do not establish that boundary.
          </p>
          <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
            <ul style={{ margin: 0, paddingLeft: 20, color: color.t2, lineHeight: 1.8 }}>
              {PRODUCTION_REQUIREMENTS.map((requirement) => <li key={requirement}>{requirement}</li>)}
            </ul>
          </div>
        </section>

        <section style={{ ...styles.section, textAlign: 'center' }}>
          <h2 style={styles.h2}>Start with the same evidence-bound intake.</h2>
          <p style={{ ...styles.body, maxWidth: 680, margin: '0 auto 24px' }}>
            Describe one consequential boundary and its current approval path. The first conversation
            determines whether it fits the canonical pilot or belongs in future implementation scope.
          </p>
          <a href="/pilot" className="ep-cta" style={cta.primary}>
            Review the canonical pilot
          </a>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
