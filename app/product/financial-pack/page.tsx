// SPDX-License-Identifier: Apache-2.0

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { GATE_IMPLEMENTATION, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { color, cta, grid, styles } from '@/lib/tokens';

const IMPLEMENTED_ARTIFACTS = [
  {
    title: 'Finance precheck adapters',
    body: 'Reference routes exist for vendor bank-detail change, beneficiary creation, and payment release. They canonicalize named material fields and return a structured policy result.',
  },
  {
    title: 'Action-bound signoff rules',
    body: 'The reference policy engine supports accountable signoff, dual-control tiers, hard-deny signals, and one-time receipt consumption. A buyer still defines the accepted rule and approver authority.',
  },
  {
    title: 'Evidence and uncertainty fields',
    body: 'Reference records bind the action, policy, decision, execution contract, and evidence status. They do not prove bank-detail correctness, fraud absence, provider success, or real-world effect.',
  },
  {
    title: 'Reference financial risk inputs',
    body: 'The repository includes amount, velocity, counterparty, and risk-flag logic with test fixtures. It does not evidence a connected live sanctions feed or a customer production screening program.',
  },
] as const;

const PILOT_PHASES = [
  {
    step: '01',
    title: 'Map one path',
    body: 'Name the executor, current approval rule, credentials, alternate routes, and every path that could reach the provider.',
  },
  {
    step: '02',
    title: 'Observe without acting',
    body: 'Use synthetic, sandbox, buyer-approved read-only, or shadow inputs. The pilot does not receive provider credentials, release a payment, or change a bank record.',
  },
  {
    step: '03',
    title: 'Make the implementation decision',
    body: `Accept the proposed boundary, keep observing, or stop. Production begins only through a separately scoped ${GATE_IMPLEMENTATION.name}.`,
  },
] as const;

const OUTSIDE_THE_CLAIM = [
  'Unmediated credentials, alternate payment rails, and administrative bypasses',
  'The truth of a beneficiary or vendor bank-detail source',
  'Fraud absence, legal compliance, audit sufficiency, or payment success',
  'Any integrated customer deployment, production actuation, or adoption claim',
] as const;

export default function FinancialPackPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 64 }}>
          <div style={styles.eyebrowBlue}>Reference solution profile / Finance authority</div>
          <h1 style={styles.h1}>Control the exact finance action before provider entry.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            This profile assembles implemented EMILIA reference artifacts around one finance
            boundary. It is not a standalone product bundle, a fraud-prevention guarantee, or
            evidence of a deployed customer control.
          </p>
          <div style={{ ...styles.card, maxWidth: 760, marginTop: 28, border: `1px solid ${color.border}` }}>
            <div style={styles.eyebrowBlue}>First public profile</div>
            <h2 style={{ ...styles.cardTitle, fontSize: 19, marginTop: 8 }}>
              {PROTECTED_WORKFLOW_PILOT.firstProfileLabel}
            </h2>
            <p style={styles.cardBody}>{PROTECTED_WORKFLOW_PILOT.safetyRuleLabel}.</p>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 24 }}>
            <a href="/pilot?v=fin" className="ep-cta" style={cta.primary}>
              Scope the finance pilot
            </a>
            <a
              href="mailto:team@emiliaprotocol.ai?subject=Finance%20Gate%20Implementation%20inquiry"
              className="ep-cta"
              style={cta.secondary}
            >
              Ask about Gate Implementation
            </a>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>One canonical offer</div>
            <h2 style={styles.h2}>
              {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.durationLabel}.{' '}
              {PROTECTED_WORKFLOW_PILOT.shortPriceLabel}.
            </h2>
            <p style={{ ...styles.body, maxWidth: 760 }}>
              The pilot is nonproduction by design. It tests whether one buyer-owned control
              boundary is coherent before anyone discusses provider credentials or actuation.
            </p>
            <div style={grid.stack}>
              {PILOT_PHASES.map((phase) => (
                <article key={phase.step} style={styles.card}>
                  <div style={styles.eyebrowBlue}>{phase.step}</div>
                  <h3 style={{ ...styles.cardTitle, fontSize: 18, marginTop: 8 }}>{phase.title}</h3>
                  <p style={styles.cardBody}>{phase.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Implemented in the repository</div>
          <h2 style={styles.h2}>A reference profile with inspectable building blocks.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Implemented means code, tests, or public protocol artifacts exist. It does not mean a
            bank, treasury team, or payment provider has accepted or deployed the profile.
          </p>
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
            <div style={styles.eyebrowBlue}>Complete-mediation boundary</div>
            <h2 style={styles.h2}>Gate controls only the paths the buyer actually mediates.</h2>
            <p style={{ ...styles.body, maxWidth: 760 }}>
              A production Gate belongs immediately before the finance provider or system of
              record. Production protection requires every covered path to pass through that
              accepted boundary under customer-held credentials and trust inputs.
            </p>
            <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
              <h3 style={styles.cardTitle}>Outside this profile&apos;s claim</h3>
              <ul style={{ margin: '14px 0 0', paddingLeft: 20, color: color.t2, lineHeight: 1.8 }}>
                {OUTSIDE_THE_CLAIM.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, textAlign: 'center' }}>
          <h2 style={styles.h2}>Test one finance boundary without production access.</h2>
          <p style={{ ...styles.body, maxWidth: 680, margin: '0 auto 24px' }}>
            Bring the current workflow, owner, approval rule, executor path, and known bypasses.
            The pilot ends with a buyer-owned yes, no, or keep-observing decision.
          </p>
          <a href="/pilot?v=fin" className="ep-cta" style={cta.primary}>
            Review the fixed pilot
          </a>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
