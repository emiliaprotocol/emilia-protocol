// SPDX-License-Identifier: Apache-2.0

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { GATE_IMPLEMENTATION, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { color, cta, grid, styles } from '@/lib/tokens';

const IMPLEMENTED_ARTIFACTS = [
  {
    title: 'iOS reference app and Swift SDK',
    body: 'Buildable reference code renders the exact-action presentation, material revisions, quorum, and consequence state, and composes with passkeys and App Attest evidence. Public distribution remains release-gated.',
  },
  {
    title: 'Android reference app and Kotlin SDK',
    body: 'Buildable reference code implements the same Action Lock and lifecycle with Credential Manager, Android Keystore, and Play Integrity inputs under server-pinned app identity. Public distribution remains release-gated.',
  },
  {
    title: 'WebAuthn signoff ceremony',
    body: 'Reference server paths register enrolled credentials, issue exact-action challenges, verify assertions, record approve or deny decisions, and enforce configured approver and quorum constraints.',
  },
  {
    title: 'Decision continuity artifacts',
    body: 'Reference formats distinguish authorized, consumed, indeterminate, executed, refused, withdrawn, expired, and cancelled states without treating a decision as provider outcome proof.',
  },
] as const;

const CEREMONY_STEPS = [
  {
    step: '01',
    title: 'Gate creates the challenge',
    body: 'The relying party resolves the authoritative action and binds its reference, CAID, digest, policy, intended approver, and expiry into one challenge.',
  },
  {
    step: '02',
    title: 'The reference client captures a decision',
    body: 'The app verifies the Action Lock, renders material fields and revisions, and returns an approve or deny response with the configured credential and supported integrity evidence.',
  },
  {
    step: '03',
    title: 'Gate verifies and consumes',
    body: 'At a separately implemented, completely mediated boundary, Gate can verify the accepted profile and consume admitted authority once before provider entry.',
  },
  {
    step: '04',
    title: 'Outcome remains separate',
    body: 'A provider timeout becomes indeterminate. Only retained, authenticated provider evidence bound to the same operation can resolve outcome; the app does not invent certainty or trigger blind replay.',
  },
] as const;

const DOES_NOT_PROVE = [
  'That the person perceived or understood every displayed field',
  'That the approved action was wise, legal, compliant, or factually correct',
  'That a provider accepted the request or the intended real-world effect occurred',
  'That every path to the provider passed through Gate',
  'That any customer has deployed these reference apps in production',
] as const;

export default function AccountableSignoffPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 64 }}>
          <div style={styles.eyebrowBlue}>Gate capture surface / Approver reference apps</div>
          <h1 style={styles.h1}>Bind a fresh human decision to the exact action.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            Approver reference apps capture a device-bound decision when a customer&apos;s policy
            requires fresh signoff. They are open reference artifacts and SDKs, not a standalone
            commercial product or a production control without an accepted Gate boundary.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 28 }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>
              Scope the protected-workflow pilot
            </a>
            <a
              href="mailto:team@emiliaprotocol.ai?subject=Approver%20Gate%20Implementation%20inquiry"
              className="ep-cta"
              style={cta.secondary}
            >
              Ask about Gate Implementation
            </a>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Operating posture</div>
            <h2 style={styles.h2}>AI workers need authority, not a tap for every action.</h2>
            <p style={{ ...styles.body, maxWidth: 780 }}>
              A standing, finite customer mandate can authorize unattended work inside its bounds.
              Fresh Approver signoff is one authority source, used only when policy requires
              per-occurrence review or when requested work is missing, stale, expired, widened, or
              otherwise outside the standing mandate.
            </p>
            <div style={grid.cols2}>
              <article style={styles.card}>
                <h3 style={styles.cardTitle}>Authentication</h3>
                <p style={styles.cardBody}>
                  Establishes control of an enrolled credential. It does not by itself authorize a
                  specific action with specific material fields.
                </p>
              </article>
              <article style={{ ...styles.card, border: `1px solid ${color.border}` }}>
                <h3 style={styles.cardTitle}>Exact-action signoff</h3>
                <p style={styles.cardBody}>
                  Adds the relying party&apos;s challenge, action bytes, profile, decision, credential,
                  and expiry so Gate can evaluate one bounded ceremony.
                </p>
              </article>
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Implemented in the repository</div>
          <h2 style={styles.h2}>Reference clients, SDKs, server paths, and tests.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            Implemented describes inspectable public artifacts. It does not establish public app
            distribution, managed availability, an integrated customer deployment, or production
            complete mediation.
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
            <div style={styles.eyebrowBlue}>How the capture surface composes</div>
            <h2 style={styles.h2}>The decision and the consequence stay distinct.</h2>
            <div style={grid.stack}>
              {CEREMONY_STEPS.map((item) => (
                <article key={item.step} style={styles.card}>
                  <div style={styles.eyebrowBlue}>{item.step}</div>
                  <h3 style={{ ...styles.cardTitle, fontSize: 18, marginTop: 8 }}>{item.title}</h3>
                  <p style={styles.cardBody}>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Claim boundary</div>
          <h2 style={styles.h2}>A verified ceremony is narrow evidence.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            It can establish that a pinned enrolled key completed the specified response over exact
            bytes under a named profile. It does not prove the broader conclusions below.
          </p>
          <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
            <ul style={{ margin: 0, paddingLeft: 20, color: color.t2, lineHeight: 1.8 }}>
              {DOES_NOT_PROVE.map((claim) => <li key={claim}>{claim}</li>)}
            </ul>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={{ ...styles.section, textAlign: 'center' }}>
            <div style={styles.eyebrowBlue}>One canonical offer</div>
            <h2 style={styles.h2}>
              {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.durationLabel}.{' '}
              {PROTECTED_WORKFLOW_PILOT.shortPriceLabel}.
            </h2>
            <p style={{ ...styles.body, maxWidth: 700, margin: '0 auto 24px' }}>
              The pilot is synthetic, sandbox, read-only, or shadow only. It receives no production
              provider credentials and cannot actuate a provider. Approver is included only if the
              proposed authority rule needs fresh human signoff. Production integration is a separate
              {GATE_IMPLEMENTATION.name} after buyer acceptance.
            </p>
            <a href="/pilot" className="ep-cta" style={cta.primary}>
              Review the canonical pilot
            </a>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
