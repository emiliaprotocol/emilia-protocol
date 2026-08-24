// SPDX-License-Identifier: Apache-2.0

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import { GATE_IMPLEMENTATION, PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { color, cta, grid, styles } from '@/lib/tokens';

const IMPLEMENTED_ARTIFACTS = [
  {
    title: 'Exact-action binding',
    body: 'Reference Guard and Gate paths canonicalize material action fields, bind policy and authority evidence to those bytes, and return machine-readable decisions and refusal reasons.',
  },
  {
    title: 'Action-type policies and hard refusals',
    body: 'The shipped reference engine evaluates named action types, signoff thresholds, evidence conditions, and hard-deny flags. It does not automatically classify every tool or business consequence.',
  },
  {
    title: 'Accountable signoff and quorum',
    body: 'Reference signoff paths support enrolled approvers, distinct-human quorum, initiator exclusion, expiry, revocation, and one-time consumption under explicit profiles.',
  },
  {
    title: 'Portable verification',
    body: 'Protocol formats, verifiers, conformance vectors, and action-bound evidence support independent re-performance. They do not prove source truth, wisdom, provider outcome, or complete mediation.',
  },
] as const;

const DESIGNED_PROFILES = [
  {
    title: 'Risk-class taxonomy',
    body: 'Low, medium, high, and critical labels can be designed with a buyer, but no universal classifier or default business taxonomy is claimed. The buyer owns consequence classification and thresholds.',
  },
  {
    title: 'Tool and framework integration',
    body: 'MCP or HTTP calls can be mapped to a named Gate boundary only when the actual mutating route is known. An SDK call or gateway log alone does not establish prevention.',
  },
  {
    title: 'Regulatory mapping',
    body: 'EU AI Act, NIST AI RMF, and other framework mappings may inform future scoped work. This profile does not claim compliance, legal sufficiency, audit approval, or a certified control.',
  },
] as const;

const BOUNDARY_STEPS = [
  {
    step: '01',
    title: 'Name the consequential action',
    body: 'Choose one exact action and identify the system where its consequence becomes real.',
  },
  {
    step: '02',
    title: 'Define customer authority',
    body: 'Specify the accepted mandate, evidence, trust roots, expiry, and exception path without granting EMILIA production credentials during the pilot.',
  },
  {
    step: '03',
    title: 'Find every bypass',
    body: 'Map alternate credentials, direct APIs, administrative paths, and workflows that could avoid the proposed Gate.',
  },
  {
    step: '04',
    title: 'Decide whether to implement',
    body: `Validate in synthetic, sandbox, read-only, or shadow mode, then accept, continue observing, or stop before a separate ${GATE_IMPLEMENTATION.name}.`,
  },
] as const;

export default function AgentGovernancePackPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 64 }}>
          <div style={styles.eyebrowBlue}>Reference solution profile / Agent action authority</div>
          <h1 style={styles.h1}>Give the agent a mandate. Gate the consequential action.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            This reference profile composes implemented exact-action, signoff, consumption, and
            evidence artifacts. It is not a standalone governance product, a universal risk
            classifier, or evidence of a production customer deployment.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 28 }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>
              Scope the protected-workflow pilot
            </a>
            <a
              href="mailto:team@emiliaprotocol.ai?subject=Agent%20Gate%20Implementation%20inquiry"
              className="ep-cta"
              style={cta.secondary}
            >
              Ask about Gate Implementation
            </a>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Commercial boundary</div>
            <h2 style={styles.h2}>One public pilot, regardless of the proposing agent.</h2>
            <p style={{ ...styles.body, maxWidth: 780 }}>
              The only public offer is the {PROTECTED_WORKFLOW_PILOT.name}: {' '}
              {PROTECTED_WORKFLOW_PILOT.workflowLabel}, {PROTECTED_WORKFLOW_PILOT.durationLabel},{' '}
              {PROTECTED_WORKFLOW_PILOT.shortPriceLabel}. Finance operations is the first profile.
              Other consequential workflows use the same intake, not a second Agent Governance pilot.
            </p>
            <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
              <h3 style={styles.cardTitle}>Nonproduction only</h3>
              <p style={styles.cardBody}>
                The pilot uses synthetic, sandbox, buyer-approved read-only, or shadow inputs. It
                receives no provider credentials, production actuation authority, or permission to
                mutate the buyer&apos;s systems.
              </p>
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Implemented in the repository</div>
          <h2 style={styles.h2}>Building blocks with inspectable boundaries.</h2>
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
            <div style={styles.eyebrowBlue}>Designed profiles, not shipped defaults</div>
            <h2 style={styles.h2}>Configuration begins with the buyer&apos;s real boundary.</h2>
            <div style={grid.stack}>
              {DESIGNED_PROFILES.map((profile) => (
                <article key={profile.title} style={{ ...styles.card, opacity: 0.9 }}>
                  <h3 style={styles.cardTitle}>{profile.title}</h3>
                  <p style={styles.cardBody}>{profile.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Protected-path method</div>
          <h2 style={styles.h2}>From agent proposal to a buyer-owned implementation decision.</h2>
          <div style={grid.stack}>
            {BOUNDARY_STEPS.map((item) => (
              <article key={item.step} style={styles.card}>
                <div style={styles.eyebrowBlue}>{item.step}</div>
                <h3 style={{ ...styles.cardTitle, fontSize: 18, marginTop: 8 }}>{item.title}</h3>
                <p style={styles.cardBody}>{item.body}</p>
              </article>
            ))}
          </div>
          <p style={{ ...styles.body, marginTop: 24 }}>
            Only a completely mediated, buyer-accepted production boundary can support the rule:
            no accepted exact-action authority and required evidence, no provider entry.
          </p>
        </section>

        <section style={{ ...styles.sectionAlt, textAlign: 'center' }}>
          <div style={styles.section}>
            <h2 style={styles.h2}>Bring one action, not an entire agent platform.</h2>
            <p style={{ ...styles.body, maxWidth: 680, margin: '0 auto 24px' }}>
              The first task is to identify one leverage-bearing executor boundary and determine
              whether the proposed authority rule can be tested honestly without production access.
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
