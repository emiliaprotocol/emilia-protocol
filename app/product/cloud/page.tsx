// SPDX-License-Identifier: Apache-2.0

import SiteFooter from '@/components/SiteFooter';
import SiteNav from '@/components/SiteNav';
import {
  GATE_IMPLEMENTATION,
  PRODUCTION_GATE,
  PROTECTED_WORKFLOW_PILOT,
} from '@/lib/commercial-offer';
import { color, cta, grid, styles } from '@/lib/tokens';

const REFERENCE_SURFACES = [
  {
    title: 'Policy operations',
    body: 'The repository includes tenant-scoped policy version, diff, simulation, and rollout surfaces. These are implemented reference artifacts, not evidence of an operated customer control plane.',
  },
  {
    title: 'Signoff operations',
    body: 'Reference APIs and dashboards cover challenge queues, decisions, quorum state, consumption, and escalation. Production use still requires buyer-pinned approvers, credentials, and authority rules.',
  },
  {
    title: 'Event and evidence operations',
    body: 'Reference event search, integrity checks, reports, exports, and evidence-readiness runs show the intended operating surface. A deployment must separately prove retention, access, and source coverage.',
  },
  {
    title: 'Tenant administration',
    body: 'Reference tenant, API-key, webhook, emergency-stop, and settings surfaces are implemented and tested. Their presence does not establish production isolation, availability, or customer adoption.',
  },
] as const;

const STATUS_LADDER = [
  {
    label: 'Implemented now',
    title: 'Reference operations surfaces',
    body: 'Runnable UI, API, and test artifacts exist in the public repository. They can be inspected without treating the hosted surface as a generally available managed service.',
  },
  {
    label: 'Current public offer',
    title: `${PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · ${PROTECTED_WORKFLOW_PILOT.durationLabel} · ${PROTECTED_WORKFLOW_PILOT.workflowLabel}`,
    body: 'The pilot maps one boundary and validates with synthetic, sandbox, read-only, or shadow inputs. It receives no production actuation authority or provider credentials.',
  },
  {
    label: 'Separate after acceptance',
    title: GATE_IMPLEMENTATION.name,
    body: 'A buyer-approved implementation can integrate one real executor boundary, customer-held credentials, trust roots, retention, and operating procedures. It is not included in the pilot.',
  },
] as const;

const NOT_CLAIMED = [
  'No generally available EMILIA-operated Gate or Cloud service',
  'No evidenced integrated customer deployment or production coverage',
  'No pilot access to production provider credentials or actuation',
  'No SLA, availability, compliance, audit, or customer-adoption claim',
] as const;

export default function CloudPage(): React.ReactElement {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <main>
        <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 64 }}>
          <div style={styles.eyebrowBlue}>Reference solution profile / Gate operations</div>
          <h1 style={styles.h1}>The operating surface a production Gate would need.</h1>
          <p style={{ ...styles.body, maxWidth: 720 }}>
            EMILIA has implemented reference policy, signoff, tenant, event, and evidence surfaces.
            Gate Cloud is not generally available as an operated service, and the repository does
            not evidence an integrated customer deployment.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 28 }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>
              Scope the protected-workflow pilot
            </a>
            <a
              href="mailto:team@emiliaprotocol.ai?subject=Gate%20Implementation%20inquiry"
              className="ep-cta"
              style={cta.secondary}
            >
              Ask about Gate Implementation
            </a>
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Commercial status</div>
            <h2 style={styles.h2}>Pilot first. Production is a separate decision.</h2>
            <p style={{ ...styles.body, maxWidth: 760 }}>
              The only public pilot is the fixed Protected-workflow pilot. It stays nonproduction.
              A real executor integration begins only after the buyer accepts the boundary and
              separately scopes {GATE_IMPLEMENTATION.name}.
            </p>
            <div style={grid.stack}>
              {STATUS_LADDER.map((item) => (
                <article key={item.label} style={styles.card}>
                  <div style={styles.eyebrowBlue}>{item.label}</div>
                  <h3 style={{ ...styles.cardTitle, fontSize: 18, marginTop: 8 }}>{item.title}</h3>
                  <p style={styles.cardBody}>{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section style={styles.section}>
          <div style={styles.eyebrowBlue}>Implemented artifacts</div>
          <h2 style={styles.h2}>Reference operations surfaces, not availability promises.</h2>
          <p style={{ ...styles.body, maxWidth: 760 }}>
            These surfaces show how an operator could administer an accepted Gate boundary. Each
            production claim still depends on the deployed topology, credentials, trust inputs,
            failure behavior, and complete-mediation review.
          </p>
          <div style={grid.auto(280)}>
            {REFERENCE_SURFACES.map((surface) => (
              <article key={surface.title} className="ep-card-hover" style={styles.card}>
                <h3 style={styles.cardTitle}>{surface.title}</h3>
                <p style={styles.cardBody}>{surface.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section style={styles.sectionAlt}>
          <div style={styles.section}>
            <div style={styles.eyebrowBlue}>Truth boundary</div>
            <h2 style={styles.h2}>What this page does not claim.</h2>
            <div style={{ ...styles.card, border: `1px solid ${color.border}` }}>
              <ul style={{ margin: 0, paddingLeft: 20, color: color.t2, lineHeight: 1.8 }}>
                {NOT_CLAIMED.map((claim) => <li key={claim}>{claim}</li>)}
              </ul>
              <p style={{ ...styles.cardBody, marginTop: 18 }}>
                {PRODUCTION_GATE.availabilityLabel}. Customer authority, policies, trust roots,
                provider credentials, acceptance rules, and portable evidence remain customer-owned.
              </p>
            </div>
          </div>
        </section>

        <section style={{ ...styles.section, textAlign: 'center' }}>
          <h2 style={styles.h2}>Start with one nonproduction boundary.</h2>
          <p style={{ ...styles.body, maxWidth: 680, margin: '0 auto 24px' }}>
            Bring one consequential workflow, its current approval path, and its known bypasses.
            The pilot produces a buyer-owned decision about whether a separate Gate Implementation
            is justified.
          </p>
          <a href="/pilot" className="ep-cta" style={cta.primary}>
            Review the {PROTECTED_WORKFLOW_PILOT.durationLabel} pilot
          </a>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
