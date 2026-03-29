'use client';

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function GovernancePage() {
  const LANES = [
    'Technical review',
    'Pilot participation',
    'Policy feedback',
    'Conformance discussion',
    'Governance participation',
    'Ecosystem partnership',
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="Governance" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrow}>Governance</div>
        <h1 style={styles.h1}>Governance at EMILIA</h1>
        <p style={{ ...styles.body, maxWidth: 560 }}>
          EMILIA is being developed as an open protocol for trust decisions and appeals. The protocol layer should become stronger through inspectability, conformance, ecosystem participation, and broader governance over time.
        </p>
      </section>

      {/* Protocol and company */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Open protocol, clear execution</h2>
          <p style={styles.body}>
            We believe the protocol layer and the commercial layer should be clearly legible. The protocol can remain open and portable while companies build products, services, and implementation support on top.
          </p>
          <p style={styles.body}>
            The protocol should remain inspectable, interoperable, and challengeable even as commercial products are built on top of it.
          </p>
        </div>
      </section>

      {/* Direction */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Direction of travel</h2>
        <p style={styles.body}>
          Our long-term direction is to support broader participation in governance, conformance expectations, and policy discussion as the ecosystem matures.
        </p>
      </section>

      {/* Trust evaluation */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Trust-graph dispute adjudication</h2>
          <p style={styles.body}>
            Dispute resolution is no longer purely operator-managed. High-confidence vouchers in the trust graph now vote on contested receipts. Voting weight is proportional to accumulated evidence -- it cannot be purchased or injected. This makes the adjudication process Sybil-resistant by design and structurally harder to capture by any single operator.
          </p>
          <p style={styles.body}>
            The 48-hour procedural window before graph adjudication is enforced in code, not just policy. The dispute lifecycle -- submission, operator response window, escalation to graph vote -- is executed by the protocol itself. No manual override is needed; no human can short-circuit the window.
          </p>
          <div style={grid.cols2}>
            {[
              'Operator dispute response window: 48 hours, enforced in code',
              'Escalation to trust-graph vote after window expires',
              'Voucher voting weight derived from accumulated evidence',
              'Sybil-resistant: no purchased influence on adjudication outcomes',
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
                <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Attribution chain */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Attribution chain and human accountability</h2>
        <p style={styles.body}>
          Every receipt now carries an attribution chain: <code style={styles.mono}>Principal &rarr; Agent &rarr; Tool</code>. This creates a verifiable record of which human authorized which agent action, executed through which tool. Accountability for agent behavior is not diffused -- it traces back to a specific human delegation decision.
        </p>
        <p style={styles.body}>
          Delegation Authority extends this further: EMILIA now scores the quality of human delegation decisions, not just agent outcomes. Principals who consistently authorize well-scoped, low-risk delegations build positive reputation. Principals who authorize reckless or disputed actions accumulate negative signal. Human accountability for machine behavior becomes legible and contestable.
        </p>
      </section>

      {/* Participation lanes */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Ways to participate</h2>
          <div style={grid.cols2}>
            {LANES.map((lane, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <span style={{ color: color.green, fontSize: 14, flexShrink: 0 }}>+</span>
                <span style={{ fontSize: 15, color: color.t2 }}>{lane}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ ...styles.section, textAlign: 'center', paddingBottom: 100 }}>
        <h2 style={{ ...styles.h2, fontSize: 28 }}>Want to help shape the trust protocol?</h2>
        <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Contact the Team</a>
      </section>

      <SiteFooter />
    </div>
  );
}
