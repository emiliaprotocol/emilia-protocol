'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function GovernancePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const LANES = [
    'Technical review',
    'Pilot participation',
    'Policy feedback',
    'Conformance discussion',
    'Governance participation',
    'Ecosystem partnership',
  ];

  const cardStyle = (accent) => ({
    border: `1px solid ${color.border}`,
    borderTop: `2px solid ${accent}`,
    borderRadius: radius.base,
    padding: '24px',
    background: '#FAFAF9',
  });

  return (
    <div style={styles.page}>
      <SiteNav activePage="Governance" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Governance</div>
        <h1 className="ep-hero-text" style={styles.h1}>Governance at EMILIA</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 560 }}>
          EMILIA is being developed as an open protocol for trust decisions and appeals. The protocol layer should become stronger through inspectability, conformance, ecosystem participation, and broader governance over time.
        </p>
      </section>

      {/* Protocol and company */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 24 }}>
            <h2 style={styles.h2}>Open protocol, clear execution</h2>
            <p style={styles.body}>
              We believe the protocol layer and the commercial layer should be clearly legible. The protocol can remain open and portable while companies build products, services, and implementation support on top.
            </p>
            <p style={styles.body}>
              The protocol should remain inspectable, interoperable, and challengeable even as commercial products are built on top of it.
            </p>
          </div>
        </div>
      </section>

      {/* Direction */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 24 }}>
          <h2 style={styles.h2}>Direction of travel</h2>
          <p style={styles.body}>
            Our long-term direction is to support broader participation in governance, conformance expectations, and policy discussion as the ecosystem matures.
          </p>
        </div>
      </section>

      {/* Trust evaluation */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Trust-graph dispute adjudication</h2>
            <p style={styles.body}>
              Dispute resolution is no longer purely operator-managed. High-confidence vouchers in the trust graph now vote on contested receipts. Voting weight is proportional to accumulated evidence — it cannot be purchased or injected. This makes the adjudication process Sybil-resistant by design and structurally harder to capture by any single operator.
            </p>
            <p style={styles.body}>
              The 48-hour procedural window before graph adjudication is enforced in code, not just policy. The dispute lifecycle — submission, operator response window, escalation to graph vote — is executed by the protocol itself. No manual override is needed; no human can short-circuit the window.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            {[
              { title: 'Operator dispute response window', body: '48 hours, enforced in code — not policy. The window cannot be shortened or bypassed.' },
              { title: 'Escalation to trust-graph vote', body: 'After the response window expires, contested receipts are escalated to a trust-graph vote automatically.' },
              { title: 'Evidence-weighted voting', body: 'Voucher voting weight is derived from accumulated evidence — it cannot be purchased or injected.' },
              { title: 'Sybil-resistant by design', body: 'No purchased influence on adjudication outcomes. The protocol enforces this structurally, not procedurally.' },
            ].map((item, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.gold)}>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{item.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{item.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Attribution chain */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 24 }}>
          <h2 style={styles.h2}>Attribution chain and human accountability</h2>
          <p style={styles.body}>
            Every receipt now carries an attribution chain: <code style={styles.mono}>Principal → Agent → Tool</code>. This creates a verifiable record of which human authorized which agent action, executed through which tool. Accountability for agent behavior is not diffused — it traces back to a specific human delegation decision.
          </p>
          <p style={styles.body}>
            Delegation Authority extends this further: EMILIA now scores the quality of human delegation decisions, not just agent outcomes. Principals who consistently authorize well-scoped, low-risk delegations build positive reputation. Principals who authorize reckless or disputed actions accumulate negative signal. Human accountability for machine behavior becomes legible and contestable.
          </p>
        </div>
      </section>

      {/* Participation lanes */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 32 }}>
            <h2 style={styles.h2}>Ways to participate</h2>
          </div>
          {LANES.map((lane, i) => (
            <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
              <span className="ep-list-bullet">+</span>
              <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{lane}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Open Protocol Governance</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Help shape the trust protocol
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            We are looking for technical reviewers, governance participants, and ecosystem partners who can strengthen correctness, adoption, and legitimacy.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="mailto:team@emiliaprotocol.ai" className="ep-cta" style={cta.primary}>Contact the Team</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
