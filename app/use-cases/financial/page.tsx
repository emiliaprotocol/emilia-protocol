'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function FinancialUseCasePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const PROBLEMS = [
    { title: 'Beneficiary changes inside authenticated sessions', body: 'A valid session can still leave a gap between broad role authority and the exact beneficiary, routing instruction, amount, and operation being attempted.' },
    { title: 'Approvals without exact-action binding', body: 'Some treasury workflows authorize a session or transaction class without independently checking the complete material payment instruction at provider entry.' },
    { title: 'Request-channel compromise', body: 'Email, voice, and operator-session signals can inform risk analysis but should not silently become exact-action authority for a payment release.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Configurable quorum with exact transaction binding', body: 'When the buyer-pinned policy requires two distinct approvers, each decision binds the same exact amount, destination, and routing parameters.' },
    { title: 'Action-level control evidence', body: 'Each protected financial action can produce a tamper-evident record of who requested it, who authorized it, the exact parameters, the policy, and the time. Auditors still decide what conclusion the record supports.' },
    { title: 'Replay-resistant admission', body: 'Within shared durable state, accepted authority is reserved before provider entry and cannot be replayed for a different amount, beneficiary, or routing instruction.' },
    { title: 'Policy-bound evaluation', body: 'Trust decisions are evaluated against explicit policies: transaction thresholds, counterparty risk classes, velocity limits, and dual-approval requirements. No black-box scoring.' },
  ];

  const CANDIDATE_WORKFLOWS = [
    { title: 'Beneficiary change', body: 'Assess whether one buyer-owned boundary can bind the exact new beneficiary, routing instruction, operation identifier, and required authority evidence.' },
    { title: 'Payout destination change', body: 'Assess a buyer-pinned evidence requirement for the exact new destination, amount ceiling, and effective date without changing production state.' },
    { title: 'Treasury release approval', body: 'Assess an exact payment release with the buyer-selected amount, currency, counterparty, settlement date, and optional quorum policy.' },
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
      <SiteNav activePage="" />
      <main>

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Use Case / Financial Infrastructure</div>
        <h1 className="ep-hero-text" style={styles.h1}>Control infrastructure for high-risk financial operations</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Beneficiary changes, payment releases, and treasury approvals can occur inside authenticated
          workflows. The initial offered profile tests whether one buyer-owned exact-action boundary
          closes a material gap before provider entry.
        </p>
        <div className="ep-hero-text">
          <a href="/pilot?v=fin" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
        </div>
      </section>

      {/* Stats */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{
            display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
          }}>
            {[
              { value: PROTECTED_WORKFLOW_PILOT.shortPriceLabel, label: 'Fixed protected-workflow pilot price', accent: color.blue },
              { value: PROTECTED_WORKFLOW_PILOT.durationLabel, label: 'Nonproduction assessment period', accent: color.blue },
              { value: '1', label: 'Buyer-selected consequence boundary assessed', accent: color.t3 },
            ].map((s, i) => (
              <div key={i} style={{ padding: '28px 24px', borderRight: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 700, color: s.accent, marginBottom: 6 }}>{s.value}</div>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.2, textTransform: 'uppercase', lineHeight: 1.5 }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* The problem */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>The problem</h2>
          <p style={styles.body}>
            Financial systems authenticate users, apply policy, and record events. A buyer may still
            need an exact-action boundary immediately before one selected payment change or release
            reaches its provider. EMILIA supplements rather than replaces those systems.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>PROBLEM {String(i + 1).padStart(2, '0')}</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{p.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{p.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* How EP helps */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>How EMILIA helps</h2>
            <p style={styles.body}>
              On a completely mediated covered path, EMILIA Gate evaluates buyer-pinned identity,
              authority, policy, and exact transaction evidence before provider entry. It does not
              establish payee identity, bank-detail correctness, fraud absence, or provider success.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{h.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{h.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What changes */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>What changes with EMILIA</h2>
          <p style={styles.body}>On a completely mediated protected path, a buyer-pinned profile can add:</p>
        </div>
        {[
          'Exact destination, amount, operation, and authority evidence binding for the selected workflow',
          'An action-level quorum only where the buyer-pinned policy requires it',
          'Each configured protected action can preserve control-testing evidence: principal, authority chain, policy, exact parameters, and timestamp',
          'Replay resistance ensures a captured approval cannot be reused for a different transaction',
          'Scoped evidence that can support an authorized regulatory or control-testing procedure without establishing compliance',
        ].map((item, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Candidate workflows */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Initial offered profile and adjacent candidates</h2>
            <p style={styles.body}>The initial offered profile is one finance-operations vendor bank-detail change or payment release. These examples are assessment candidates, not deployment claims.</p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {CANDIDATE_WORKFLOWS.map((d, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>CANDIDATE {String(i + 1).padStart(2, '0')}</div>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{d.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{d.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Built for banks */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>Finance-operations safety boundary</h2>
          <p style={styles.body}>No accepted exact-action authority and required evidence, no provider entry. The statement applies only to completely mediated covered paths.</p>
        </div>
        {[
          'One-time wire approval semantics: each authorization is cryptographically bound to a single transaction and consumed on use. A captured approval cannot authorize a second wire.',
          'Exact transaction binding: the handshake locks amount, currency, beneficiary, routing instruction, and settlement date. Any parameter change invalidates the authorization.',
          'Configurable quorum support: when the buyer-pinned policy requires it, distinct enrolled credentials decide over the exact same bound parameters.',
          'Tamper-evident event chain: each protected handshake, signoff, and execution statement can be reconstructed as action-level control evidence rather than only a session access log.',
        ].map((item, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Financial Infrastructure Controls</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Trust before high-risk action in financial infrastructure
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel}. One assessed consequence boundary.
            Synthetic, read-only, sandbox, or shadow validation only, with no production provider
            credentials or production actuation. Production requires a separate Gate Implementation after the
            buyer accepts the boundary.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/pilot?v=fin" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
          </div>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
