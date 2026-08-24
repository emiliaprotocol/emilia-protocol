'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function GovernmentUseCasePage() {
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
    { title: 'Benefits redirect inside authorized sessions', body: 'Threat actors change payment destinations, mailing/contact routes, or identity evidence within legitimate authenticated workflows. The session looks valid. The action is not.' },
    { title: 'Operator overrides without action-level accountability', body: 'Caseworkers and system operators can modify records, approve exceptions, and redirect funds. Current audit trails capture who logged in, not who authorized the exact action.' },
    { title: 'Payment destination changes in approved workflows', body: 'Wire destinations, direct-deposit targets, and disbursement accounts can change inside otherwise authenticated sessions.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Receipt binds exact action', body: 'A configured protected action can require a receipt that binds the enrolled credential, policy, action parameters, nonce, and execution-binding fields.' },
    { title: 'Signoff when policy requires it', body: 'A fresh human decision is one authority source. Gate requires it only when the buyer-pinned profile names it for the exact action.' },
    { title: 'Evidence packet for authorized review', body: 'A configured path can export scoped receipt, decision, policy, admission, and outcome evidence without deciding what conclusion an Inspector General, controller, or auditor should reach.' },
    { title: 'Replay-resistant admission', body: 'Within a shared durable state domain, accepted authority is reserved before provider entry and cannot be replayed for a different payment, amount, or destination.' },
  ];

  const WORKFLOWS = [
    { title: 'Vendor payment destination change', body: 'A candidate profile binds the exact new destination, vendor, policy, and required authority evidence before a completely mediated path admits provider entry.' },
    { title: 'Disbursement or grant release', body: 'A buyer can define the exact release, evidence threshold, and optional quorum under its own policy. EMILIA does not determine whether the payment is correct or lawful.' },
    { title: 'Provider enrollment or eligibility override', body: 'A candidate profile can bind an exact enrollment, payment-address, eligibility, or caseworker exception to the buyer-pinned policy and evidence requirement.' },
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
        <div className="ep-tag ep-hero-badge" style={{ color: color.green }}>Use Case / Government</div>
        <h1 className="ep-hero-text" style={styles.h1}>Government action-control solution profile</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Vendor payment destinations, disbursements, benefit routing, provider enrollment, and
          operator overrides are candidate protected workflows. On a completely mediated covered
          path, Gate evaluates exact authority and required evidence before provider entry. It does
          not prove fraud absence, source truth, program eligibility, or legal compliance.
        </p>
        <div className="ep-hero-text">
          <a href="/pilot?v=gov" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
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
              { value: 'Exact', label: 'Bind the administrative or payment action, not only the session', accent: color.green },
              { value: 'Pinned', label: 'Keep authority and evidence requirements buyer-controlled', accent: color.green },
              { value: 'Closed', label: 'Scope prevention to completely mediated covered paths', accent: color.t3 },
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
            Government systems authenticate users and log activity. A program may still need an
            independently checkable exact-action boundary before one selected consequence reaches
            its system of record. This page is a solution profile, not an adoption claim.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.green)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>PROBLEM {String(i + 1).padStart(2, '0')}</div>
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
              EMILIA can add a separate control layer between authentication and one configured
              executor. It does not replace identity management, eligibility systems, payment rails,
              or administrative judgment.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.green)}>
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
          'An evidence requirement binding the exact new destination, amount, and configured authority inputs',
          'An action-bound human decision record when the buyer-pinned policy requires one',
          'Shared durable reservation and replay refusal for accepted exact-action authority',
          'Scoped evidence exports that can support authorized oversight and control-testing procedures',
        ].map((item, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Best first workflow */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Best first workflow</h2>
            <p style={styles.body}>Pick one action surface for a synthetic, read-only, sandbox, or shadow assessment. These are candidate profiles, not claims about common agency deployments.</p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {WORKFLOWS.map((w, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.green)}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>WORKFLOW {String(i + 1).padStart(2, '0')}</div>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{w.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{w.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Government solution profile</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Trust before high-risk action in government workflows
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            The one public offer is {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel} to assess one
            buyer-selected consequence boundary. Finance operations remains the initial offered
            profile; government workflows are an eligible solution profile for fit review. It uses no production provider credentials or
            actuation. Production requires a separate Gate Implementation after the buyer accepts
            the boundary.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/pilot?v=gov" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
            <a href="/docs" className="ep-cta-secondary" style={{ ...cta.secondary, borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(250,250,249,0.7)' }}>See Government Architecture →</a>
          </div>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
