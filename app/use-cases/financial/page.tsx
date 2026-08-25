'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export default function FinancialUseCasePage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const res = await fetch('/api/pilot/request', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name,
          org: form.org,
          email: form.email,
          workflow: 'beneficiary_change',
          offer_id: PROTECTED_WORKFLOW_PILOT.id,
          message: [form.title, form.surface, form.problem, form.notes].filter(Boolean).join('\n'),
        }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const PROBLEMS = [
    { title: 'Beneficiary changes inside approved sessions', body: 'Wire destinations, ACH routing, and payment beneficiaries can change inside authenticated workflows. A valid session does not by itself establish authority for the exact new destination.' },
    { title: 'Treasury approval without exact-action binding', body: 'Some approval flows preserve a role or session decision without cryptographically binding every material field that reaches the payment partner.' },
    { title: 'Fraud through legitimate channels', body: 'Business email compromise and insider manipulation can use approved payment channels. Detection and reconciliation remain important, but they occur after a request has already reached or crossed the rail.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Quorum when the buyer requires it', body: 'A relying-party profile can require two distinct enrolled approver credentials over the same amount, destination, and routing parameters. Quorum is a policy choice, not a universal requirement.' },
    { title: 'Action-level control evidence', body: 'Each protected financial action can produce a tamper-evident record of who requested it, who authorized it, the exact parameters, the policy, and the time. Auditors still decide what conclusion the record supports.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured wire approval cannot be replayed for a different amount, a different beneficiary, or a different routing instruction.' },
    { title: 'Policy-bound evaluation', body: 'The buyer pins the authority, evidence, thresholds, counterparty classes, velocity limits, and quorum rules that Gate evaluates. An external risk score may be an input, but it is never authority by itself.' },
  ];

  const DEPLOYMENTS = [
    { title: 'Beneficiary change', body: 'A counterparty or internal operator modifies wire beneficiary details inside an authenticated treasury session. EMILIA generates a handshake binding the exact new beneficiary, routing instruction, and authorizing principal. The change does not commit until the handshake is satisfied and a named signoff is recorded.' },
    { title: 'Payout destination change', body: 'An ACH or real-time payment destination is updated in a payment platform. Gate can require the buyer-selected evidence over the exact destination, amount ceiling, and effective date before the connector is entered.' },
    { title: 'Treasury release approval', body: 'For a release above a buyer-defined threshold, Gate can require a distinct-approver quorum over amount, currency, counterparty, settlement date, and GL account. That evidence cannot verify for different parameters.' },
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
          Beneficiary changes, wire transfers, and treasury approvals happen inside approved workflows every day. The control gap is not authentication. It is the absence of action-level trust enforcement at the exact moment a high-risk financial operation executes.
        </p>
        <div className="ep-hero-text">
          <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
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
              { value: 'Session', label: 'Authentication opens the workflow', accent: color.blue },
              { value: 'Action', label: 'Gate checks the exact payment instruction', accent: color.blue },
              { value: 'Rail', label: 'Provider entry follows accepted authority and evidence', accent: color.t3 },
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
            Financial systems authenticate users, authorize sessions, and log events. Those controls do not always bind the complete payment instruction to current exact-action authority at provider entry. Gate adds that decision on the paths the buyer selects.
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
              EMILIA Gate sits between authentication and a configured financial connector. On a completely mediated covered path, it checks the presenting credential, accepted authority, policy, and exact transaction before provider entry. A credential reference is not proof of civil identity.
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
          <p style={styles.body}>For a configured, completely mediated beneficiary-change or payment-release path, Gate adds:</p>
        </div>
        {[
          'Accepted authority and required evidence bound to the exact destination, amount, and operation',
          'Distinct-approver quorum at the action level when the buyer policy requires it',
          'Each protected financial action can preserve control-testing evidence: presenting credential, accepted authority, policy, exact parameters, and timestamp',
          'Action binding and one-time consumption refuse approval reuse for a different transaction',
          'Action-level evidence that can support, but does not decide, control testing or regulatory examination',
        ].map((item, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Best first deployment */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Best first deployment</h2>
            <p style={styles.body}>Start with one high-risk action surface. These three workflows make the material fields and consequence owner concrete.</p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {DEPLOYMENTS.map((d, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
                <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>DEPLOYMENT {String(i + 1).padStart(2, '0')}</div>
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
          <h2 style={styles.h2}>Built for banks and payment operators</h2>
          <p style={styles.body}>EMILIA is control infrastructure for a buyer-selected financial boundary. Production still requires the buyer to accept the connector, policy, durable store, keys, monitoring, and operating procedure.</p>
        </div>
        {[
          'One-time wire approval semantics: each authorization is cryptographically bound to a single transaction and consumed on use. A captured approval cannot authorize a second wire.',
          'Exact transaction binding: the handshake locks amount, currency, beneficiary, routing instruction, and settlement date. Any parameter change invalidates the authorization.',
          'Quorum support: a buyer profile can require two distinct enrolled approver credentials over the exact same bound parameters before provider entry.',
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
            The protected-workflow pilot is available to financial institutions, treasury teams, and payment infrastructure providers that can name one vendor-change or payment-release boundary.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 32 }}>
          <h2 style={styles.h2}>Request a pilot</h2>
          <p style={styles.body}>
            {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.rolloutLabel}.
          </p>
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.blue}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <form style={styles.card} onSubmit={handleSubmit}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Institution / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                <div key={k}>
                  <label htmlFor={`pilot-${k}`} style={styles.label}>{label}</label>
                  <input
                    id={`pilot-${k}`}
                    name={k}
                    type={k === 'email' ? 'email' : 'text'}
                    required={k === 'name' || k === 'org' || k === 'email'}
                    autoComplete={k === 'name' ? 'name' : k === 'org' ? 'organization' : k === 'email' ? 'email' : 'organization-title'}
                    className="ep-input"
                    style={styles.input}
                    value={form[k]}
                    onChange={e => update(k, e.target.value)}
                  />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Trust surface of interest</label>
                <input className="ep-input" style={styles.input} placeholder="e.g. wire transfers, treasury approvals, beneficiary management" value={form.surface} onChange={e => update('surface', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Problem description</label>
                <textarea className="ep-input" style={{ ...styles.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Notes</label>
                <input className="ep-input" style={styles.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
              </div>
            </div>
            {error && <p role="alert" aria-live="polite" style={{ color: '#DC2626', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button type="submit" className="ep-cta" disabled={submitting || !form.name || !form.org || !form.email} style={{ ...(!form.name || !form.org || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </form>
        )}
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
