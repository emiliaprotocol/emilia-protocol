'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export default function GovernmentUseCasePage() {
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
          workflow: 'benefit_account_change',
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
    { title: 'Benefits redirect inside an authorized session', body: 'Payment destinations, mailing routes, or evidence references can change inside a legitimate authenticated workflow. A valid session does not establish authority for the exact redirect.' },
    { title: 'Operator override without exact-action evidence', body: 'Caseworkers and system operators can modify records and approve exceptions. Existing logs may identify the session without preserving the accepted authority and material parameters for one override.' },
    { title: 'Payment destination change in an approved workflow', body: 'Wire destinations, direct-deposit targets, and disbursement accounts can change after authentication has succeeded. The executor still needs an exact-action decision.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Receipt binds the exact action', body: 'Each protected action can return a receipt binding the presenting credential, accepted authority evidence, policy, material parameters, nonce, and admission result.' },
    { title: 'Fresh signoff when policy requires it', body: 'A relying party can require an enrolled approver credential over the exact action. A finite mandate can authorize unattended work inside its scope; the receipt does not establish civil identity by itself.' },
    { title: 'Evidence packet for authorized review', body: 'A packet can preserve the receipt, required approver evidence, admission, and outcome so an Inspector General, controller, or auditor can re-perform the stated checks under their own procedure.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured handshake cannot be replayed to authorize a different payment, amount, or destination.' },
  ];

  const WORKFLOWS = [
    { title: 'Vendor payment destination change', body: 'A supplier payment destination changes before the next disbursement run. GovGuard binds the exact new destination, vendor, policy, and named approver before the change can be treated as authorized.' },
    { title: 'Disbursement or grant release', body: 'A treasury or program payment is ready to leave. GovGuard applies the buyer\'s evidence policy, including a distinct-approver quorum when the configured threshold requires it.' },
    { title: 'Provider enrollment or eligibility override', body: 'A provider record, payment address, eligibility result, or caseworker override changes inside a valid session. GovGuard binds the exact exception to policy and named ownership.' },
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
        <h1 className="ep-hero-text" style={styles.h1}>Pre-payment control for government fraud</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Authentication can be valid while a vendor destination, benefit route, provider record, or override is wrong. GovGuard adds a customer-owned exact-action decision before a configured government workflow reaches its consequence owner.
        </p>
        <div className="ep-hero-text">
          <a href="/pilot/sandbox?v=gov" className="ep-cta" style={cta.primary}>Run GovGuard Fire Drill</a>
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
              { value: 'Session', label: 'Authentication establishes the operator context', accent: color.green },
              { value: 'Action', label: 'Gate checks the exact requested state change', accent: color.green },
              { value: 'Packet', label: 'Authorized reviewers can re-perform the stated checks', accent: color.t3 },
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
            Government systems authenticate users, authorize sessions, and log activity. Those controls do not always bind one material state change to accepted current authority. Gate adds that decision at the selected executor or system-of-record boundary.
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
              EMILIA sits between authentication and a selected government action. It does not replace identity management or session controls. On a completely mediated covered path, Gate refuses provider entry without accepted exact-action authority and required evidence.
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
          <p style={styles.body}>For a configured, completely mediated benefit-change or payment path, Gate adds:</p>
        </div>
        {[
          'Exact destination, amount, operation, policy, and accepted authority evidence bound together before admission',
          'A fresh approver record tied to the action when the buyer policy requires one',
          'One-time consumption and replay refusal for accepted authority',
          'Action-level evidence for an authorized reviewer to inspect alongside native system logs',
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
            <p style={styles.body}>Pick one high-risk action surface and start with a synthetic, read-only fire drill. These three examples make the authority source, material fields, and consequence owner concrete.</p>
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
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.green, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Government Fraud Prevention</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Trust before high-risk action in government workflows
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            The protected-workflow pilot is available to government agencies, system integrators, and public-sector technology teams that can name one consequence owner and one exact action schema.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/pilot/sandbox?v=gov" className="ep-cta" style={cta.primary}>Run GovGuard Fire Drill</a>
            <a href="/docs" className="ep-cta-secondary" style={{ ...cta.secondary, borderColor: 'rgba(255,255,255,0.15)', color: 'rgba(250,250,249,0.7)' }}>See Government Architecture →</a>
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
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.green}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <form style={styles.card} onSubmit={handleSubmit}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Agency / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
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
                <input className="ep-input" style={styles.input} placeholder="e.g. benefits disbursement, payment routing, operator approvals" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
