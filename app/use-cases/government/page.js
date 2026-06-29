'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

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
      const res = await fetch('/api/inquiries', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'pilot-government', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const PROBLEMS = [
    { title: 'Benefits redirect inside authorized sessions', body: 'Threat actors change payment destinations, mailing/contact routes, or identity evidence within legitimate authenticated workflows. The session looks valid. The action is not.' },
    { title: 'Operator overrides without action-level accountability', body: 'Caseworkers and system operators can modify records, approve exceptions, and redirect funds. Current audit trails capture who logged in, not who authorized the exact action.' },
    { title: 'Payment destination changes in approved workflows', body: 'Wire destinations, direct deposit targets, and disbursement accounts change inside sessions that pass every existing authentication check.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Receipt binds exact action', body: 'Every high-risk action generates an authorization receipt that binds the actor, policy, action parameters, nonce, and execution-binding fields before execution proceeds.' },
    { title: 'Signoff ensures named human accountability', body: 'No high-risk action executes without a named principal signing off. The signoff is bound to the exact action context, not a blanket session approval.' },
    { title: 'Evidence packet for IG and controller review', body: 'Every receipt, signoff, and execution produces a packet showing which actions would have required approval, which policy fired, and how to verify representative receipts offline.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured handshake cannot be replayed to authorize a different payment, amount, or destination.' },
  ];

  const WORKFLOWS = [
    { title: 'Vendor payment destination change', body: 'A supplier payment destination changes before the next disbursement run. GovGuard binds the exact new destination, vendor, policy, and named approver before the change can be treated as authorized.' },
    { title: 'Disbursement or grant release', body: 'A treasury or program payment is ready to leave. GovGuard requires Class-A accountable signoff, and escalates million-dollar releases to dual authorization.' },
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

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 72 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.green }}>Use Case / Government</div>
        <h1 className="ep-hero-text" style={styles.h1}>Pre-payment control for government fraud</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          The hardest fraud to stop is the fraud that happens inside legitimate sessions. Vendor payment destinations, disbursements, benefit routing, provider enrollment, and operator overrides can all pass existing authentication. GovGuard enforces trust before the high-risk action, not after the loss.
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
              { value: '$233B-$521B', label: 'GAO annual federal fraud loss estimate, 2018-2022 data (GAO-24-105833)', accent: color.green },
              { value: 'GG-1', label: 'GovGuard conformance: missing receipt, wrong org, wrong approver, replay, tamper, and execution mismatch refused', accent: color.green },
              { value: '0',     label: 'Action-level authorization receipts in most government workflows today', accent: color.t3 },
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
            Government systems authenticate users. They authorize sessions. They log activity after the fact. What they do not do is enforce trust at the exact moment a high-risk action is about to execute.
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
              EMILIA inserts a control layer between authentication and action execution. It does not replace identity management or session controls. It adds action-level trust enforcement where none exists today.
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
          <p style={styles.body}>Before EMILIA, a benefits redirect inside an authenticated session is invisible until post-incident review. After EMILIA:</p>
        </div>
        {[
          'Every payment destination change requires a cryptographic handshake binding the exact new destination, amount, and authorizing principal',
          'Every operator override produces a named signoff record tied to the specific action, not a session log entry',
          'Every high-risk action is replay-resistant and one-time consumable',
          'Inspector General and GAO auditors receive action-level evidence chains, not session-level access logs',
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
            <p style={styles.body}>Pick one high-risk action surface and start with an observe-mode fire drill. These are the three most common starting points in government environments.</p>
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
            EMILIA is selectively working with government agencies, system integrators, and public-sector technology teams to pilot action-level trust enforcement.
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
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.green}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={styles.card}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Agency / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                <div key={k}>
                  <label style={styles.label}>{label}</label>
                  <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
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
            {error && <p style={{ color: '#DC2626', fontSize: 13, marginTop: 12 }}>{error}</p>}
            <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...(!form.name || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
