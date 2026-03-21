'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function FinancialUseCasePage() {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState(null);

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitting(true); setError(null);
    try {
      const res = await fetch('/api/inquiries', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'pilot-financial', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const s = {
    page: { minHeight: '100vh', background: '#0a0f1e', color: '#f0f2f5', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#111827', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#4a90d9', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#8b95a5', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#111827', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#f0f2f5', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#8b95a5', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#111827', color: '#f0f2f5', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#8b95a5', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
  };

  const PROBLEMS = [
    { title: 'Beneficiary changes inside approved sessions', body: 'Wire transfer destinations, ACH routing, and payment beneficiaries change inside authenticated workflows. The session is valid. The action is unauthorized.' },
    { title: 'Treasury approvals without action-level binding', body: 'Treasury management systems approve transactions at the session or role level. No existing control binds the exact transaction parameters to the exact authorizing principal at the moment of execution.' },
    { title: 'Wire transfer fraud in legitimate channels', body: 'Business email compromise and insider manipulation route funds through approved payment channels. Post-facto detection catches losses, not the action itself.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Dual signoff with exact transaction binding', body: 'High-value transactions require two named principals to sign off on the exact amount, destination, and routing parameters. The signoff is cryptographically bound to those exact values.' },
    { title: 'SOX-grade evidence production', body: 'Every high-risk financial action produces an immutable evidence chain: who requested, who authorized, what exact parameters, under what policy, at what time. Auditors get action-level proof, not access logs.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured wire approval cannot be replayed for a different amount, a different beneficiary, or a different routing instruction.' },
    { title: 'Policy-bound evaluation', body: 'Trust decisions are evaluated against explicit policies: transaction thresholds, counterparty risk classes, velocity limits, and dual-approval requirements. No black-box scoring.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Use Case / Financial Infrastructure</div>
        <h1 style={s.h1}>Control infrastructure for high-risk financial operations</h1>
        <p style={{ ...s.body, maxWidth: 620 }}>
          Beneficiary changes, wire transfers, and treasury approvals happen inside approved workflows every day. The control gap is not authentication. It is the absence of action-level trust enforcement at the exact moment a high-risk financial operation executes.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Pilot</a>
      </section>

      {/* The problem */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>The problem</h2>
          <p style={s.body}>
            Financial systems authenticate users, authorize sessions, and log events after execution. What they lack is a trust-control layer that enforces named accountability and exact parameter binding before the high-risk action proceeds.
          </p>
          <div style={{ display: 'grid', gap: 16 }}>
            {PROBLEMS.map((p, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{p.title}</div>
                <div style={s.cardBody}>{p.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How EP helps */}
      <section style={s.section}>
        <h2 style={s.h2}>How EMILIA helps</h2>
        <p style={s.body}>
          EMILIA operates as a control layer between authentication and financial action execution. It binds identity, authority, policy, and exact transaction parameters into a cryptographic handshake that must be satisfied before the action proceeds.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
          {HOW_EP_HELPS.map((h, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{h.title}</div>
              <div style={s.cardBody}>{h.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* What changes */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>What changes with EMILIA</h2>
          <p style={s.body}>Before EMILIA, a beneficiary change inside an authenticated treasury session is invisible until reconciliation. After EMILIA:</p>
          {[
            'Every wire transfer and beneficiary change requires a handshake binding the exact destination, amount, and authorizing principals',
            'Dual signoff is enforced at the action level, not the role or session level',
            'Every high-risk financial action produces SOX-grade evidence: principal, authority chain, policy, exact parameters, timestamp',
            'Replay resistance ensures a captured approval cannot be reused for a different transaction',
            'Compliance teams receive action-level audit trails that satisfy regulatory examination requirements',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: '#d4af55', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#8b95a5', lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Best first deployment */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...s.section, textAlign: 'left' }}>
          <h2 style={s.h2}>Best first deployment</h2>
          <p style={s.body}>Start with one high-risk action surface. These are the three workflows where banks and payment operators deploy EMILIA first.</p>
          <div style={{ display: 'grid', gap: 16 }}>
            {[
              { title: 'Beneficiary change', body: 'A counterparty or internal operator modifies wire beneficiary details inside an authenticated treasury session. EMILIA generates a handshake binding the exact new beneficiary, routing instruction, and authorizing principal. The change does not commit until the handshake is satisfied and a named signoff is recorded.' },
              { title: 'Payout destination change', body: 'An ACH or real-time payment destination is updated in a payment platform. EMILIA requires dual signoff bound to the exact new destination, amount ceiling, and effective date. Each signoff is one-time consumable and replay-resistant.' },
              { title: 'Treasury release approval', body: 'A treasury management system releases funds above a policy threshold. EMILIA enforces dual-principal signoff with exact parameter binding: amount, currency, counterparty, settlement date, and GL account. The approval cannot be reused for different parameters.' },
            ].map((d, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{d.title}</div>
                <div style={s.cardBody}>{d.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Proof points */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Built for banks and payment operators</h2>
          <p style={s.body}>EMILIA is control infrastructure designed for the exact constraints of regulated financial environments.</p>
          {[
            'One-time wire approval semantics: each authorization is cryptographically bound to a single transaction and consumed on use. A captured approval cannot authorize a second wire.',
            'Exact transaction binding: the handshake locks amount, currency, beneficiary, routing instruction, and settlement date. Any parameter change invalidates the authorization.',
            'Dual signoff support: high-value and high-risk transactions require two named principals to independently sign off on the exact same bound parameters before execution proceeds.',
            'Immutable event chain: every handshake, signoff, and execution produces a tamper-evident record. Compliance teams receive SOX-grade action-level evidence, not session access logs.',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: '#d4af55', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#8b95a5', lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 540, paddingTop: 60, paddingBottom: 60 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Trust before high-risk action in financial infrastructure</h2>
          <p style={s.body}>
            EMILIA is selectively working with financial institutions, treasury teams, and payment infrastructure providers to pilot action-level trust enforcement for high-risk financial operations.
          </p>
          <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Pilot</a>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={{ ...s.sectionAlt }}>
        <div style={s.section}>
          <h2 style={s.h2}>Request a pilot</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#d4af55', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#8b95a5', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={s.card}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[['name','Name'],['org','Institution / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={s.label}>{label}</label>
                    <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Trust surface of interest</label>
                  <input style={s.input} placeholder="e.g. wire transfers, treasury approvals, beneficiary management" value={form.surface} onChange={e => update('surface', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Problem description</label>
                  <textarea style={{ ...s.input, minHeight: 80, resize: 'vertical' }} value={form.problem} onChange={e => update('problem', e.target.value)} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Notes</label>
                  <input style={s.input} value={form.notes} onChange={e => update('notes', e.target.value)} />
                </div>
              </div>
              {error && <p style={{ color: '#f87171', fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#d4af55', color: !form.name || !form.email ? '#5a6577' : '#0a0f1e', marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#5a6577', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#5a6577', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
