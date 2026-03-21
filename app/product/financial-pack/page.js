'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function FinancialPackPage() {
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
        body: JSON.stringify({ type: 'pilot-financial-pack', ...form }),
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
    mono: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, color: '#4a90d9' },
  };

  const FEATURES = [
    { title: 'Beneficiary / remittance change controls', body: 'Cryptographic handshake required before any beneficiary or remittance destination change commits. The handshake binds the exact new destination, currency, and authorizing principal. No change executes without satisfied trust policy.' },
    { title: 'Treasury dual authorization', body: 'High-value treasury operations require two named principals to independently sign off on the exact action. Each signoff is cryptographically bound to the action parameters. Both must be satisfied before execution proceeds.' },
    { title: 'SOX-ready payment-action evidence', body: 'Every handshake, signoff, and execution event produces structured evidence records. Evidence packages satisfy SOX segregation-of-duties requirements and provide tamper-evident audit trails for financial controls.' },
    { title: 'Wire transfer protection', body: 'Wire instruction changes, new wire destinations, and wire amount modifications above policy thresholds require accountable signoff. The signoff binds the exact wire parameters to named authorizers.' },
    { title: 'Amount-based escalation', body: 'Policy-defined amount thresholds trigger escalating signoff requirements. Low-value actions may proceed with single signoff. High-value actions require dual authorization. Critical-value actions require dual authorization plus senior officer attestation.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Financial Control Pack</div>
        <h1 style={s.h1}>Financial Control Pack</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          Pre-configured EP deployment for financial transaction control.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Financial Pilot</a>
      </section>

      {/* Features */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Included controls</h2>
          <p style={s.body}>
            The Financial Control Pack includes pre-configured policies, signoff workflows, and evidence formats designed for financial transaction control. Deploy against a single trust surface in weeks, not months.
          </p>
          <div style={{ display: 'grid', gap: 16 }}>
            {FEATURES.map((f, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{f.title}</div>
                <div style={s.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Best first workflow */}
      <section style={s.section}>
        <h2 style={s.h2}>Best first workflow</h2>
        <p style={s.body}>Start with the highest-impact trust surface. For most financial deployments, that is beneficiary change.</p>
        <div style={{ ...s.card, border: '1px solid rgba(212,175,55,0.2)' }}>
          <div style={{ ...s.cardTitle, color: '#d4af55', fontSize: 18, marginBottom: 10 }}>Beneficiary change</div>
          <div style={s.cardBody}>
            A payment beneficiary, wire destination, or remittance target is modified within an authorized workflow. EP generates a cryptographic handshake binding the exact new destination, currency, amount, the requesting identity, and the authorizing officer. If the handshake is not satisfied, the change does not execute. For amounts above the dual-authorization threshold, two named principals must independently sign off. The signoff records are immutable and satisfy SOX evidence requirements.
          </div>
          <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
            {[
              'Handshake binds exact new beneficiary, currency, and amount',
              'Named officer signoff required before change commits',
              'Dual authorization for amounts above policy threshold',
              'Signoff is one-time consumable and replay-resistant',
              'SOX-grade evidence chain for every beneficiary change',
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span style={{ color: '#d4af55', fontSize: 14, flexShrink: 0, marginTop: 1 }}>+</span>
                <span style={{ fontSize: 14, color: '#8b95a5', lineHeight: 1.6 }}>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Request Financial Pilot</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#d4af55', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#8b95a5', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={s.card}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={s.label}>{label}</label>
                    <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Trust surface of interest</label>
                  <input style={s.input} placeholder="e.g. wire transfers, beneficiary changes, treasury operations" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Financial Pilot'}
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
