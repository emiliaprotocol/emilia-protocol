'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function GovernmentPackPage() {
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
        body: JSON.stringify({ type: 'pilot-government-pack', ...form }),
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
    { title: 'Benefits payment redirect controls', body: 'Cryptographic handshake required before any payment destination change commits. The handshake binds the exact new destination, program, amount, and authorizing principal. No redirect executes without satisfied trust policy.' },
    { title: 'Operator override constraints', body: 'Every caseworker or system operator override produces a named signoff record. The signoff is bound to the exact action parameters, not a session-level approval. Override without accountability does not proceed.' },
    { title: 'IG/GAO-ready audit evidence', body: 'Every handshake, signoff, and execution event produces an immutable record. Evidence packages are pre-formatted for Inspector General and GAO examination. Action-level traceability, not session-level logs.' },
    { title: 'Government identity integration', body: 'Native support for PIV/CAC smart cards, Login.gov, and agency-specific identity providers. Principal identities in EP map directly to government-issued credentials.' },
    { title: 'FISMA/FedRAMP mapping', body: 'Pre-mapped controls for FISMA and FedRAMP authorization. EP trust enforcement satisfies action-level accountability requirements across multiple control families. Documentation packages available for ATO submissions.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Government Control Pack</div>
        <h1 style={s.h1}>Government Control Pack</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          Pre-configured EP deployment for government fraud prevention.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Government Pilot</a>
      </section>

      {/* Features */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Included controls</h2>
          <p style={s.body}>
            The Government Control Pack includes pre-configured policies, signoff workflows, and evidence formats designed for government fraud prevention. Deploy against a single trust surface in weeks, not months.
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
        <p style={s.body}>Start with the highest-impact trust surface. For most government deployments, that is payment destination change.</p>
        <div style={{ ...s.card, border: '1px solid rgba(212,175,55,0.2)' }}>
          <div style={{ ...s.cardTitle, color: '#d4af55', fontSize: 18, marginBottom: 10 }}>Payment destination change</div>
          <div style={s.cardBody}>
            A benefits recipient, vendor, or disbursement target updates their bank account, routing number, or payment address. EP generates a cryptographic handshake binding the exact new destination, the requesting identity, the authorizing caseworker, and the applicable policy. If the handshake is not satisfied, the change does not execute. The signoff record is immutable and available to Inspector General auditors in real time.
          </div>
          <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
            {[
              'Handshake binds exact new destination, amount, and program',
              'Named caseworker signoff required before change commits',
              'Signoff is one-time consumable and replay-resistant',
              'Immutable event record available to IG and GAO auditors',
              'Policy defines which changes require signoff based on risk class',
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
          <h2 style={s.h2}>Request Government Pilot</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#d4af55', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#8b95a5', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
            </div>
          ) : (
            <div style={s.card}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {[['name','Name'],['org','Agency / Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                  <div key={k}>
                    <label style={s.label}>{label}</label>
                    <input style={s.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                  </div>
                ))}
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={s.label}>Trust surface of interest</label>
                  <input style={s.input} placeholder="e.g. benefits disbursement, payment routing, operator approvals" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Government Pilot'}
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
