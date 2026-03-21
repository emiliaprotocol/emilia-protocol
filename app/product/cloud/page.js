'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function CloudPage() {
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
        body: JSON.stringify({ type: 'pilot-cloud', ...form }),
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
    { title: 'Managed policy registry', body: 'Define, version, and deploy trust policies from a central control plane. Policy changes are audited and diffed before activation.' },
    { title: 'Policy simulation & diff', body: 'Test policy changes against historical action data before deploying. See exactly which actions would be affected, approved, or blocked by a proposed policy change.' },
    { title: 'Hosted signoff orchestration', body: 'Accountable signoff flows managed as a service. Challenge delivery, attestation collection, and consumption tracking without running signoff infrastructure.' },
    { title: 'Event explorer', body: 'Search, filter, and inspect every handshake, signoff, and execution event. Full action-level traceability across all trust surfaces.' },
    { title: 'Audit exports', body: 'Export evidence packages in formats consumable by auditors, compliance teams, and regulators. Structured data, not log files.' },
    { title: 'Tenant controls', body: 'Multi-tenant isolation with per-tenant policy configuration, signoff routing, and event boundaries. Each tenant operates as an independent trust domain.' },
    { title: 'Observability', body: 'Real-time metrics on policy evaluations, signoff latency, approval rates, and anomaly detection. Integrate with existing monitoring infrastructure via standard protocols.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Cloud</div>
        <h1 style={s.h1}>EP Cloud</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          Managed trust-control plane for teams that need policy management, signoff orchestration, and audit evidence without running infrastructure.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Cloud Access</a>
      </section>

      {/* Features grid */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Capabilities</h2>
          <p style={s.body}>
            EP Cloud provides the full trust-control plane as a managed service. You define policies, configure signoff requirements, and consume audit evidence. We run the infrastructure.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {FEATURES.map((f, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{f.title}</div>
                <div style={s.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it fits */}
      <section style={s.section}>
        <h2 style={s.h2}>How EP Cloud fits your stack</h2>
        <p style={s.body}>EP Cloud is a control plane, not an inline proxy. Your applications call the EP SDK at action decision points. The SDK communicates with the cloud control plane for policy evaluation and signoff orchestration. Your data path is unchanged.</p>
        <div style={{ display: 'grid', gap: 16 }}>
          {[
            { title: 'SDK integration', body: 'Instrument your application at action decision points. The SDK handles policy evaluation, signoff orchestration, and event emission. Typical integration is under 20 lines of code per action surface.' },
            { title: 'Control plane', body: 'Policy registry, signoff orchestration, and event storage run as a managed service. You configure policies and consume evidence. We handle availability, scaling, and key management.' },
            { title: 'Evidence consumption', body: 'Audit exports, event explorer, and compliance reports are available through the dashboard and API. Integrate evidence into existing GRC tooling or export for external auditors.' },
          ].map((item, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{item.title}</div>
              <div style={s.cardBody}>{item.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={{ ...s.sectionAlt }}>
        <div style={s.section}>
          <h2 style={s.h2}>Request Cloud Access</h2>
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
                  <input style={s.input} placeholder="e.g. payment authorization, agent governance, API access control" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Cloud Access'}
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
