'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function GovernmentUseCasePage() {
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
        body: JSON.stringify({ type: 'pilot-government', ...form }),
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
    stat: { textAlign: 'center', padding: '24px 16px' },
    statNumber: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 36, fontWeight: 700, color: '#d4af55', marginBottom: 4 },
    statLabel: { fontSize: 13, color: '#8b95a5', lineHeight: 1.5 },
  };

  const PROBLEMS = [
    { title: 'Benefits redirect inside authorized sessions', body: 'Threat actors change payment destinations within legitimate authenticated workflows. The session looks valid. The action is not.' },
    { title: 'Operator overrides without action-level accountability', body: 'Caseworkers and system operators can modify records, approve exceptions, and redirect funds. Current audit trails capture who logged in, not who authorized the exact action.' },
    { title: 'Payment destination changes in approved workflows', body: 'Wire destinations, direct deposit targets, and disbursement accounts change inside sessions that pass every existing authentication check.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Handshake binds exact action', body: 'Every high-risk action generates a cryptographic handshake that binds the actor, the authority chain, the policy, and the exact action parameters before execution proceeds.' },
    { title: 'Signoff ensures named human accountability', body: 'No high-risk action executes without a named principal signing off. The signoff is bound to the exact action context, not a blanket session approval.' },
    { title: 'Immutable audit trail for IG and GAO', body: 'Every handshake, signoff, and execution produces an immutable event record. Inspector General and GAO auditors get action-level traceability, not session-level logs.' },
    { title: 'Replay-resistant authorization', body: 'Each authorization is one-time consumable. A captured handshake cannot be replayed to authorize a different payment, a different amount, or a different destination.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Use Case / Government</div>
        <h1 style={s.h1}>Fraud prevention inside authorized government workflows</h1>
        <p style={{ ...s.body, maxWidth: 620 }}>
          The hardest fraud to stop is the fraud that happens inside legitimate sessions. Benefits redirects, payment destination changes, and operator overrides all occur within workflows that pass every existing authentication check. EMILIA enforces trust before the high-risk action, not after the breach.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Pilot</a>
      </section>

      {/* Numbers */}
      <section style={s.sectionAlt}>
        <div style={{ ...s.section, paddingTop: 60, paddingBottom: 60 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 24 }}>
            <div style={s.stat}>
              <div style={s.statNumber}>$236B</div>
              <div style={s.statLabel}>GAO-reported improper payments across federal programs annually</div>
            </div>
            <div style={s.stat}>
              <div style={s.statNumber}>$125K</div>
              <div style={s.statLabel}>Average loss per business email compromise incident (FBI IC3)</div>
            </div>
            <div style={s.stat}>
              <div style={s.statNumber}>0</div>
              <div style={s.statLabel}>Action-level trust enforcement layers in most government workflows today</div>
            </div>
          </div>
        </div>
      </section>

      {/* The problem */}
      <section style={s.section}>
        <h2 style={s.h2}>The problem</h2>
        <p style={s.body}>
          Government systems authenticate users. They authorize sessions. They log activity after the fact. What they do not do is enforce trust at the exact moment a high-risk action is about to execute.
        </p>
        <div style={{ display: 'grid', gap: 16 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{p.title}</div>
              <div style={s.cardBody}>{p.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* How EP helps */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>How EMILIA helps</h2>
          <p style={s.body}>
            EMILIA inserts a control layer between authentication and action execution. It does not replace identity management or session controls. It adds action-level trust enforcement where none exists today.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{h.title}</div>
                <div style={s.cardBody}>{h.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What changes */}
      <section style={s.section}>
        <h2 style={s.h2}>What changes with EMILIA</h2>
        <p style={s.body}>Before EMILIA, a benefits redirect inside an authenticated session is invisible until post-incident review. After EMILIA:</p>
        {[
          'Every payment destination change requires a cryptographic handshake binding the exact new destination, amount, and authorizing principal',
          'Every operator override produces a named signoff record tied to the specific action, not a session log entry',
          'Every high-risk action is replay-resistant and one-time consumable',
          'Inspector General and GAO auditors receive action-level evidence chains, not session-level access logs',
        ].map((item, i) => (
          <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
            <span style={{ color: '#d4af55', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
            <span style={{ fontSize: 15, color: '#8b95a5', lineHeight: 1.6 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Best first workflow */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Best first workflow</h2>
          <p style={s.body}>Pick one high-risk action surface and deploy EMILIA in enforcement mode. These are the three most common starting points in government environments.</p>
          <div style={{ display: 'grid', gap: 16 }}>
            {[
              { title: 'Payment destination change', body: 'A benefits recipient or vendor updates their bank account or routing number. EMILIA generates a cryptographic handshake binding the exact new destination, the requesting identity, and the authorizing caseworker before the change commits. If the handshake is not satisfied, the change does not execute.' },
              { title: 'Benefit redirect', body: 'A disbursement target changes inside an authenticated session. EMILIA requires a named signoff bound to the exact new target, amount, and program. The signoff record is immutable and available to Inspector General auditors in real time.' },
              { title: 'Operator override', body: 'A caseworker or system operator modifies a record, approves an exception, or escalates privileges. EMILIA enforces action-level accountability: the override does not proceed without a handshake that binds the exact action parameters to the exact operator identity and authority chain.' },
            ].map((w, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{w.title}</div>
                <div style={s.cardBody}>{w.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 600, paddingTop: 60, paddingBottom: 60 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Trust before high-risk action in government workflows</h2>
          <p style={s.body}>
            EMILIA is selectively working with government agencies, system integrators, and public-sector technology teams to pilot action-level trust enforcement.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
            <a href="/partners?type=government-pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e', width: '100%', maxWidth: 380, textAlign: 'center' }}>Request Fraud-Control Pilot</a>
            <a href="/docs/architecture" style={{ ...s.cta, background: 'transparent', color: '#4a90d9', border: '1px solid rgba(212,175,55,0.3)', width: '100%', maxWidth: 380, textAlign: 'center' }}>See Government Architecture</a>
            <a href="/docs" style={{ ...s.cta, background: 'transparent', color: '#8b95a5', border: '1px solid rgba(255,255,255,0.08)', width: '100%', maxWidth: 380, textAlign: 'center' }}>Download Audit Evidence Model</a>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.section}>
        <h2 style={s.h2}>Request a pilot</h2>
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
              {submitting ? 'Submitting...' : 'Request Pilot'}
            </button>
          </div>
        )}
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
