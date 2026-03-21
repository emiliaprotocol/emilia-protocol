'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function EnterpriseUseCasePage() {
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
        body: JSON.stringify({ type: 'pilot-enterprise', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const s = {
    page: { minHeight: '100vh', background: '#05060a', color: '#e8eaf0', fontFamily: "'Space Grotesk', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0a0c18', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'JetBrains Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#00d4ff', marginBottom: 16 },
    h1: { fontFamily: "'Outfit', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 900, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'Outfit', sans-serif", fontSize: 24, fontWeight: 800, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#7a809a', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'Outfit', sans-serif", fontSize: 16, fontWeight: 700, color: '#e8eaf0', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#7a809a', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0a0c18', color: '#e8eaf0', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#7a809a', marginBottom: 6, fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5 },
  };

  const PROBLEMS = [
    { title: 'Privileged access escalation inside approved sessions', body: 'Administrators and operators escalate privileges within authenticated sessions. The session is valid. The escalation is uncontrolled. No action-level enforcement exists to bind the exact privileged action to the exact authority chain.' },
    { title: 'Configuration changes without action-level accountability', body: 'Infrastructure configuration changes, security policy modifications, and access control updates happen inside legitimate admin sessions. Post-incident logs show who was logged in, not who authorized the specific change.' },
    { title: 'Deployment approvals without parameter binding', body: 'Production deployments proceed through approval workflows that authorize the deployment action but do not bind the exact deployment parameters: which artifact, which environment, which configuration, which principal approved.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Authority chain verification', body: 'Every privileged action requires verification of the complete authority chain: which principal requested, under what role, with what delegated authority, approved by whom. The chain is cryptographically bound to the exact action.' },
    { title: 'Exact action binding', body: 'A deployment approval binds the exact artifact hash, target environment, configuration parameters, and authorizing principal. An approval for staging cannot be replayed against production.' },
    { title: 'Accountable signoff for privileged actions', body: 'No privileged action executes without a named signoff. The signoff is bound to the exact action parameters, producing an immutable record of who authorized what, when, and under what policy.' },
    { title: 'Replay-resistant authorization', body: 'Each privileged action authorization is one-time consumable. Captured approvals cannot be replayed for different parameters, different environments, or different time windows.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Use Case / Enterprise</div>
        <h1 style={s.h1}>Action-level control for high-risk enterprise operations</h1>
        <p style={{ ...s.body, maxWidth: 620 }}>
          Privileged access escalation, configuration changes, and deployment approvals happen inside authenticated sessions every day. The control gap is not identity. It is the absence of a trust-control layer that binds the exact high-risk action to the exact authority chain before execution.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#ffd700', color: '#05060a' }}>Request Pilot</a>
      </section>

      {/* The problem */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>The problem</h2>
          <p style={s.body}>
            Enterprise systems authenticate users, assign roles, and log activity. What they lack is a control layer that enforces trust at the exact moment a privileged action is about to execute. Role-based access control determines what a user can do. It does not enforce accountability for the specific action they are about to perform.
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
          EMILIA operates as a trust-control layer between enterprise authentication and privileged action execution. It does not replace IAM or RBAC. It adds action-level trust enforcement where existing access control stops.
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
          <p style={s.body}>Before EMILIA, a configuration change inside an authenticated admin session is invisible until post-incident review. After EMILIA:</p>
          {[
            'Every privileged action requires a handshake binding the exact action parameters to the authorizing principal and authority chain',
            'Deployment approvals are bound to exact artifact hashes, target environments, and configuration states',
            'Every configuration change produces an immutable signoff record with named accountability',
            'Replay resistance ensures captured approvals cannot authorize different actions',
            'Security teams receive action-level audit trails that satisfy SOC 2, ISO 27001, and internal compliance requirements',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: '#ffd700', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#7a809a', lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...s.section, maxWidth: 540, paddingTop: 60, paddingBottom: 60 }}>
          <h2 style={{ ...s.h2, fontSize: 28 }}>Trust before high-risk action in enterprise operations</h2>
          <p style={s.body}>
            EMILIA is selectively working with enterprise security teams, platform engineering organizations, and infrastructure providers to pilot action-level trust enforcement for privileged operations.
          </p>
          <a href="#pilot" style={{ ...s.cta, background: '#ffd700', color: '#05060a' }}>Request Pilot</a>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Request a pilot</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#ffd700', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#7a809a', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
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
                  <input style={s.input} placeholder="e.g. deployment approvals, infrastructure config, privileged access management" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#ffd700', color: !form.name || !form.email ? '#4a4f6a' : '#05060a', marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#4a4f6a', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
