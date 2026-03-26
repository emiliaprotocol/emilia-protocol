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
    page: { minHeight: '100vh', background: '#020617', color: '#F8FAFC', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" },
    section: { maxWidth: 760, margin: '0 auto', padding: '80px 24px' },
    sectionAlt: { background: '#0F172A', borderTop: '1px solid rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.04)' },
    eyebrow: { fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#3B82F6', marginBottom: 16 },
    h1: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 'clamp(32px, 5vw, 48px)', fontWeight: 700, letterSpacing: -1, marginBottom: 16, lineHeight: 1.1 },
    h2: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 24, fontWeight: 700, letterSpacing: -0.5, marginBottom: 16 },
    body: { fontSize: 16, color: '#94A3B8', lineHeight: 1.75, marginBottom: 24 },
    card: { background: '#0F172A', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '24px 28px' },
    cardTitle: { fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 16, fontWeight: 700, color: '#F8FAFC', marginBottom: 6 },
    cardBody: { fontSize: 14, color: '#94A3B8', lineHeight: 1.65 },
    cta: { display: 'inline-block', padding: '12px 28px', borderRadius: 8, fontFamily: "'IBM Plex Mono', monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', textDecoration: 'none', cursor: 'pointer', border: 'none' },
    input: { width: '100%', padding: '12px 16px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.08)', background: '#0F172A', color: '#F8FAFC', fontSize: 15, fontFamily: 'inherit', outline: 'none' },
    label: { display: 'block', fontSize: 13, fontWeight: 600, color: '#94A3B8', marginBottom: 6, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: 0.5 },
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
        <a href="#pilot" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Request Pilot</a>
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
              <span style={{ color: '#22C55E', fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: '#94A3B8', lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Concrete risk scenarios */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...s.section, textAlign: 'left' }}>
          <h2 style={s.h2}>Where the control gap hurts most</h2>
          <p style={s.body}>These are the four action surfaces where enterprises have zero action-level trust enforcement today. Each one is a breach vector that existing IAM and RBAC do not cover.</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {[
              { title: 'Privileged access changes', body: 'An admin adds a user to a high-privilege group, escalates a role, or grants emergency access. The session is valid. The specific access change has no action-level signoff, no parameter binding, and no replay resistance.' },
              { title: 'Deployment approvals', body: 'A production deployment proceeds through a CI/CD pipeline. The approval authorizes "a deployment" but does not bind the exact artifact hash, target environment, or configuration snapshot. A staging approval can be replayed against production.' },
              { title: 'Secrets and credential rotation', body: 'API keys, service account credentials, and database passwords are rotated inside authenticated admin sessions. No existing control binds the rotation action to the exact credential, the exact new value scope, and the exact authorizing principal.' },
              { title: 'Security policy modifications', body: 'Firewall rules, network ACLs, WAF policies, and endpoint security configurations change inside approved sessions. Post-incident logs show who was logged in. They do not show who authorized the specific policy change or what the exact parameters were.' },
            ].map((r, i) => (
              <div key={i} style={s.card}>
                <div style={s.cardTitle}>{r.title}</div>
                <div style={s.cardBody}>{r.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why now */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Why now</h2>
          <p style={s.body}>Three forces are converging to make action-level trust enforcement an urgent requirement for enterprise security teams.</p>
          {[
            { title: 'Identity compromise is the new perimeter breach', body: 'Attackers do not break through firewalls. They log in with compromised credentials and operate inside authenticated sessions. Session-level controls cannot distinguish a legitimate admin from a threat actor using the same valid session.' },
            { title: 'Supply chain attacks target the deployment pipeline', body: 'Build systems, CI/CD pipelines, and package registries are attack surfaces. Without action-level binding on deployment approvals, a compromised pipeline can push arbitrary artifacts to production under a valid approval.' },
            { title: 'Compliance frameworks are moving to action-level evidence', body: 'SOC 2 Type II, ISO 27001:2022, and NIST CSF 2.0 increasingly require evidence of who authorized specific actions, not just who had access. Session-level audit logs are no longer sufficient for examination.' },
          ].map((w, i) => (
            <div key={i} style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: "'IBM Plex Sans', sans-serif", fontSize: 15, fontWeight: 700, color: '#F8FAFC', marginBottom: 4 }}>{w.title}</div>
              <div style={{ fontSize: 14, color: '#94A3B8', lineHeight: 1.65 }}>{w.body}</div>
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
          <a href="#pilot" style={{ ...s.cta, background: '#22C55E', color: '#020617' }}>Request Pilot</a>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Request a pilot</h2>
          {submitted ? (
            <div style={{ ...s.card, textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#22C55E', marginBottom: 8 }}>Thank you</div>
              <p style={{ color: '#94A3B8', fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
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
              <button onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...s.cta, background: !form.name || !form.email ? '#1a1e30' : '#22C55E', color: !form.name || !form.email ? '#64748B' : '#020617', marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <footer style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '40px 40px 32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', letterSpacing: 1 }}>EMILIA PROTOCOL · APACHE 2.0</div>
        <div style={{ display: 'flex', gap: 24 }}>
          {[['/governance','Governance'],['/partners','Partners'],['mailto:team@emiliaprotocol.ai','Contact'],['/investors','Investor Inquiries']].map(([href, label]) => (
            <a key={label} href={href} style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, color: '#64748B', textDecoration: 'none', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</a>
          ))}
        </div>
      </footer>
    </div>
  );
}
