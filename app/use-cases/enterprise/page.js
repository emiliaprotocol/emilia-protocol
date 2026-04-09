'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

export default function EnterpriseUseCasePage() {
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
        body: JSON.stringify({ type: 'pilot-enterprise', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

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

  const RISK_SCENARIOS = [
    { title: 'Privileged access changes', body: 'An admin adds a user to a high-privilege group, escalates a role, or grants emergency access. The session is valid. The specific access change has no action-level signoff, no parameter binding, and no replay resistance.' },
    { title: 'Deployment approvals', body: 'A production deployment proceeds through a CI/CD pipeline. The approval authorizes "a deployment" but does not bind the exact artifact hash, target environment, or configuration snapshot. A staging approval can be replayed against production.' },
    { title: 'Secrets and credential rotation', body: 'API keys, service account credentials, and database passwords are rotated inside authenticated admin sessions. No existing control binds the rotation action to the exact credential, the exact new value scope, and the exact authorizing principal.' },
    { title: 'Security policy modifications', body: 'Firewall rules, network ACLs, WAF policies, and endpoint security configurations change inside approved sessions. Post-incident logs show who was logged in. They do not show who authorized the specific policy change or what the exact parameters were.' },
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
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Use Case / Enterprise</div>
        <h1 className="ep-hero-text" style={styles.h1}>Action-level control for high-risk enterprise operations</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Privileged access escalation, configuration changes, and deployment approvals happen inside authenticated sessions every day. The control gap is not identity. It is the absence of a trust-control layer that binds the exact high-risk action to the exact authority chain before execution.
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
              { value: '80%', label: 'Of breaches involve privileged credential abuse (Verizon DBIR)', accent: color.gold },
              { value: '56d', label: 'Average dwell time before detection in enterprises', accent: color.gold },
              { value: '0',   label: 'Action-level binding on most deployment pipelines today', accent: color.t3 },
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
            Enterprise systems authenticate users, assign roles, and log activity. What they lack is a control layer that enforces trust at the exact moment a privileged action is about to execute. Role-based access control determines what a user can do. It does not enforce accountability for the specific action they are about to perform.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.gold)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>PROBLEM {String(i + 1).padStart(2, '0')}</div>
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
              EMILIA operates as a trust-control layer between enterprise authentication and privileged action execution. It does not replace IAM or RBAC. It adds action-level trust enforcement where existing access control stops.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.gold)}>
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
          <p style={styles.body}>Before EMILIA, a configuration change inside an authenticated admin session is invisible until post-incident review. After EMILIA:</p>
        </div>
        {[
          'Every privileged action requires a handshake binding the exact action parameters to the authorizing principal and authority chain',
          'Deployment approvals are bound to exact artifact hashes, target environments, and configuration states',
          'Every configuration change produces an immutable signoff record with named accountability',
          'Replay resistance ensures captured approvals cannot authorize different actions',
          'Security teams receive action-level audit trails that satisfy SOC 2, ISO 27001, and internal compliance requirements',
        ].map((item, i) => (
          <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
            <span className="ep-list-bullet">+</span>
            <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
          </div>
        ))}
      </section>

      {/* Where the gap hurts */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <h2 style={styles.h2}>Where the control gap hurts most</h2>
            <p style={styles.body}>These are the four action surfaces where enterprises have zero action-level trust enforcement today. Each one is a breach vector that existing IAM and RBAC do not cover.</p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {RISK_SCENARIOS.map((r, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.gold)}>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{r.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{r.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Why now */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>Why now</h2>
          <p style={styles.body}>Three forces are converging to make action-level trust enforcement an urgent requirement for enterprise security teams.</p>
        </div>
        {[
          { title: 'Identity compromise is the new perimeter breach', body: 'Attackers do not break through firewalls. They log in with compromised credentials and operate inside authenticated sessions. Session-level controls cannot distinguish a legitimate admin from a threat actor using the same valid session.' },
          { title: 'Supply chain attacks target the deployment pipeline', body: 'Build systems, CI/CD pipelines, and package registries are attack surfaces. Without action-level binding on deployment approvals, a compromised pipeline can push arbitrary artifacts to production under a valid approval.' },
          { title: 'Compliance frameworks are moving to action-level evidence', body: 'SOC 2 Type II, ISO 27001:2022, and NIST CSF 2.0 increasingly require evidence of who authorized specific actions, not just who had access. Session-level audit logs are no longer sufficient for examination.' },
        ].map((w, i) => (
          <div key={i} className={`ep-problem-row ep-reveal ep-stagger-${i + 1}`} style={{ marginBottom: 20 }}>
            <div style={{ fontFamily: font.sans, fontSize: 15, fontWeight: 700, color: color.t1, marginBottom: 6 }}>{w.title}</div>
            <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{w.body}</div>
          </div>
        ))}
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>Enterprise Privileged Actions</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Trust before high-risk action in enterprise operations
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            EMILIA is selectively working with enterprise security teams, platform engineering organizations, and infrastructure providers to pilot action-level trust enforcement for privileged operations.
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
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.gold}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <div style={styles.card}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
                <div key={k}>
                  <label style={styles.label}>{label}</label>
                  <input className="ep-input" style={styles.input} value={form[k]} onChange={e => update(k, e.target.value)} />
                </div>
              ))}
              <div style={{ gridColumn: '1 / -1' }}>
                <label style={styles.label}>Trust surface of interest</label>
                <input className="ep-input" style={styles.input} placeholder="e.g. deployment approvals, infrastructure config, privileged access management" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
