'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

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
      const res = await fetch('/api/pilot/request', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name,
          org: form.org,
          email: form.email,
          workflow: 'other',
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
    { title: 'Privileged escalation inside an approved session', body: 'Authentication establishes a session, but a broad session or role grant may not bind the exact privilege change to current delegated authority.' },
    { title: 'Configuration changes without exact-action evidence', body: 'Infrastructure, security-policy, and access-control changes can be reconstructed only from several logs. The accepted authority for one exact mutation may remain implicit.' },
    { title: 'Deployment approval without parameter binding', body: 'A deployment workflow may record approval without cryptographically binding the artifact, target environment, configuration, and operation identifier that ultimately reach production.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Authority evidence at the action boundary', body: 'For each protected action, the relying party chooses accepted issuers, roles, delegation evidence, and policy. Gate binds the accepted evidence to the exact action rather than trusting declarations in the request body.' },
    { title: 'Exact action binding', body: 'A deployment approval can bind the exact artifact hash, target environment, configuration parameters, and accepted authority evidence. An approval for staging cannot verify for production parameters.' },
    { title: 'Accountable signoff for protected actions', body: 'Where the pinned profile requires it, Gate refuses the configured privileged action without a named signoff bound to the exact parameters. The resulting record is tamper-evident under its signed and content-addressed inputs.' },
    { title: 'Replay-resistant authorization', body: 'A one-time authorization for one action cannot verify for different parameters, environments, or validity windows. Gate consumes accepted authority through the configured durable admission store.' },
  ];

  const RISK_SCENARIOS = [
    { title: 'Privileged access changes', body: 'An admin adds a user to a high-privilege group, escalates a role, or grants emergency access. The session is valid. The specific access change has no action-level signoff, no parameter binding, and no replay resistance.' },
    { title: 'Deployment approvals', body: 'A CI/CD approval can authorize "a deployment" without binding the exact artifact hash, target environment, or configuration snapshot. Gate makes those material fields part of the decision.' },
    { title: 'Secrets and credential rotation', body: 'API keys, service-account credentials, and database passwords are often rotated inside authenticated admin sessions. A Gate profile can bind the rotation to the affected credential reference, new scope, and accepted authority without placing the secret itself in the receipt.' },
    { title: 'Security policy modifications', body: 'Firewall rules, network ACLs, WAF policies, and endpoint configurations change inside approved sessions. Gate adds a pre-action record of the exact parameters and accepted authority on the paths it covers.' },
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
              { value: 'Session', label: 'Authentication establishes who or what connected', accent: color.gold },
              { value: 'Action', label: 'Gate evaluates the exact proposed mutation', accent: color.gold },
              { value: 'Evidence', label: 'Decision, admission, and outcome remain distinguishable', accent: color.t3 },
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
            Enterprise systems authenticate users, assign roles, and log activity. Those controls answer different questions from exact-action admission. Gate adds the missing decision where a configured privileged operation is about to cross into the consequence owner.
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
              EMILIA sits between enterprise authentication and selected privileged actions. It does not replace IAM or RBAC. On a completely mediated covered path, Gate checks accepted authority and evidence for the exact action before provider entry.
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
          <p style={styles.body}>For a configured, completely mediated privileged path, Gate adds a pre-action authority decision and a portable record:</p>
        </div>
        {[
          'Each protected action binds its exact parameters to accepted authority evidence and the current policy',
          'Protected deployment approvals bind exact artifact hashes, target environments, and configuration states',
          'Each mediated configuration change can produce a tamper-evident record of the accepted authority evidence',
          'Action binding and one-time consumption refuse approval reuse for a different action',
          'Security teams receive action-level evidence that can support SOC 2, ISO 27001, and internal control testing',
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
            <p style={styles.body}>These are four action surfaces where a session-level permission can be wider than the exact mutation the operator intends to authorize.</p>
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
          <p style={styles.body}>Three operating pressures make exact-action evidence worth evaluating alongside existing enterprise controls.</p>
        </div>
        {[
          { title: 'A valid session can still carry the wrong action', body: 'Compromised credentials and malicious insiders can operate inside authenticated sessions. Exact-action authority gives the executor a decision point beyond the login event.' },
          { title: 'Supply chain attacks target the deployment pipeline', body: 'Build systems, CI/CD pipelines, and package registries are attack surfaces. Without action-level binding on deployment approvals, a compromised pipeline can push arbitrary artifacts to production under a valid approval.' },
          { title: 'Control reviewers need reconstructable evidence', body: 'Action-bound records can support SOC 2, ISO 27001, NIST CSF, and internal-control testing. The authorized reviewer still determines whether the complete control design and operation meet the applicable criteria.' },
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
            The protected-workflow pilot is available to enterprise security teams, platform engineering organizations, and infrastructure providers that can name one privileged executor boundary.
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
          <p style={styles.body}>
            {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} · {PROTECTED_WORKFLOW_PILOT.durationLabel} · {PROTECTED_WORKFLOW_PILOT.workflowLabel}. {PROTECTED_WORKFLOW_PILOT.rolloutLabel}.
          </p>
        </div>
        {submitted ? (
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.gold}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color: color.green, marginBottom: 8 }}>Thank you</div>
            <p style={{ color: color.t2, fontSize: 15 }}>We review all inquiries personally and will follow up if there is a fit.</p>
          </div>
        ) : (
          <form style={styles.card} onSubmit={handleSubmit}>
            <div style={grid.cols2}>
              {[['name','Name'],['org','Organization'],['title','Title'],['email','Email']].map(([k,label]) => (
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
