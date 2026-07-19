'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

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
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>EMILIA Gate / Managed Cloud</div>
        <h1 style={styles.h1}>EMILIA Gate Cloud</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Managed policy, approval orchestration, durable consumption, and evidence operations
          around the enforcement adapter at your consequential execution boundary.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Cloud Access</a>
      </section>

      {/* Features grid */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Capabilities</h2>
          <p style={styles.body}>
            Gate Cloud operates the coordination plane as a managed service. You keep control of
            the protected executor, accepted keys, profiles, and trust sources; we operate the
            policy, ceremony, evidence, and monitoring services.
          </p>
          <div style={grid.auto(280)}>
            {FEATURES.map((f, i) => (
              <div key={i} style={styles.card}>
                <div style={styles.cardTitle}>{f.title}</div>
                <div style={styles.cardBody}>{f.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it fits */}
      <section style={styles.section}>
        <h2 style={styles.h2}>How Gate Cloud fits your stack</h2>
        <p style={styles.body}>
          The enforcement adapter remains immediately before your mutating system. It calls the
          managed control plane for policy, challenge, approval, and evidence operations, then
          refuses locally unless the required authorization can be consumed for that exact action.
        </p>
        <div style={grid.stack}>
          {[
            { title: 'Executor integration', body: 'Place the Gate adapter at each supported mutating path. Coverage is limited to the paths you fully mediate, and every uncovered path remains explicitly outside the guarantee.' },
            { title: 'Control plane', body: 'Policy registry, signoff orchestration, and event storage run as a managed service. You configure policies and consume evidence. We handle availability, scaling, and key management.' },
            { title: 'Evidence handoff', body: 'Export portable evidence and re-performance packages through the dashboard and API. Your auditor, underwriter, or internal assurer keeps the conclusion.' },
          ].map((item, i) => (
            <div key={i} style={styles.card}>
              <div style={styles.cardTitle}>{item.title}</div>
              <div style={styles.cardBody}>{item.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Request Cloud Access</h2>
          {submitted ? (
            <div style={{ ...styles.card, textAlign: 'center', padding: 40 }}>
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
                  <input className="ep-input" style={styles.input} placeholder="e.g. payment authorization, agent governance, API access control" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              {error && <p style={{ color: color.red, fontSize: 13, marginTop: 12 }}>{error}</p>}
              <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...((!form.name || !form.email) ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
                {submitting ? 'Submitting...' : 'Request Cloud Access'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
