'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function EnterprisePage() {
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
    mono: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: '#00d4ff' },
  };

  const FEATURES = [
    { title: 'VPC / private deployment', body: 'EP runs entirely within your infrastructure boundary. No trust data, policy configurations, or signoff records leave your network. Deploy in your VPC, private cloud, or air-gapped environment.' },
    { title: 'Data residency', body: 'All trust data, event records, and policy configurations reside in your chosen jurisdiction. Meet data sovereignty requirements without architectural compromise.' },
    { title: 'SSO / SCIM', body: 'Integrate with your identity provider via SAML 2.0 or OIDC. Automated user provisioning and deprovisioning through SCIM. Principal identities in EP map directly to your enterprise directory.' },
    { title: 'Evidence retention & legal hold', body: 'Configurable retention policies for all trust events. Legal hold capability preserves evidence across retention boundaries for litigation, investigation, or regulatory response.' },
    { title: 'Regulator artifact exports', body: 'Generate structured evidence packages for regulatory examination. Pre-formatted for common regulatory frameworks including SOX, FISMA, PCI-DSS, and sector-specific requirements.' },
    { title: 'Investigation tooling', body: 'Query and reconstruct action sequences across time, principals, and trust surfaces. Investigation mode provides forensic-grade evidence chains for incident response and internal audit.' },
    { title: 'Delegated administration', body: 'Hierarchical administration with scoped permissions. Delegate policy management, signoff configuration, and evidence access to business units without granting global control.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Enterprise</div>
        <h1 style={s.h1}>EP Enterprise</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          Hardened deployment for regulated environments that require private infrastructure, data residency, and compliance-grade evidence.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#ffd700', color: '#05060a' }}>Request Enterprise Pilot</a>
      </section>

      {/* Features */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Enterprise capabilities</h2>
          <p style={s.body}>
            EP Enterprise provides the full trust-control plane deployed within your infrastructure. Every feature available in EP Cloud, plus the controls required by regulated environments.
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

      {/* Deployment models */}
      <section style={s.section}>
        <h2 style={s.h2}>Deployment models</h2>
        <p style={s.body}>EP Enterprise supports multiple deployment topologies based on your security requirements and infrastructure constraints.</p>
        <div style={{ display: 'grid', gap: 16 }}>
          {[
            { title: 'Customer VPC', body: 'EP control plane deployed in your cloud account. You control the network boundary, encryption keys, and data lifecycle. We provide the container images, configuration, and operational runbooks.' },
            { title: 'Private cloud', body: 'On-premises deployment for environments that require physical infrastructure control. Supports VMware, OpenShift, and bare-metal Kubernetes. Air-gap compatible with offline policy updates.' },
            { title: 'Hybrid', body: 'Policy management and event explorer in EP Cloud. Signoff orchestration and evidence storage in your infrastructure. Minimizes operational burden while maintaining data residency for sensitive records.' },
          ].map((d, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{d.title}</div>
              <div style={s.cardBody}>{d.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Request Enterprise Pilot</h2>
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
                  <input style={s.input} placeholder="e.g. payment controls, privilege escalation, agent governance" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Enterprise Pilot'}
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
