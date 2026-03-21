'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';

export default function AgentGovernancePackPage() {
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
        body: JSON.stringify({ type: 'pilot-agent-governance-pack', ...form }),
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

  const RISK_CLASSES = [
    { level: 'Low', color: '#3b9b6e', actions: 'Read-only queries, status checks, data retrieval', signoff: 'No signoff required. Policy logged, action proceeds.' },
    { level: 'Medium', color: '#d4af55', actions: 'Data modifications, configuration changes, non-financial writes', signoff: 'Single named human signoff. Agent pauses, presents action context, waits for attestation.' },
    { level: 'High', color: '#d4af55', actions: 'Financial transactions, access grants, external communications', signoff: 'Named human signoff with action-bound attestation. Signoff is cryptographically bound to exact action parameters.' },
    { level: 'Critical', color: '#ef4444', actions: 'Irreversible actions, bulk operations, privilege escalation', signoff: 'Dual named human signoff. Two independent principals must attest to the exact action before the agent can proceed.' },
  ];

  const FEATURES = [
    { title: 'Action risk classes', body: 'Every agent action is classified into a risk level: low, medium, high, or critical. Risk classification is policy-defined and can be customized per agent, per tool, or per action type.' },
    { title: 'Signoff thresholds per risk class', body: 'Each risk class has a configurable signoff requirement. Low-risk actions proceed without signoff. Higher risk classes require progressively stronger attestation from named human principals.' },
    { title: 'Tool-use control', body: 'Policy defines which tools an agent can invoke, under what conditions, and with what signoff requirements. Tool invocations outside policy are blocked before execution, not logged after the fact.' },
    { title: 'Principal-to-agent attribution', body: 'Every agent action is attributed to the human principal who authorized it. The attribution chain is cryptographically bound: principal authorized agent, agent requested action, named human signed off on exact parameters.' },
    { title: 'EU AI Act / NIST AI RMF mapping', body: 'Pre-mapped controls for EU AI Act high-risk system requirements and NIST AI Risk Management Framework. EP trust enforcement satisfies human oversight, transparency, and accountability requirements across both frameworks.' },
  ];

  return (
    <div style={s.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...s.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={s.eyebrow}>Product / Agent Governance Pack</div>
        <h1 style={s.h1}>Agent Governance Pack</h1>
        <p style={{ ...s.body, maxWidth: 640 }}>
          Pre-configured EP deployment for AI agent execution control.
        </p>
        <a href="#pilot" style={{ ...s.cta, background: '#d4af55', color: '#0a0f1e' }}>Request Agent Governance Pilot</a>
      </section>

      {/* Risk classes */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Action risk classes</h2>
          <p style={s.body}>Every agent action is classified by risk. Policy defines signoff requirements per class.</p>
          <div style={{ display: 'grid', gap: 16 }}>
            {RISK_CLASSES.map((r, i) => (
              <div key={i} style={s.card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: r.color, flexShrink: 0 }} />
                  <span style={{ ...s.cardTitle, marginBottom: 0, fontSize: 17 }}>{r.level}</span>
                </div>
                <div style={{ fontSize: 13, color: '#8b95a5', marginBottom: 6 }}>
                  <span style={s.mono}>Actions: </span>{r.actions}
                </div>
                <div style={{ fontSize: 13, color: '#8b95a5' }}>
                  <span style={s.mono}>Signoff: </span>{r.signoff}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section style={s.section}>
        <h2 style={s.h2}>Included controls</h2>
        <p style={s.body}>
          The Agent Governance Pack includes pre-configured policies, signoff workflows, and evidence formats designed for AI agent execution control.
        </p>
        <div style={{ display: 'grid', gap: 16 }}>
          {FEATURES.map((f, i) => (
            <div key={i} style={s.card}>
              <div style={s.cardTitle}>{f.title}</div>
              <div style={s.cardBody}>{f.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Best first workflow */}
      <section style={s.sectionAlt}>
        <div style={s.section}>
          <h2 style={s.h2}>Best first workflow</h2>
          <p style={s.body}>Start with the highest-impact agent trust surface. For most deployments, that is agent-initiated high-value transactions.</p>
          <div style={{ ...s.card, border: '1px solid rgba(212,175,55,0.2)' }}>
            <div style={{ ...s.cardTitle, color: '#d4af55', fontSize: 18, marginBottom: 10 }}>Agent-initiated high-value transaction</div>
            <div style={s.cardBody}>
              An AI agent determines that a financial transaction, access grant, or irreversible operation should be executed. EP classifies the action by risk, pauses the agent, and presents the exact action context to a named human principal. The principal reviews the parameters and explicitly assumes responsibility through accountable signoff. The signoff is cryptographically bound to the exact action. Only then does the agent proceed. The full attribution chain is preserved: which human authorized the agent, what the agent requested, and who signed off on the exact execution.
            </div>
            <div style={{ marginTop: 16, display: 'grid', gap: 8 }}>
              {[
                'Agent pauses at policy-defined risk threshold',
                'Exact action context presented to named human principal',
                'Named human signoff bound to exact action parameters',
                'Full attribution chain: principal, agent, signoff, execution',
                'Immutable evidence record for regulatory and audit requirements',
              ].map((item, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                  <span style={{ color: '#d4af55', fontSize: 14, flexShrink: 0, marginTop: 1 }}>+</span>
                  <span style={{ fontSize: 14, color: '#8b95a5', lineHeight: 1.6 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={s.section}>
        <h2 style={s.h2}>Request Agent Governance Pilot</h2>
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
                <input style={s.input} placeholder="e.g. agent transactions, tool-use control, autonomous operations" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
              {submitting ? 'Submitting...' : 'Request Agent Governance Pilot'}
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
