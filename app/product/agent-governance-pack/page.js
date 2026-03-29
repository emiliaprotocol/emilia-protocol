'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

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

  const RISK_CLASSES = [
    { level: 'Low', color: color.green, actions: 'Read-only queries, status checks, data retrieval', signoff: 'No signoff required. Policy logged, action proceeds.' },
    { level: 'Medium', color: color.green, actions: 'Data modifications, configuration changes, non-financial writes', signoff: 'Single named human signoff. Agent pauses, presents action context, waits for attestation.' },
    { level: 'High', color: color.green, actions: 'Financial transactions, access grants, external communications', signoff: 'Named human signoff with action-bound attestation. Signoff is cryptographically bound to exact action parameters.' },
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
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Product / Agent Governance Pack</div>
        <h1 style={styles.h1}>Agent Governance Pack</h1>
        <p style={{ ...styles.body, maxWidth: 640 }}>
          Pre-configured EP deployment for AI agent execution control.
        </p>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Agent Governance Pilot</a>
      </section>

      {/* Risk classes */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Action risk classes</h2>
          <p style={styles.body}>Every agent action is classified by risk. Policy defines signoff requirements per class.</p>
          <div style={grid.stack}>
            {RISK_CLASSES.map((r, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: r.color, flexShrink: 0 }} />
                  <span style={{ ...styles.cardTitle, marginBottom: 0, fontSize: 17 }}>{r.level}</span>
                </div>
                <div style={{ fontSize: 13, color: color.t2, marginBottom: 6 }}>
                  <span style={styles.mono}>Actions: </span>{r.actions}
                </div>
                <div style={{ fontSize: 13, color: color.t2 }}>
                  <span style={styles.mono}>Signoff: </span>{r.signoff}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section style={styles.section}>
        <h2 style={styles.h2}>Included controls</h2>
        <p style={styles.body}>
          The Agent Governance Pack includes pre-configured policies, signoff workflows, and evidence formats designed for AI agent execution control.
        </p>
        <div style={grid.stack}>
          {FEATURES.map((f, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{f.title}</div>
              <div style={styles.cardBody}>{f.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Best first workflow */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Best first workflow</h2>
          <p style={styles.body}>Start with the highest-impact agent trust surface. For most deployments, that is agent-initiated high-value transactions.</p>
          <div className="ep-card-accent" style={{ ...styles.card, border: `1px solid ${color.border}` }}>
            <div style={{ ...styles.cardTitle, color: color.green, fontSize: 18, marginBottom: 10 }}>Agent-initiated high-value transaction</div>
            <div style={styles.cardBody}>
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
                  <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 1 }}>+</span>
                  <span style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.section}>
        <h2 style={styles.h2}>Request Agent Governance Pilot</h2>
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
                <input className="ep-input" style={styles.input} placeholder="e.g. agent transactions, tool-use control, autonomous operations" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
            <button className="ep-cta" onClick={handleSubmit} disabled={submitting || !form.name || !form.email} style={{ ...(!form.name || !form.email ? cta.disabled : cta.primary), marginTop: 20, width: '100%', textAlign: 'center' }}>
              {submitting ? 'Submitting...' : 'Request Agent Governance Pilot'}
            </button>
          </div>
        )}
      </section>

      <SiteFooter />
    </div>
  );
}
