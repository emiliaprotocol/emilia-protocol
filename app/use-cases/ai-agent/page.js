'use client';

import { useState } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, grid, font, radius } from '@/lib/tokens';

export default function AIAgentUseCasePage() {
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
        body: JSON.stringify({ type: 'pilot-ai-agent', ...form }),
      });
      if (!res.ok) throw new Error('Submission failed');
      setSubmitted(true);
    } catch (err) { setError(err.message); }
    setSubmitting(false);
  }

  const PROBLEMS = [
    { title: 'Agents moving from recommendation to action', body: 'AI agents increasingly execute actions, not just suggest them. Tool calls, API requests, and workflow steps happen with broad permissions and no action-level control.' },
    { title: 'Broad tool access without action-level enforcement', body: 'Agent frameworks grant tool access at the connection level. An agent with access to a payment API can execute any payment, not just the one the principal intended.' },
    { title: 'No principal-to-agent attribution chain', body: 'When an agent executes a high-risk action, there is no structured record binding the delegating principal, the agent identity, the exact action, and the authority under which it was performed.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Action risk classes', body: 'Every agent action is classified by risk level. Read-only operations proceed without friction. High-risk actions (payments, data modifications, external API calls) require explicit trust enforcement before execution.' },
    { title: 'Signoff thresholds by risk class', body: 'High-risk agent actions require signoff from the delegating principal or a designated authority. The signoff is bound to the exact action parameters, not a blanket tool permission.' },
    { title: 'Principal-to-agent attribution', body: 'Every agent action produces a structured evidence chain: which principal delegated, which agent executed, what exact action, under what policy, with what authority. The delegation chain is traceable and auditable.' },
    { title: 'EU AI Act alignment', body: 'EMILIA produces the structured evidence records that high-risk AI system requirements demand: human oversight records, action-level traceability, and authority chain documentation.' },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* Hero */}
      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 60 }}>
        <div style={styles.eyebrowBlue}>Use Case / AI and Agent Control</div>
        <h1 style={styles.h1}>Trust-control layer between AI intent and execution</h1>
        <p style={{ ...styles.body, maxWidth: 620 }}>
          AI agents are moving from recommendations to actions. Tool calls execute payments, modify data, and trigger workflows with broad permissions and no action-level control. EMILIA is the trust substrate that enforces accountability before high-risk agent actions proceed.
        </p>
        <div style={{ ...styles.card, borderLeft: `3px solid ${color.blue}`, marginBottom: 24, padding: '16px 20px' }}>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>
            <span style={{ color: color.t1, fontWeight: 700 }}>AI is one wedge.</span> The broader category is high-risk action enforcement. EMILIA is not an AI company. It is control infrastructure for any workflow where a high-risk action executes without action-level trust. AI agents are one vertical where this gap is acute and growing.
          </div>
        </div>
        <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
      </section>

      {/* The problem */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>The problem</h2>
          <p style={styles.body}>
            Agent frameworks handle connection and tool discovery. What they do not handle is action-level trust enforcement. An agent with tool access can execute any action that tool permits. There is no structured control layer between the agent deciding to act and the action executing.
          </p>
          <div style={grid.stack}>
            {PROBLEMS.map((p, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{p.title}</div>
                <div style={styles.cardBody}>{p.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How EP helps */}
      <section style={styles.section}>
        <h2 style={styles.h2}>How EMILIA helps</h2>
        <p style={styles.body}>
          EMILIA is not an agent framework. It is infrastructure. It operates as the control layer between agent intent and action execution, enforcing trust, accountability, and policy compliance at the action level across any agent system.
        </p>
        <div style={grid.auto(280)}>
          {HOW_EP_HELPS.map((h, i) => (
            <div key={i} className="ep-card-hover" style={styles.card}>
              <div style={styles.cardTitle}>{h.title}</div>
              <div style={styles.cardBody}>{h.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Agent-specific enforcement */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>How EMILIA enforces trust in agent workflows</h2>
          <p style={styles.body}>Three protocol capabilities make EMILIA the control layer for agent-driven actions.</p>
          <div style={grid.stack}>
            {[
              { title: 'Delegated principal attribution', body: 'When an agent acts on behalf of a human, EMILIA records the full delegation chain: which principal delegated authority, to which agent identity, under what scope, with what constraints. The chain is cryptographically bound and auditable. No agent action executes without traceable human accountability.' },
              { title: 'Exact tool-use binding', body: 'An agent with access to a payment API can call any endpoint. EMILIA binds authorization to the exact tool call parameters: the specific API endpoint, the specific payload, the specific amount and destination. An approval to call transferFunds with $500 to Account A cannot be replayed for $5,000 to Account B.' },
              { title: 'Accountable signoff thresholds by risk class', body: 'Agent actions are classified into risk tiers. Read-only operations proceed without friction. Medium-risk actions require async principal notification. High-risk actions (payments, data deletion, external API calls with side effects) require explicit principal signoff before execution. The thresholds are policy-driven and configurable per deployment.' },
            ].map((a, i) => (
              <div key={i} className="ep-card-hover" style={styles.card}>
                <div style={styles.cardTitle}>{a.title}</div>
                <div style={styles.cardBody}>{a.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* EMILIA as infrastructure */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...styles.section, textAlign: 'left' }}>
          <h2 style={styles.h2}>Infrastructure, not an agent tool</h2>
          <p style={styles.body}>
            EMILIA is designed as trust substrate for high-risk action enforcement. AI agent control is one application of this substrate, not its boundary. The same protocol primitives that enforce trust before agent actions also enforce trust before government disbursements, financial wire transfers, and enterprise privileged operations.
          </p>
          {[
            'Action-level trust enforcement that works across agent frameworks, not inside one',
            'Protocol-grade primitives: handshake, signoff, receipt, dispute, appeal',
            'Risk classification that separates read-only operations from high-risk actions requiring human oversight',
            'Structured evidence production for regulatory compliance (EU AI Act, SOX, IG audit)',
            'Principal-to-agent delegation chains that make human accountability traceable',
          ].map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <span style={{ color: color.green, fontSize: 14, flexShrink: 0, marginTop: 2 }}>+</span>
              <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* CTA strip */}
      <section style={{ textAlign: 'center' }}>
        <div style={{ ...styles.section, maxWidth: 540, paddingTop: 60, paddingBottom: 60 }}>
          <h2 style={{ ...styles.h2, fontSize: 28 }}>Trust before high-risk action in AI and agent workflows</h2>
          <p style={styles.body}>
            EMILIA is selectively working with agent framework teams, AI infrastructure providers, and enterprise AI teams to pilot action-level trust enforcement for agent-driven workflows.
          </p>
          <a href="#pilot" className="ep-cta" style={cta.primary}>Request Pilot</a>
        </div>
      </section>

      {/* Pilot form */}
      <section id="pilot" style={styles.sectionAlt}>
        <div style={styles.section}>
          <h2 style={styles.h2}>Request a pilot</h2>
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
                  <input className="ep-input" style={styles.input} placeholder="e.g. MCP tool calls, agent-driven payments, autonomous workflow execution" value={form.surface} onChange={e => update('surface', e.target.value)} />
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
                {submitting ? 'Submitting...' : 'Request Pilot'}
              </button>
            </div>
          )}
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
