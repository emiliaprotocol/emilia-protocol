'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

export default function AIAgentUseCasePage() {
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

  const ENFORCEMENT = [
    { title: 'Delegated principal attribution', body: 'When an agent acts on behalf of a human, EMILIA records the full delegation chain: which principal delegated authority, to which agent identity, under what scope, with what constraints. The chain is cryptographically bound and auditable. No agent action executes without traceable human accountability.' },
    { title: 'Exact tool-use binding', body: 'An agent with access to a payment API can call any endpoint. EMILIA binds authorization to the exact tool call parameters: the specific API endpoint, the specific payload, the specific amount and destination. An approval to call transferFunds with $500 to Account A cannot be replayed for $5,000 to Account B.' },
    { title: 'Accountable signoff thresholds by risk class', body: 'Agent actions are classified into risk tiers. Read-only operations proceed without friction. Medium-risk actions require async principal notification. High-risk actions (payments, data deletion, external API calls with side effects) require explicit principal signoff before execution. The thresholds are policy-driven and configurable per deployment.' },
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
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Use Case / AI and Agent Control</div>
        <h1 className="ep-hero-text" style={styles.h1}>Trust-control layer between AI intent and execution</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          AI agents are moving from recommendations to actions. Tool calls execute payments, modify data, and trigger workflows with broad permissions and no action-level control. EMILIA is the trust substrate that enforces accountability before high-risk agent actions proceed.
        </p>
        <div className="ep-hero-text" style={{ border: `1px solid ${color.border}`, borderLeft: `3px solid ${color.blue}`, borderRadius: 4, padding: '14px 20px', maxWidth: 560, marginBottom: 24 }}>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>
            <span style={{ color: color.t1, fontWeight: 700 }}>AI is one wedge.</span> The broader category is high-risk action enforcement. EMILIA is not an AI company. It is control infrastructure for any workflow where a high-risk action executes without action-level trust. AI agents are one vertical where this gap is acute and growing.
          </div>
        </div>
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
              // Stat removed: prior "82% Gartner" claim could not be sourced
              // to a specific Gartner report ID and date. Restore once cited.
              { value: 'Most',  label: 'Major agent platforms ship without action-level trust enforcement', accent: color.blue },
              { value: '0',     label: 'Agent frameworks with native action-level trust enforcement', accent: color.t3 },
              { value: '∞',     label: 'Blast radius of an agent with broad tool access and no controls', accent: '#DC2626' },
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
            Agent frameworks handle connection and tool discovery. What they do not handle is action-level trust enforcement. An agent with tool access can execute any action that tool permits. There is no structured control layer between the agent deciding to act and the action executing.
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>PROBLEM {String(i + 1).padStart(2, '0')}</div>
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
              EMILIA is not an agent framework. It is infrastructure. It operates as the control layer between agent intent and action execution, enforcing trust, accountability, and policy compliance at the action level across any agent system.
            </p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {HOW_EP_HELPS.map((h, i) => (
              <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
                <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{h.title}</div>
                <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{h.body}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How enforcement works */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 40 }}>
          <h2 style={styles.h2}>How EMILIA enforces trust in agent workflows</h2>
          <p style={styles.body}>Three protocol capabilities make EMILIA the control layer for agent-driven actions.</p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {ENFORCEMENT.map((a, i) => (
            <div key={i} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
              <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>CAPABILITY {String(i + 1).padStart(2, '0')}</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: color.t1, marginBottom: 8 }}>{a.title}</div>
              <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{a.body}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Infrastructure, not a tool */}
      <section style={styles.sectionAlt}>
        <div style={styles.section}>
          <div className="ep-reveal" style={{ marginBottom: 32 }}>
            <h2 style={styles.h2}>Infrastructure, not an agent tool</h2>
            <p style={styles.body}>
              EMILIA is designed as trust substrate for high-risk action enforcement. AI agent control is one application of this substrate, not its boundary. The same protocol primitives that enforce trust before agent actions also enforce trust before government disbursements, financial wire transfers, and enterprise privileged operations.
            </p>
          </div>
          {[
            'Action-level trust enforcement that works across agent frameworks, not inside one',
            'Protocol-grade primitives: handshake, signoff, receipt, dispute, appeal',
            'Risk classification that separates read-only operations from high-risk actions requiring human oversight',
            'Structured evidence production for regulatory compliance (EU AI Act, SOX, IG audit)',
            'Principal-to-agent delegation chains that make human accountability traceable',
          ].map((item, i) => (
            <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
              <span className="ep-list-bullet">+</span>
              <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Dark CTA */}
      <section style={{ borderTop: `4px solid ${color.gold}`, background: '#1C1917', padding: '80px 0', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)' }} />
        <div style={{ ...styles.section, position: 'relative', zIndex: 1 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 24 }}>AI / Agent Governance</div>
          <h2 style={{ fontFamily: font.sans, fontSize: 32, fontWeight: 700, color: '#FAFAF9', marginBottom: 16, lineHeight: 1.2, maxWidth: 560 }}>
            Trust before high-risk action in AI and agent workflows
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', maxWidth: 520, lineHeight: 1.7, marginBottom: 32 }}>
            EMILIA is selectively working with agent framework teams, AI infrastructure providers, and enterprise AI teams to pilot action-level trust enforcement for agent-driven workflows.
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
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.blue}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
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
