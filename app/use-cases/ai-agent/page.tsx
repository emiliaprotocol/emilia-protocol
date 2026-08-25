'use client';

import { useState, useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

export default function AIAgentUseCasePage(): React.ReactElement {
  const [form, setForm] = useState({ name:'', org:'', title:'', email:'', surface:'', problem:'', notes:'' });
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const update = (k: string, v: string): void => setForm(f => ({ ...f, [k]: v }));

  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  async function handleSubmit(e: React.SyntheticEvent): Promise<void> {
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
    } catch (err: any) { setError(err.message); }
    setSubmitting(false);
  }

  const PROBLEMS = [
    { title: 'Agents moving from recommendation to action', body: 'Agents can now call tools, mutate data, and trigger workflows. A broad tool grant does not answer whether this exact consequential call is within the customer\'s current mandate.' },
    { title: 'Connection permission is wider than action authority', body: 'A framework may authorize access to a payment tool while leaving amount, destination, purpose, and one-time use to application code. That is the action boundary Gate is designed to protect.' },
    { title: 'Attribution can stop at the session', body: 'Many workflows can name the service or credential that connected without preserving the accepted authority, exact action, and outcome evidence for one consequential call.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Buyer-defined action classes', body: 'The buyer selects which tool calls are covered and which evidence each class needs. Read-only traffic can remain outside the protected boundary; consequential calls can require stronger authority.' },
    { title: 'Fresh approval only when policy requires it', body: 'A finite mandate can let agents work unattended. When current authority is missing, stale, exhausted, or wider than the request, Gate refuses or returns to the configured authority source.' },
    { title: 'Action-bound attribution evidence', body: 'Each protected action can preserve the presenting agent credential, accepted delegation evidence, exact action, policy, admission, and outcome as distinct records.' },
    { title: 'Control mapping, not automatic compliance', body: 'EMILIA evidence can support an organization\'s EU AI Act, NIST AI RMF, or internal-control assessment. The organization and its authorized reviewer decide whether the complete system meets a requirement.' },
  ];

  const ENFORCEMENT = [
    { title: 'Delegated authority evidence', body: 'EMILIA can verify a pinned agent credential and delegation chain under the relying party\'s rules, then bind that evidence to one exact action. A machine credential is not proof of a human\'s civil identity, and human approval is required only when local policy says so.' },
    { title: 'Exact tool-use binding', body: 'An agent with access to a payment API can call any endpoint. EMILIA binds authorization to the exact tool call parameters: the specific API endpoint, the specific payload, the specific amount and destination. An approval to call transferFunds with $500 to Account A cannot be replayed for $5,000 to Account B.' },
    { title: 'Customer-owned admission policy', body: 'The buyer defines the protected action classes, accepted issuers, evidence requirements, limits, and exception path. On a completely mediated covered path, no accepted exact-action authority and required evidence means no provider entry.' },
  ];

  const GATE_PATTERN = `const d = await guardAction({ action: 'payment.release', context });
if (d.deny)            throw new Error(d.reason);   // blocked outright
if (d.signoffRequired) await waitForApprover(d);    // enrolled credential signs
// ...otherwise proceed under the configured mandate and record the decision.`;

  const SNIPPETS = [
    { k: 'MCP server', sub: 'Claude Desktop, Cursor, Cline', code: '{ "command": "npx",\n  "args": ["-y", "@emilia-protocol/mcp-server"] }' },
    { k: 'LangChain.js', sub: 'wrap any irreversible tool', code: "import { withGuard } from '@emilia-protocol/langchain';\nconst safe = withGuard(tool, { action: 'payment.release' });" },
    { k: 'CrewAI / AutoGen', sub: 'Python — guard() decorator', code: '@guard("payment.release", context_fn=..., fetch=post)\ndef wire_transfer(amount, destination): ...' },
  ];

  const codeBox: React.CSSProperties = {
    fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.7, color: '#D6D3D1',
    background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base,
    padding: '16px 18px', margin: 0, overflowX: 'auto', whiteSpace: 'pre',
  };

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
        <div className="ep-tag ep-hero-badge" style={{ color: color.blue }}>Use Case / AI and Agent Control</div>
        <h1 className="ep-hero-text" style={styles.h1}>Trust-control layer between AI intent and execution</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 620 }}>
          Agents can move money, modify data, and operate infrastructure through tools that were granted at connection time. EMILIA Gate adds a customer-owned decision at the exact-action boundary. On a completely mediated covered path, the action reaches the provider only with accepted authority and required evidence.
        </p>
        <div className="ep-hero-text" style={{ border: `1px solid ${color.border}`, borderLeft: `3px solid ${color.blue}`, borderRadius: 4, padding: '14px 20px', maxWidth: 560, marginBottom: 24 }}>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>
            <span style={{ color: color.t1, fontWeight: 700 }}>AI is one wedge.</span> The broader category is exact-action authority control. EMILIA is infrastructure for buyer-selected workflows where a consequential action needs a decision at the executor boundary.
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
              { value: 'Intent', label: 'The agent proposes one typed tool call', accent: color.blue },
              { value: 'Gate', label: 'The customer policy admits or refuses provider entry', accent: color.blue },
              { value: 'Receipt', label: 'Authorization, admission, and outcome remain distinct', accent: color.t3 },
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
            Agent frameworks handle connection and tool discovery. A connection grant alone does not establish authority for every possible parameter set. Gate sits at a selected executor boundary and checks one exact call against the customer&apos;s current mandate and evidence policy.
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
              EMILIA is not an agent framework. It is an authority-control layer that can be integrated at a selected tool or system-of-record boundary. Protocol proves. Gate prevents on the completely mediated paths the customer configures.
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
            'Open adapters and reference integrations for multiple agent frameworks',
            'Protocol primitives for exact-action challenges, approval evidence, receipts, and remedies',
            'Buyer-authored action classes that separate uncovered read-only traffic from protected consequential operations',
            'Structured evidence and published mappings that can support regulatory and internal-control review',
            'Pinned agent and delegation evidence that makes accepted authority traceable without treating a credential as civil identity',
          ].map((item, i) => (
            <div key={i} className={`ep-list-item ep-reveal ep-stagger-${i + 1}`}>
              <span className="ep-list-bullet">+</span>
              <span style={{ fontSize: 15, color: color.t2, lineHeight: 1.65 }}>{item}</span>
            </div>
          ))}
        </div>
      </section>

      {/* What it looks like in code */}
      <section style={styles.section}>
        <div className="ep-reveal" style={{ marginBottom: 28 }}>
          <h2 style={styles.h2}>What it looks like in code</h2>
          <p style={styles.body}>
            At a configured tool boundary, Gate evaluates one exact action. A current finite mandate can authorize unattended work; fresh approver evidence is an exception path when the buyer&apos;s policy requires it.
          </p>
        </div>
        <div className="ep-reveal" style={{ marginBottom: 16 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, color: color.blue, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 8 }}>The gate — same everywhere</div>
          <pre style={codeBox as React.CSSProperties}>{GATE_PATTERN}</pre>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12, marginBottom: 28 }}>
          {SNIPPETS.map((s, i) => (
            <div key={s.k} className={`ep-reveal ep-stagger-${i + 1}`} style={cardStyle(color.blue)}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 15, color: color.t1 }}>{s.k}</div>
                <div style={{ fontSize: 12.5, color: color.t3 }}>{s.sub}</div>
              </div>
              <pre style={{ ...codeBox, fontSize: 11.5 } as React.CSSProperties}>{s.code}</pre>
            </div>
          ))}
        </div>
        <div className="ep-reveal" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Full quickstart →</a>
          <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples" target="_blank" rel="noopener noreferrer" className="ep-cta-secondary" style={cta.secondary}>Framework examples →</a>
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
            The protected-workflow pilot is available to agent framework teams, AI infrastructure providers, and enterprise AI teams that can name one consequential tool or executor boundary.
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
          <div style={{ border: `1px solid ${color.border}`, borderTop: `2px solid ${color.blue}`, borderRadius: radius.base, padding: 40, textAlign: 'center' }}>
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
