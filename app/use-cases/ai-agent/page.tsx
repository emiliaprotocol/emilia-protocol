'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function AIAgentUseCasePage(): React.ReactElement {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  const PROBLEMS = [
    { title: 'Agents moving from recommendation to action', body: 'Tool calls, API requests, and workflow steps can cross from recommendation into consequential action while relying on broad connection-level permissions.' },
    { title: 'Broad tool access without exact-action checks', body: 'Some integrations authorize a tool or session without independently checking the exact payment, data change, or external request at provider entry.' },
    { title: 'Attribution split across systems', body: 'Principal, agent, policy, exact-action, provider, and outcome evidence may live in different logs that do not preserve one independently checkable join.' },
  ];

  const HOW_EP_HELPS = [
    { title: 'Buyer-pinned action classes', body: 'The relying party selects which tool calls remain read-only and which consequential actions require additional authority or evidence before provider entry.' },
    { title: 'Conditional human signoff', body: 'When the pinned policy requires a fresh human decision, the enrolled credential signs the exact action parameters rather than a blanket tool permission.' },
    { title: 'Separated evidence rows', body: 'A protected path can preserve principal, agent, policy, exact-action, admission, provider, and outcome evidence without treating any one row as universal authorization.' },
    { title: 'Review support, not compliance', body: 'Scoped evidence can support a buyer-authorized governance or control-testing procedure. EMILIA does not establish legal compliance or issue an audit opinion.' },
  ];

  const ENFORCEMENT = [
    { title: 'Delegated principal attribution', body: 'A relying-party-pinned profile can verify delegated scope separately from any human decision and bind both to the same exact action. A human ceremony is required only when local policy says so.' },
    { title: 'Exact tool-use binding', body: 'An agent with access to a payment API can call any endpoint. EMILIA binds authorization to the exact tool call parameters: the specific API endpoint, the specific payload, the specific amount and destination. An approval to call transferFunds with $500 to Account A cannot be replayed for $5,000 to Account B.' },
    { title: 'Policy-selected evidence thresholds', body: 'The relying party selects which evidence applies to each protected action. Missing or mismatched required evidence refuses provider entry only on a completely mediated covered path.' },
  ];

  const GATE_PATTERN = `const d = await guardAction({ action: 'payment.release', context });
if (d.deny)            throw new Error(d.reason);   // refuse before provider entry
if (d.signoffRequired) await waitForHuman(d);       // only when pinned policy requires it
// Invoke the provider only behind the configured, completely mediated Gate.`;

  const SNIPPETS = [
    { k: 'MCP server', sub: 'wrap the existing dispatcher', code: "import { withMcpGuard } from '@emilia-protocol/mcp-guard';\nconst guarded = withMcpGuard(handleTool, pinnedConfig);" },
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
          AI agents can move from recommendations to consequential tool calls. EMILIA is a candidate
          control layer for exact-action authority and evidence checks when the buyer can place Gate
          at a completely mediated executor boundary.
        </p>
        <div className="ep-hero-text" style={{ border: `1px solid ${color.border}`, borderLeft: `3px solid ${color.blue}`, borderRadius: 4, padding: '14px 20px', maxWidth: 560, marginBottom: 24 }}>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>
            <span style={{ color: color.t1, fontWeight: 700 }}>AI is one wedge.</span> The broader category is high-risk action enforcement. EMILIA is not an AI company. It is control infrastructure for any workflow where a high-risk action executes without action-level trust. AI agents are one vertical where this gap is acute and growing.
          </div>
        </div>
        <div className="ep-hero-text">
          <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
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
              { value: 'Exact', label: 'Bind the material tool call, not only the session', accent: color.blue },
              { value: 'Pinned', label: 'Keep trust roots, policy, and evidence requirements buyer-controlled', accent: color.blue },
              { value: 'Closed', label: 'Require complete mediation before making a prevention claim', accent: color.t3 },
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
            Agent frameworks handle connection and tool discovery. A deployment may still need a
            separate boundary that evaluates the exact consequential tool call immediately before
            its provider or system-of-record entry.
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
              EMILIA is not an agent framework. It can serve as a separate control layer between
              agent intent and a configured executor. Its prevention guarantee applies only to
              completely mediated covered paths and does not establish policy or legal compliance.
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
              EMILIA is designed as an authority and evidence substrate for consequential action.
              AI agent control is one solution profile. Government, healthcare, physical, and
              enterprise examples are additional profiles, not simultaneous opening markets or
              claims of deployed adoption.
            </p>
          </div>
          {[
            'Action-level trust enforcement that works across agent frameworks, not inside one',
            'Protocol-grade primitives: handshake, signoff, receipt, dispute, appeal',
            'Risk classification that separates read-only operations from high-risk actions requiring human oversight',
            'Scoped evidence that can support buyer-authorized governance and control-testing procedures',
            'Principal-to-agent delegation chains that make human accountability traceable',
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
            The pattern checks one buyer-selected consequential action before provider entry. A fresh
            human decision is included only when the pinned policy requires it. Read-only behavior
            and all alternate execution paths remain deployment-specific.
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
            The one public offer is {PROTECTED_WORKFLOW_PILOT.shortPriceLabel} for {PROTECTED_WORKFLOW_PILOT.durationLabel} to assess one
            buyer-selected consequence boundary. Finance operations remains the initial offered
            profile; agent-tool workflows are an eligible solution profile for fit review. Validation is synthetic, read-only, sandbox, or
            shadow only, with no production provider credentials or actuation. Production requires a separate
            Gate Implementation after the buyer accepts the boundary.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/pilot" className="ep-cta" style={cta.primary}>Scope the protected-workflow pilot</a>
          </div>
        </div>
      </section>

      </main>

      <SiteFooter />
    </div>
  );
}
