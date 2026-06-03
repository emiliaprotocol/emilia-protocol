import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Agent Guard — One Line Between Your AI Agent and Disaster',
  description:
    'Agent Guard stops an AI agent before any irreversible action — moving money, '
    + 'deleting data, sending email — until a named human signs off. Framework-agnostic.',
  alternates: { canonical: '/agent-guard' },
  openGraph: {
    title: 'EMILIA Agent Guard — the kill switch and accountability layer for AI agents',
    description:
      'Wrap any high-risk agent action in one call. Blocked until a named human signs off. '
      + 'Every decision produces a cryptographically verifiable Trust Receipt.',
    url: 'https://www.emiliaprotocol.ai/agent-guard',
    type: 'website',
  },
  keywords: [
    'AI agent guardrails',
    'AI agent authorization',
    'human in the loop AI agents',
    'agent action approval',
    'LangChain authorization',
    'MCP authorization',
    'agent payment guardrail',
    'autonomous agent safety',
  ],
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

// Real, copy-pasteable: a live decision call against the policy gate. The gate
// returns one of allow / allow_with_signoff / deny — the same engine the demo runs on.
const HTTP_SNIPPET = `# Ask EMILIA whether this exact action may proceed — before it runs.
curl -s https://www.emiliaprotocol.ai/api/trust/gate \\
  -H 'content-type: application/json' \\
  -d '{
    "actor":   "agent_invoice_bot",
    "action":  "payment.release",
    "context": { "amount": 50000, "destination": "acct_9f12" }
  }'

# → { "decision": "allow_with_signoff",
#     "reason": "ai_agent_payment_action",
#     "signoff_required": true }`;

// The ergonomic SDK wrapper — the "Stripe moment" one-liner.
const GUARD_SNIPPET = `import { guard } from '@emilia-protocol/sdk';

// Wrap anything irreversible. One line.
const decision = await guard({
  actor:   agent.id,
  action:  'payment.release',
  context: { amount: 50_000, destination: invoice.account },
});

if (decision.deny) throw new Error('Blocked by policy');
if (decision.signoffRequired) {
  await decision.waitForHuman();   // blocks until a named human approves
}

// Proceeds only with a signed, verifiable Trust Receipt:
await bank.wire(invoice);          // decision.receipt is your audit evidence`;

const FLOW = [
  {
    step: '01', accent: color.green, label: 'Intercept',
    body: 'Your agent is about to do something it can’t take back. One guard() call routes the exact action — actor, intent, parameters — to EMILIA before it touches the real world.',
  },
  {
    step: '02', accent: color.blue, label: 'Decide',
    body: 'The formally verified policy engine returns one of three answers: allow (safe, proceed), allow-with-signoff (a named human must approve this exact action), or deny (a hard rule says no). No ambiguity, no silent pass.',
  },
  {
    step: '03', accent: color.gold, label: 'Prove',
    body: 'Every decision emits a signed, Merkle-anchored Trust Receipt — who approved what, when, bound to the action hash. Auditor-grade evidence, verifiable offline with @emilia-protocol/verify. No EMILIA server required to check it.',
  },
];

const FRAMEWORKS = [
  { name: 'LangChain', note: 'Wrap any tool before .invoke()' },
  { name: 'CrewAI', note: 'Gate a crew’s high-risk tasks' },
  { name: 'AutoGPT', note: 'Guard the action execution step' },
  { name: 'LlamaIndex', note: 'Approve tool-calling agents' },
  { name: 'Vercel AI SDK', note: 'Guard inside tool() handlers' },
  { name: 'Model Context Protocol', note: 'Native MCP server · 34 tools' },
];

const SCENARIOS = [
  { tag: 'TREASURY', title: 'Agent tries to wire $50K', body: 'An invoice-paying agent attempts a payment to a new account. Blocked. A named human signs off. Wire proceeds with a receipt.', enforced: true },
  { tag: 'INFRA', title: 'Agent tries to drop prod', body: 'A coding agent runs a destructive migration on the production database. The action is gated before it executes.', enforced: false },
  { tag: 'BENEFITS', title: 'Agent redirects a benefit', body: 'An agent changes the bank account on a benefits case. Blocked pending an accountable caseworker signoff — due process, proven.', enforced: true },
  { tag: 'DATA', title: 'Agent exfiltrates PII', body: 'An agent attempts to export a table of personal records to an external destination. The high-risk write is intercepted.', enforced: false },
];

const codeBox = {
  fontFamily: font.mono,
  fontSize: 12.5,
  lineHeight: 1.7,
  color: '#D6D3D1',
  background: '#1C1917',
  border: `1px solid ${color.border}`,
  borderRadius: radius.base,
  padding: '22px 24px',
  margin: 0,
  overflowX: 'auto',
  whiteSpace: 'pre',
};

export default function AgentGuardPage() {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="Agent Guard" />

      {/* HERO */}
      <section style={{ paddingTop: 120, paddingBottom: 80, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 28 }}>
            EMILIA Agent Guard
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(40px, 5.5vw, 72px)', letterSpacing: -2.5, lineHeight: 0.98, color: color.t1, margin: '0 0 28px', maxWidth: 900 }}>
            One line of code between your agent and a{' '}
            <em style={{ fontStyle: 'normal', color: color.gold }}>catastrophe.</em>
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: '0 0 40px' }}>
            Your AI agent can move money, delete production data, send email, sign contracts. Agent
            Guard stops every irreversible action at the pre-execution moment and requires a signed
            human yes &mdash; or a policy that proves it&rsquo;s safe. Vendor-neutral. Works with any framework.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/demo" className="ep-cta" style={cta.primary}>Watch an agent get stopped &rarr;</Link>
            <Link href="/signup" className="ep-cta-secondary" style={cta.secondary}>Start free &mdash; get a key</Link>
          </div>
        </C>
      </section>

      {/* THE ONE-LINER */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '0.85fr 1.15fr', gap: 56, alignItems: 'center' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                The integration
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 38px)', letterSpacing: -1, lineHeight: 1.12, color: color.t1, marginBottom: 20 }}>
                Wrap the dangerous action. Ship the same day.
              </h2>
              <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, marginBottom: 18 }}>
                No proxy to deploy. No data path to reroute. You call the gate at the decision point;
                EMILIA answers <strong style={{ color: color.t1 }}>allow</strong>, <strong style={{ color: color.t1 }}>require&nbsp;signoff</strong>, or <strong style={{ color: color.t1 }}>deny</strong> &mdash; decided by a
                policy engine with 26 machine-checked safety theorems behind it.
              </p>
              <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, margin: 0 }}>
                The HTTP call below is live. The SDK wrapper is the ergonomic version of the same thing.
                Exact signatures in the <Link href="/docs" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>docs</Link>.
              </p>
            </div>
            <div style={{ display: 'grid', gap: 16 }}>
              <pre style={codeBox}>{HTTP_SNIPPET}</pre>
              <pre style={codeBox}>{GUARD_SNIPPET}</pre>
            </div>
          </div>
        </C>
      </section>

      {/* FLOW */}
      <section style={{ padding: '88px 0', background: 'rgba(245,244,240,0.45)', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            What happens on every call
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 36px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 560, marginBottom: 48 }}>
            Intercept, decide, prove.
          </h2>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {FLOW.map((item) => (
              <div key={item.step} style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: 56, alignItems: 'start', padding: '40px 0', borderBottom: `1px solid ${color.border}` }}>
                <div>
                  <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: item.accent, marginBottom: 10 }}>{item.step}</div>
                  <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 600, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t1 }}>{item.label}</div>
                </div>
                <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.72, maxWidth: 620, margin: 0 }}>{item.body}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* FRAMEWORKS */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
            Drop into any stack
          </div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 36px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 600, marginBottom: 16 }}>
            If your agent calls tools, EMILIA can guard them.
          </h2>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, maxWidth: 620, marginBottom: 40 }}>
            Agent Guard is framework-agnostic middleware, not a lock-in. It sits at the action
            boundary, wherever that is in your loop &mdash; and it doesn&rsquo;t care whose model your agent runs on.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {FRAMEWORKS.map((f) => (
              <div key={f.name} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
                <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, color: color.t1, marginBottom: 6 }}>{f.name}</div>
                <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 0.2 }}>{f.note}</div>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* SCENARIOS */}
      <section style={{ padding: '88px 0', background: 'rgba(245,244,240,0.45)', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 24, marginBottom: 40, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                The agent that tried to
              </div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 36px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 520, margin: 0 }}>
                Four things you never want an agent to do unsupervised.
              </h2>
            </div>
            <Link href="/demo" className="ep-cta" style={{ ...cta.primary, flexShrink: 0 }}>Run it live &rarr;</Link>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {SCENARIOS.map((s) => (
              <div key={s.title} style={{ background: color.card, border: `1px solid ${color.border}`, borderLeft: `3px solid ${s.enforced ? color.green : color.gold}`, borderRadius: radius.base, padding: '24px 26px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                  <span style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t3 }}>{s.tag}</span>
                  <span style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1, textTransform: 'uppercase', color: s.enforced ? color.green : color.t3, border: `1px solid ${color.border}`, borderRadius: 2, padding: '2px 7px' }}>
                    {s.enforced ? 'Policy-enforced' : 'Illustrative'}
                  </span>
                </div>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, color: color.t1, marginBottom: 8 }}>{s.title}</h3>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>{s.body}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* CTA */}
      <section style={{ position: 'relative', overflow: 'hidden', padding: '96px 0', background: '#1C1917', borderTop: `3px solid ${color.gold}` }}>
        <div aria-hidden style={{ position: 'absolute', inset: 0, pointerEvents: 'none', backgroundImage: 'radial-gradient(circle, rgba(176,141,53,0.06) 1px, transparent 1px)', backgroundSize: '36px 36px' }} />
        <C>
          <div style={{ maxWidth: 640, position: 'relative' }}>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(30px, 4vw, 52px)', letterSpacing: -2, lineHeight: 1.0, color: '#FAFAF9', marginBottom: 24 }}>
              Don&rsquo;t ship an agent without a kill switch.
            </h2>
            <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.7)', lineHeight: 1.7, marginBottom: 36, maxWidth: 520 }}>
              EP Core is free and open source. Self-host the protocol, the SDK, and the MCP server today.
              Add the hosted control plane when you need policy management and audit at scale.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/pricing" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917' }}>See pricing</Link>
              <Link href="/docs" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#FAFAF9' }}>Read the docs</Link>
              <Link href="/protocol" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.8)', borderColor: 'rgba(255,255,255,0.15)' }}>How it works</Link>
            </div>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
