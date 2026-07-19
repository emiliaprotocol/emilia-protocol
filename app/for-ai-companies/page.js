import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'For AI Companies — Accountability for Agent Actions',
  description:
    'OAuth solved login. EMILIA solves accountability for AI agents. How OpenAI, Anthropic, Google, '
    + 'and xAI can prove who approved every irreversible agent action — Accountable Signoff, authorization receipt, Policy Hash, Authority Chain.',
  alternates: { canonical: '/for-ai-companies' },
  openGraph: {
    title: 'OAuth solved login. EMILIA solves accountability for AI agents.',
    description: 'A cryptographic answer to the question every lab hits: who approved this exact action?',
    url: 'https://www.emiliaprotocol.ai/for-ai-companies',
    type: 'website',
  },
  keywords: ['AI agent accountability', 'OpenAI agents', 'Anthropic computer use', 'agent authorization', 'who approved this action', 'accountable signoff'],
};

const PAGE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'WebPage',
  name: 'EMILIA for AI Companies',
  description: 'Accountability infrastructure for AI agent actions — a cryptographic answer to "who approved this exact action?"',
  url: 'https://www.emiliaprotocol.ai/for-ai-companies',
};

/** @param {{ children: any, style?: React.CSSProperties }} props */
const C = ({ children, style }) => (
  <div style={{ maxWidth: 920, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

const LABS = ['OpenAI Operators', 'Anthropic Computer Use', 'Google Agents', 'Microsoft Copilot Actions', 'xAI', 'Visa Agent Commerce'];

const CONCEPTS = [
  ['Accountable Signoff', 'A named human cryptographically assumes responsibility for the exact action — not a role, not a token, a person. This is the answer to "who owns this decision?"'],
  ['Authorization receipt', 'A signed, offline-verifiable record of the decision (formerly Trust Receipt): action, policy, approver, outcome. Anyone verifies it with no account and no call home (Ed25519 + Merkle).'],
  ['Policy Hash', 'The exact policy version that authorized the action, pinned into the receipt. The rules that applied are provable after the fact, not reconstructed.'],
  ['Authority Chain', 'The delegation path — who was allowed to authorize whom — bound to the action. Permission isn’t assumed; it’s carried and checked.'],
];

export default async function ForAiCompaniesPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <script type="application/ld+json" nonce={nonce} dangerouslySetInnerHTML={{ __html: JSON.stringify(PAGE_JSONLD) }} />
      <SiteNav activePage="" />

      <section style={{ paddingTop: 120, paddingBottom: 8 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>For AI labs &amp; platforms</div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(36px, 5vw, 60px)', letterSpacing: -2.4, lineHeight: 1.02, color: color.t1, margin: '0 0 24px', maxWidth: 820 }}>
            OAuth solved login. EMILIA solves <em style={{ fontStyle: 'normal', color: color.gold }}>accountability</em> for AI agents.
          </h1>
          <p style={{ fontSize: 19, color: color.t2, maxWidth: 660, lineHeight: 1.65, margin: 0 }}>
            Your model can reason. It can plan. It can execute. The moment it acts in the real world,
            every team hits the same wall — and it&rsquo;s not a capability problem:
          </p>
          <p style={{ fontSize: 'clamp(22px, 3vw, 30px)', fontWeight: 700, color: color.t1, letterSpacing: -0.8, margin: '28px 0 0', maxWidth: 660 }}>
            &ldquo;Who approved this <em style={{ fontStyle: 'normal', color: color.gold }}>exact</em> action?&rdquo;
          </p>
        </C>
      </section>

      {/* PROBLEM */}
      <section style={{ padding: '64px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>The shared wall</div>
          <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.7, maxWidth: 680, margin: '0 0 24px' }}>
            Every agent platform eventually has to answer for what its agent did — to a board, a regulator,
            an insurer, a court. &ldquo;The model did it&rdquo; is not an answer. And when prompt injection turns a
            helpful assistant into a financial weapon, the headline names <em>you</em>, not the user.
          </p>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {LABS.map((l) => (
              <span key={l} style={{ fontFamily: font.mono, fontSize: 12, color: color.t2, border: `1px solid ${color.border}`, borderRadius: 20, padding: '6px 14px' }}>{l}</span>
            ))}
          </div>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 14 }}>All shipping autonomous action. All hitting the same wall.</p>
        </C>
      </section>

      {/* FOUR CONCEPTS */}
      <section style={{ padding: '72px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>The answer — four concepts</div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 620, marginBottom: 36 }}>
            A cryptographically provable record of who owns each decision.
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
            {CONCEPTS.map(([k, v]) => (
              <div key={k} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
                <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 17, color: color.t1, marginBottom: 8 }}>{k}</div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>{v}</p>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 16 }}>Four concepts. Nothing else. Formally verified (26 TLA+ theorems), Apache-2.0, no vendor lock-in.</p>
        </C>
      </section>

      {/* TRY IT */}
      <section style={{ padding: '72px 0' }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>Try it in your model today</div>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, maxWidth: 640, margin: '0 0 18px' }}>
            EMILIA ships as an MCP server, so any MCP-capable client — Claude, GPT, Gemini, Cursor, Windsurf —
            can experiment with accountable actions in one line. No partnership meeting required.
          </p>
          <pre style={{ fontFamily: font.mono, fontSize: 13, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '16px 20px', margin: '0 0 18px', overflowX: 'auto' }}>npx -y @emilia-protocol/mcp-server</pre>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, maxWidth: 640, margin: '0 0 14px' }}>
            Or guard an existing OpenAI-compatible agent &mdash; OpenAI, xAI Grok, Together &mdash; so every irreversible tool call routes through EMILIA before it runs:
          </p>
          <pre style={{ fontFamily: font.mono, fontSize: 13, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '16px 20px', margin: '0 0 14px', overflowX: 'auto' }}>npm install @emilia-protocol/openai-guard</pre>
          <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 640, margin: '0 0 14px' }}>
            For production: a <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/async-signoff.mjs" style={{ color: color.gold, textDecoration: 'none' }}>high-volume async signoff example</a> (the gate is selective &mdash; the agent loop never blocks on a human), and an <a href="https://github.com/xai-org/xai-cookbook/pull/42" style={{ color: color.gold, textDecoration: 'none' }}>open recipe PR</a> on xAI&rsquo;s cookbook.
          </p>
          <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 640, margin: '0 0 28px' }}>
            For Grok specifically, the <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/grok_guard.py" style={{ color: color.gold, textDecoration: 'none' }}>hardened Python guard</a> does the offline cryptographic check itself &mdash; it verifies the device signature in-process against a <strong>pinned</strong> signer key, bound to the exact requested action and single-use, so a server merely saying &ldquo;approved&rdquo; is never enough. It ships with a <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/examples/tests/test_grok_guard_redteam.py" style={{ color: color.gold, textDecoration: 'none' }}>red-team regression suite</a> that re-runs six attack vectors on every change.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/mcp" className="ep-cta" style={cta.primary}>The MCP server &rarr;</Link>
            <Link href="/demo" className="ep-cta-secondary" style={cta.secondary}>Watch an agent get stopped</Link>
            <a href="mailto:team@emiliaprotocol.ai" className="ep-cta-secondary" style={cta.secondary}>Talk to us</a>
          </div>
        </C>
      </section>

      {/* BENCHMARK — real, reproducible */}
      <section style={{ padding: '72px 0', borderTop: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>Real-world proof &mdash; reproducible</div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 34px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 640, marginBottom: 16 }}>
            Autonomous treasury agent, crash-tested.
          </h2>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.7, maxWidth: 660, margin: '0 0 28px' }}>
            The open benchmark harness points an autonomous treasury-agent prompt at high-stakes requests
            (large wires, a &ldquo;CFO says skip approval&rdquo; injection, payout-bank changes) and safe controls,
            then scores what would execute with and without EMILIA. The model behavior varies by run; the
            EMILIA result is deterministic because the policy gate refuses receiptless high-risk actions.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 14, marginBottom: 22 }}>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginBottom: 12 }}>Harness shape</div>
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 34, color: color.t1, letterSpacing: -1, lineHeight: 1.1 }}>12 cases</div>
              <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.6, margin: '14px 0 0' }}>Six high-stakes treasury requests and six safe controls, scored from raw model output.</p>
            </div>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginBottom: 12 }}>Deterministic gate</div>
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 34, color: color.t1, letterSpacing: -1, lineHeight: 1.1 }}>Receiptless high-risk = refused</div>
              <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.6, margin: '14px 0 0' }}>The verified engine gates every &ge;$50k release and bank-destination change unless a valid, action-bound receipt is present.</p>
            </div>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px' }}>
              <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, marginBottom: 12 }}>Auditable output</div>
              <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 34, color: color.t1, letterSpacing: -1, lineHeight: 1.1 }}>Run it yourself</div>
              <p style={{ fontSize: 13, color: color.t3, lineHeight: 1.6, margin: '14px 0 0' }}>Publish model-specific percentages only from a saved harness run; the repo gives reviewers the scorer and cases.</p>
            </div>
          </div>
          <p style={{ fontSize: 14, color: color.t3, lineHeight: 1.7, maxWidth: 660, margin: 0 }}>
            Don&rsquo;t take our word for it &mdash; the harness is open. Reproduce it, or point it at your own model:
          </p>
          <pre style={{ fontFamily: font.mono, fontSize: 13, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '16px 20px', margin: '12px 0 0', overflowX: 'auto' }}>BENCH_API_KEY=sk-... node bench/run.mjs</pre>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
