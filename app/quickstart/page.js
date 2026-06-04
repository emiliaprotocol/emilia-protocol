import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Quickstart — Put a Human in the Loop in 5 Minutes',
  description:
    'Add EMILIA to your agent in minutes: MCP, LangChain, CrewAI/AutoGen, or any Node service. '
    + 'Gate irreversible actions behind a named human sign-off; verify receipts offline in JS or Python.',
  alternates: { canonical: '/quickstart' },
  openGraph: {
    title: 'EMILIA Quickstart — human sign-off for agent actions in 5 minutes',
    description: 'Pick your stack, gate an irreversible action, mint a verifiable receipt.',
    url: 'https://www.emiliaprotocol.ai/quickstart',
    type: 'article',
  },
  keywords: ['EMILIA quickstart', 'MCP human in the loop', 'LangChain guard', 'CrewAI AutoGen', 'agent authorization', 'trust receipt'],
};

const HOWTO_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'HowTo',
  name: 'Add EMILIA human sign-off to an AI agent',
  description: 'Gate an irreversible agent action behind a named human approval and mint an offline-verifiable receipt.',
  totalTime: 'PT5M',
  step: [
    { '@type': 'HowToStep', name: 'Install', text: 'Add EMILIA to your stack — MCP server (npx), LangChain (npm), CrewAI/AutoGen (the guard decorator), or require-receipt for any Node service.' },
    { '@type': 'HowToStep', name: 'Gate the action', text: 'Route each irreversible action through the trust gate: allow → run, deny → throw, signoff_required → wait for a named human, then run.' },
    { '@type': 'HowToStep', name: 'Verify', text: 'Every approval mints a Trust Receipt you can verify offline with @emilia-protocol/verify (JS) or emilia-verify (Python).' },
  ],
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 880, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);
const Pre = ({ children }) => (
  <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.65, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px', margin: '10px 0 0', overflowX: 'auto', whiteSpace: 'pre' }}>{children}</pre>
);
const H2 = ({ children }) => (
  <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(20px, 2.4vw, 28px)', letterSpacing: -0.6, color: color.t1, margin: '56px 0 8px' }}>{children}</h2>
);

const PATHS = [
  { k: 'MCP client', sub: 'Claude Desktop, Cursor, Cline, Continue', code: '{ "command": "npx", "args": ["-y", "@emilia-protocol/mcp-server"] }' },
  { k: 'LangChain.js', sub: 'wrap any irreversible tool', code: "import { withGuard } from '@emilia-protocol/langchain';\nconst safe = withGuard(tool, { action: 'payment.release' });" },
  { k: 'CrewAI / AutoGen', sub: 'Python — the guard() decorator', code: '@guard("payment.release", context_fn=..., fetch=post)\ndef wire_transfer(amount, destination): ...' },
  { k: 'Any Node service', sub: 'demand side — answer 402', code: "import { requireEmiliaReceipt } from '@emilia-protocol/require-receipt';\napp.post('/release', requireEmiliaReceipt({ action: 'payment.release' }), handler);" },
];

const PATTERN = `const d = await guardAction({ action: 'payment.release', context });
if (d.deny)            throw new Error(d.reason);   // blocked outright
if (d.signoffRequired) await waitForHuman(d);       // a NAMED human approves
// ...otherwise proceed. Every approval mints a Trust Receipt.`;

export default async function QuickstartPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <script type="application/ld+json" nonce={nonce} dangerouslySetInnerHTML={{ __html: JSON.stringify(HOWTO_JSONLD) }} />
      <SiteNav activePage="" />

      <section style={{ paddingTop: 120, paddingBottom: 8 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 20 }}>Quickstart</div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(34px, 4.6vw, 52px)', letterSpacing: -2, lineHeight: 1.05, color: color.t1, margin: '0 0 20px', maxWidth: 720 }}>
            Put a human in the loop in 5 minutes.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 640, lineHeight: 1.7, margin: 0 }}>
            Pick your stack, gate one irreversible action, and mint a receipt anyone can verify offline.
            No account needed to start; public read tools need no key.
          </p>
        </C>
      </section>

      <section style={{ padding: '24px 0 8px' }}>
        <C>
          <H2>1. Pick your path</H2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 14, marginTop: 18 }}>
            {PATHS.map((p) => (
              <div key={p.k} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '20px 22px' }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
                  <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 16, color: color.t1 }}>{p.k}</div>
                  <div style={{ fontSize: 13, color: color.t3 }}>{p.sub}</div>
                </div>
                <Pre>{p.code}</Pre>
              </div>
            ))}
          </div>
        </C>
      </section>

      <section style={{ padding: '8px 0' }}>
        <C>
          <H2>2. The pattern (same everywhere)</H2>
          <p style={{ fontSize: 15.5, color: color.t2, lineHeight: 1.7, margin: '6px 0 0' }}>
            Whatever the framework, the gate does one job: hold an irreversible action until it&rsquo;s allowed,
            denied, or signed off by a named human.
          </p>
          <Pre>{PATTERN}</Pre>
        </C>
      </section>

      <section style={{ padding: '8px 0 80px' }}>
        <C>
          <H2>3. Verify the receipt — offline, any language</H2>
          <p style={{ fontSize: 15.5, color: color.t2, lineHeight: 1.7, margin: '6px 0 18px' }}>
            A receipt minted anywhere checks anywhere, with no account and no network.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 28 }}>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px' }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: color.t1 }}>JavaScript</div>
              <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.gold }}>npm i @emilia-protocol/verify</code>
            </div>
            <div style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px' }}>
              <div style={{ fontWeight: 600, fontSize: 14, color: color.t1 }}>Python</div>
              <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.gold }}>pip install emilia-verify</code>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/mcp" className="ep-cta" style={cta.primary}>MCP server &rarr;</Link>
            <Link href="/spec/trust-receipt" className="ep-cta-secondary" style={cta.secondary}>Receipt format spec</Link>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/examples" target="_blank" rel="noopener noreferrer" className="ep-cta-secondary" style={cta.secondary}>Framework examples</a>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
