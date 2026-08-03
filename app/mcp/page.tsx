import type { Metadata } from 'next';
import { headers } from 'next/headers';
import Link from 'next/link';
import Image from 'next/image';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'EMILIA MCP — Protect Agent Tools and Verify Receipts',
  description:
    'Protect an existing MCP dispatcher with mcp-guard, or add EMILIA receipt and passkey verification tools to an MCP client with mcp-server.',
  alternates: { canonical: '/mcp' },
  openGraph: {
    title: 'EMILIA MCP — protect agent tools and verify receipts',
    description: 'Two distinct MCP paths: guard an existing executor, or add EMILIA verification tools to a client.',
    url: 'https://www.emiliaprotocol.ai/mcp',
    type: 'website',
  },
  keywords: ['MCP server', 'Model Context Protocol', 'AI agent authorization', 'human in the loop MCP', 'trust receipt', 'agent accountability'],
};

// Page-level structured data. The MCP server as its own SoftwareApplication
// (distinct from the site-wide EP SoftwareApplication in layout.js), plus a
// FAQPage backed by the visible FAQ section below — both win AI-search
// citations for "MCP human in the loop / agent authorization" queries.
const MCP_SOFTWARE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: '@emilia-protocol/mcp-server',
  alternateName: 'EMILIA MCP Server',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'Cross-platform (Node.js 18+)',
  description:
    'MCP server that gives clients tools to verify EMILIA authorization receipts and passkey signoffs. '
    + 'Protecting an existing MCP dispatcher is the separate @emilia-protocol/mcp-guard path.',
  url: 'https://www.emiliaprotocol.ai/mcp',
  downloadUrl: 'https://www.npmjs.com/package/@emilia-protocol/mcp-server',
  installUrl: 'https://www.npmjs.com/package/@emilia-protocol/mcp-server',
  softwareVersion: '1.0.0',
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
  author: { '@type': 'Organization', name: 'EMILIA Protocol' },
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD', availability: 'https://schema.org/InStock' },
  featureList: [
    'Human-signoff workflow tools',
    'Offline-verifiable authorization receipts (Ed25519)',
    'Passkey/WebAuthn signoff verification',
    'Receipt verification',
    'Model Context Protocol (MCP) stdio server',
  ],
};

const FAQ = [
  {
    q: 'What does the EMILIA MCP server do?',
    a: 'It adds EMILIA verification tools to an MCP client: verify authorization receipts and passkey signoffs. To protect an existing tool dispatcher, use the separate @emilia-protocol/mcp-guard package at the real executor boundary. Rich trust-profile and policy-evaluation APIs require an authenticated EP API key.',
  },
  {
    q: 'How do I install it?',
    a: 'Add it to any MCP client (Claude Desktop, Cursor, Cline, Continue) in one line: command "npx" with args ["-y", "@emilia-protocol/mcp-server"]. Public verification tools need no key; set EP_API_KEY for rich trust APIs or write operations.',
  },
  {
    q: 'How is this different from permissions or OAuth?',
    a: 'Permissions gate access locally and leave no portable proof. EMILIA mints a signed, offline-verifiable authorization receipt bound to the exact action and the named human who approved it — a credential a counterparty can verify without calling home.',
  },
  {
    q: 'Is it open source?',
    a: 'Yes — Apache-2.0, and the policy engine is formally verified (26 TLA+ theorems in CI).',
  },
];

const MCP_FAQ_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map((f) => ({
    '@type': 'Question',
    name: f.q,
    acceptedAnswer: { '@type': 'Answer', text: f.a },
  })),
};

/** @param {{ children: React.ReactNode, style?: React.CSSProperties }} props */
const C = ({ children, style = {} }: { children: React.ReactNode; style?: React.CSSProperties }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);

const INSTALL = `// Claude Desktop / any MCP client — add to your config:
{
  "mcpServers": {
    "emilia": {
      "command": "npx",
      "args": ["-y", "@emilia-protocol/mcp-server"]
    }
  }
}`;

const TOOLS = [
  { name: 'ep_verify_receipt', what: 'Verify any EMILIA authorization receipt offline — signature + Merkle anchor.' },
  { name: 'ep_verify_signoff', what: 'Verify WebAuthn/passkey signoff assertions bound to the exact action.' },
];

const FLOW = [
  ['Agent attempts an irreversible action', 'release a payment, change a record, deploy'],
  ['EMILIA holds it', '428 Receipt Required / signoff_required - the agent cannot proceed alone'],
  ['A named human approves', 'the signed "yes", bound to the exact action'],
  ['Action proceeds + a receipt is minted', 'offline-verifiable proof, forever'],
];

const DIRS = ['Official MCP Registry', 'Glama', 'Smithery', 'mcp.so', 'PulseMCP', 'awesome-mcp-servers'];

export default async function McpPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <script
        type="application/ld+json"
        nonce={nonce}
        dangerouslySetInnerHTML={{ __html: JSON.stringify(MCP_SOFTWARE_JSONLD) }}
      />
      <script
        type="application/ld+json"
        nonce={nonce}
        dangerouslySetInnerHTML={{ __html: JSON.stringify(MCP_FAQ_JSONLD) }}
      />
      <SiteNav activePage="MCP" />

      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
            Model Context Protocol
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 860 }}>
            Two MCP paths. One <em style={{ fontStyle: 'normal', color: color.gold }}>consequence boundary.</em>
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: '0 0 36px' }}>
            Protect an existing tool dispatcher with <code style={{ fontFamily: font.mono, fontSize: 15 }}>@emilia-protocol/mcp-guard</code>,
            or add receipt and passkey verification tools to a client with <code style={{ fontFamily: font.mono, fontSize: 15 }}>@emilia-protocol/mcp-server</code>.
            The guard covers only the executor paths it fully mediates.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/guides/require-receipt" className="ep-cta" style={cta.primary}>Protect an MCP tool &rarr;</Link>
            <Link href="/scan" className="ep-cta-secondary" style={cta.secondary}>Scan your surface first</Link>
          </div>
          <Image
            src="/mcp-demo.gif"
            alt="EMILIA MCP demo: an AI agent is blocked from releasing $50,000 until a named human signs off, then the payment proceeds with a verifiable receipt."
            width={1589}
            height={1148}
            unoptimized
            style={{ width: '100%', maxWidth: 800, height: 'auto', marginTop: 48, borderRadius: radius.base, border: `1px solid ${color.border}`, boxShadow: '0 10px 50px rgba(12,10,9,0.10)', display: 'block' }}
          />
        </C>
      </section>

      <section style={{ padding: '20px 0 64px', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(320px, 100%), 1fr))', gap: 12 }}>
            <div style={{ border: `1px solid ${color.border}`, borderTop: `3px solid ${color.gold}`, borderRadius: radius.base, background: color.card, padding: '26px 28px' }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.7, textTransform: 'uppercase', color: color.gold, marginBottom: 12 }}>Executor path</div>
              <h2 style={{ fontSize: 23, letterSpacing: -0.5, margin: '0 0 10px' }}>Protect an existing MCP tool</h2>
              <code style={{ fontFamily: font.mono, fontSize: 13, color: color.t1 }}>@emilia-protocol/mcp-guard</code>
              <p style={{ fontSize: 14, lineHeight: 1.68, color: color.t2, margin: '14px 0 0' }}>Wrap the credential-owning dispatcher. Missing or invalid action-bound evidence is refused before the handler runs. Production requires durable provenance and shared atomic consumption state.</p>
            </div>
            <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.card, padding: '26px 28px' }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.7, textTransform: 'uppercase', color: color.green, marginBottom: 12 }}>Client tools</div>
              <h2 style={{ fontSize: 23, letterSpacing: -0.5, margin: '0 0 10px' }}>Add EMILIA verification tools to an MCP client</h2>
              <code style={{ fontFamily: font.mono, fontSize: 13, color: color.t1 }}>@emilia-protocol/mcp-server</code>
              <p style={{ fontSize: 14, lineHeight: 1.68, color: color.t2, margin: '14px 0 0' }}>Expose receipt and passkey verification tools to Claude Desktop, Cursor, Cline, Continue, or another MCP client. Installing this server alone does not mediate another tool&rsquo;s executor path.</p>
            </div>
          </div>
        </C>
      </section>

      {/* RR-1 ENFORCED — the credential, at a glance */}
      <section style={{ padding: '56px 0', borderTop: `1px solid ${color.border}` }}>
        <C>
          <div style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, background: color.card, padding: '28px 32px', maxWidth: 720 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: font.mono, fontWeight: 700, fontSize: 12.5, letterSpacing: 1, textTransform: 'uppercase', color: '#fff', background: color.green, padding: '6px 12px', borderRadius: 6 }}>✓ RR-1 Enforced</span>
              <span style={{ fontFamily: font.sans, fontSize: 15, color: color.t2 }}>Receipt Required conformance &mdash; verified in CI, not asserted.</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px 28px', margin: '22px 0 0' }}>
              {[
                ['Missing receipt', '428 Receipt Required'],
                ['Valid receipt', 'action runs'],
                ['Same receipt', 'replay refused'],
                ['Forged receipt', 'refused'],
              ].map(([a, b]) => (
                <div key={a} style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t2 }}>
                  <span style={{ color: color.green, fontWeight: 700 }}>✓</span> {a} <span style={{ color: color.t3 }}>&rarr;</span> <span style={{ color: color.t1 }}>{b}</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', margin: '24px 0 0', fontFamily: font.mono, fontSize: 12 }}>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/RECEIPT-REQUIRED-CONFORMANCE.md" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>Conformance spec &rarr;</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/guides/RECEIPT-REQUIRED-MCP.md" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>10-minute guide &rarr;</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/tests/receipt-required-conformance.test.js" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>CI test &rarr;</a>
            </div>
            <p style={{ fontSize: 12.5, color: color.t3, margin: '18px 0 0', fontFamily: font.mono }}>
              Run the RR-1 gallery locally: <span style={{ color: color.t1 }}>FAST=1 node examples/mcp/payment-server.mjs</span>
            </p>
          </div>
        </C>
      </section>

      {/* NO RECEIPT, NO IRREVERSIBLE ACTION — cold-run examples */}
      <section style={{ padding: '64px 0', background: '#1C1917', color: '#FAFAF9' }}>
        <C>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(22px, 2.6vw, 32px)', letterSpacing: -0.8, lineHeight: 1.2, color: '#FAFAF9', margin: 0, maxWidth: 760 }}>
            No receipt, no irreversible action.
          </h2>
          <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.72)', lineHeight: 1.7, margin: '16px 0 28px', maxWidth: 640 }}>
            Three tiny MCP servers, each with one dangerous tool that refuses to run without a receipt.
            Run any of them cold &mdash; fully offline, no key, no account. Each reads the public
            Action Risk Manifest and shows the whole loop: 428 refused &rarr; a named human signs
            the exact action &rarr; the tool runs &rarr; replay refused &rarr; forged receipt rejected.
          </p>
          <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.9, color: '#D6D3D1', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: radius.base, padding: '20px 22px', margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{`node examples/mcp/payment-server.mjs    # release_payment   — refuses without a receipt
node examples/mcp/github-admin.mjs      # delete_repo       — refuses without a receipt
node examples/mcp/prod-deploy.mjs       # deploy_production — refuses without a receipt
node examples/mcp/supabase-admin.mjs    # run_destructive_sql — refuses without a receipt
node examples/mcp/linear-export.mjs     # export_customer_data — refuses without a receipt`}</pre>
          <p style={{ fontSize: 13, color: 'rgba(250,250,249,0.5)', margin: '16px 0 0' }}>
            Wrap your own dispatcher with <code style={{ fontFamily: font.mono }}>withMcpGuard</code> or a manifest-driven 428 gate &mdash; missing receipt &rarr; refused, never a silent pass.
          </p>
        </C>
      </section>

      {/* INSTALL */}
      <section style={{ padding: '72px 0', background: 'rgba(245,244,240,0.45)', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.2fr', gap: 48, alignItems: 'center' }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 12 }}>Install</div>
              <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.6vw, 32px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, marginBottom: 12 }}>
                One line in any MCP client.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, margin: 0 }}>
                Works in Claude Desktop, Cursor, Cline, Continue, or your own loop. Public read tools
                need no key; set <code style={{ fontFamily: font.mono, fontSize: 13 }}>EP_API_KEY</code> for write operations.
              </p>
            </div>
            <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.7, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '22px 24px', margin: 0, overflowX: 'auto', whiteSpace: 'pre' }}>{INSTALL}</pre>
          </div>
        </C>
      </section>

      {/* FLAGSHIP FLOW */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>The flagship: human sign-off</div>
          <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(24px, 2.8vw, 36px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 560, marginBottom: 40 }}>
            Most MCP servers connect data. This one makes an agent <em style={{ fontStyle: 'normal', color: color.gold }}>accountable.</em>
          </h2>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {FLOW.map(([title, sub], i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '48px 1fr', gap: 24, alignItems: 'start', padding: '24px 0', borderBottom: `1px solid ${color.border}` }}>
                <div style={{ fontFamily: font.mono, fontSize: 20, fontWeight: 700, color: 'rgba(12,10,9,0.15)' }}>{`0${i + 1}`}</div>
                <div>
                  <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, color: color.t1 }}>{title}</div>
                  <div style={{ fontSize: 14, color: color.t3, marginTop: 4 }}>{sub}</div>
                </div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 14, color: color.t3, marginTop: 16 }}>
            Reference server + client harness in the repo (<code style={{ fontFamily: font.mono, fontSize: 12 }}>mcp-server/passport-demo.mjs</code>);
            demand side via <code style={{ fontFamily: font.mono, fontSize: 12 }}>@emilia-protocol/require-receipt</code> and{' '}
            <code style={{ fontFamily: font.mono, fontSize: 12 }}>@emilia-protocol/mcp-guard</code> &mdash;{' '}
            <Link href="/guides/require-receipt" style={{ color: color.gold }}>add Receipt Required to an MCP server &rarr;</Link>
          </p>
        </C>
      </section>

      {/* TOOLS */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>What you get today</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {TOOLS.map((t) => (
              <div key={t.name} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '20px 22px' }}>
                <code style={{ fontFamily: font.mono, fontSize: 13, color: color.t1, fontWeight: 600 }}>{t.name}</code>
                <p style={{ fontSize: 13.5, color: color.t2, lineHeight: 1.6, margin: '8px 0 0' }}>{t.what}</p>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 14 }}>Public connector tools are verification-only. Rich trust profiles, disputes, delegation, identity continuity, and write APIs require an authenticated EP API key.</p>
        </C>
      </section>

      {/* WORKS WITH YOUR STACK */}
      <section style={{ padding: '80px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>Works with your stack</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
            {[
              ['MCP client', 'npx -y @emilia-protocol/mcp-server'],
              ['LangChain.js', 'withGuard() · @emilia-protocol/langchain'],
              ['CrewAI / AutoGen', 'guard() decorator · examples/'],
              ['Any Node service', '@emilia-protocol/require-receipt -> 428'],
              ['MCP tool guard', '@emilia-protocol/mcp-guard → signoff + receipt'],
              ['Verify in JS', '@emilia-protocol/verify'],
              ['Verify in Python', 'pip install emilia-verify'],
            ].map(([k, v]) => (
              <div key={k} style={{ background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '16px 18px' }}>
                <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, color: color.t1, marginBottom: 4 }}>{k}</div>
                <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.t2 }}>{v}</code>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 13, color: color.t3, marginTop: 14 }}>
            Authorization receipts verify offline in JavaScript <em style={{ fontStyle: 'normal' }}>and</em> Python &mdash; minted anywhere, checked anywhere. See the <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/docs/QUICKSTART.md" target="_blank" rel="noopener noreferrer" style={{ color: color.gold }}>5-minute quickstart</a>.
          </p>
        </C>
      </section>

      {/* DIRECTORIES */}
      <section style={{ padding: '72px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>Find us</div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 28 }}>
            {DIRS.map((d) => (
              <span key={d} style={{ fontFamily: font.mono, fontSize: 12, color: color.t2, border: `1px solid ${color.border}`, borderRadius: 20, padding: '6px 14px' }}>{d}</span>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/mcp-server" target="_blank" rel="noopener noreferrer" className="ep-cta" style={cta.primary}>Source &rarr;</a>
            <Link href="/agent-guard" className="ep-cta-secondary" style={cta.secondary}>Agent Guard</Link>
          </div>
        </C>
      </section>

      {/* FAQ — backs the FAQPage JSON-LD above */}
      <section style={{ padding: '80px 0' }}>
        <C style={{ maxWidth: 820 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>FAQ</div>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {FAQ.map((f) => (
              <div key={f.q} style={{ padding: '22px 0', borderBottom: `1px solid ${color.border}` }}>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 17, color: color.t1, margin: '0 0 8px' }}>{f.q}</h3>
                <p style={{ fontSize: 14.5, color: color.t2, lineHeight: 1.7, margin: 0 }}>{f.a}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      <section style={{ padding: '64px 0', borderTop: `1px solid ${color.border}` }}>
        <C style={{ maxWidth: 820 }}>
          <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>FURTHER READING</div>
          <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, margin: 0 }}>
            <Link href="/blog/mcp-authorization-best-practices" style={{ color: color.t1, textDecoration: 'underline' }}>MCP Authorization Best Practices in 2026</Link>
            {' '}&mdash; why scope-level OAuth stops short for tools that move money or trigger irreversible state, and what the next authorization layer adds.
          </p>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
