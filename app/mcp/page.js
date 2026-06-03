import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'EMILIA MCP — Trust & Human Sign-off for AI Agents',
  description:
    'The Model Context Protocol server that gives AI agents a trust layer: verify Trust Receipts, '
    + 'check entity trust profiles, and — the flagship — require a named human sign-off before an '
    + 'agent takes an irreversible action. Install in one line; formally verified; Apache-2.0.',
  alternates: { canonical: '/mcp' },
  openGraph: {
    title: 'EMILIA MCP — human sign-off for AI agent actions',
    description: 'An MCP server that makes your agent get a signed human "yes" before it does anything irreversible.',
    url: 'https://www.emiliaprotocol.ai/mcp',
    type: 'website',
  },
  keywords: ['MCP server', 'Model Context Protocol', 'AI agent authorization', 'human in the loop MCP', 'trust receipt', 'agent accountability'],
};

const C = ({ children, style }) => (
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
  { name: 'ep_verify_receipt', what: 'Verify any EMILIA Trust Receipt offline — signature + Merkle anchor.' },
  { name: 'ep_trust_profile', what: 'Pull an entity’s full trust profile before transacting with it.' },
  { name: 'ep_trust_evaluate', what: 'Evaluate a counterparty/agent’s trust for a specific action.' },
  { name: 'ep_submit_receipt', what: 'Record a signed receipt of an action your agent took.' },
];

const FLOW = [
  ['Agent attempts an irreversible action', 'release a payment, change a record, deploy'],
  ['EMILIA holds it', '402 / signoff_required — the agent cannot proceed alone'],
  ['A named human approves', 'the signed "yes", bound to the exact action'],
  ['Action proceeds + a receipt is minted', 'offline-verifiable proof, forever'],
];

const DIRS = ['Official MCP Registry', 'Glama', 'Smithery', 'mcp.so', 'PulseMCP', 'awesome-mcp-servers'];

export default function McpPage() {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      <section style={{ paddingTop: 120, paddingBottom: 56 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
            Model Context Protocol
          </div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(38px, 5vw, 64px)', letterSpacing: -2.2, lineHeight: 1.0, color: color.t1, margin: '0 0 24px', maxWidth: 860 }}>
            A human signed <em style={{ fontStyle: 'normal', color: color.gold }}>yes</em> before your agent acts.
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 620, lineHeight: 1.7, margin: '0 0 36px' }}>
            EMILIA is the trust &amp; accountability layer for AI agents, delivered as an MCP server.
            Verify receipts, check trust profiles, and &mdash; the flagship &mdash; require a named human
            sign-off before an agent does anything irreversible. Formally verified. Apache-2.0.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/demo" className="ep-cta" style={cta.primary}>Watch an agent get stopped &rarr;</Link>
            <Link href="/agent-guard" className="ep-cta-secondary" style={cta.secondary}>How it works</Link>
          </div>
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
            demand side via <code style={{ fontFamily: font.mono, fontSize: 12 }}>@emilia-protocol/require-receipt</code>.
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
          <p style={{ fontSize: 13, color: color.t3, marginTop: 14 }}>34 tools total &mdash; trust profiles, receipts, disputes, delegation, identity continuity, and more. Full list in the <a href="https://www.npmjs.com/package/@emilia-protocol/mcp-server" target="_blank" rel="noopener noreferrer" style={{ color: color.gold }}>npm package</a>.</p>
        </C>
      </section>

      {/* DIRECTORIES */}
      <section style={{ padding: '72px 0' }}>
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

      <SiteFooter />
    </div>
  );
}
