import type { Metadata } from 'next';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata: Metadata = {
  title: 'Free AI Agent Authority Scanner — EMILIA',
  description:
    'Run a passive local inventory of configured agent runtimes, MCP servers, credential-shaped configuration, ambient credential files, and permission rules.',
  alternates: { canonical: '/scan' },
  openGraph: {
    title: 'See what your agents can reach',
    description:
      'A passive local authority inventory. Scanner code performs no network I/O or configured-server launch. No security guarantee.',
    url: 'https://www.emiliaprotocol.ai/scan',
    type: 'website',
  },
  keywords: [
    'AI agent security scanner',
    'MCP security scanner',
    'AI agent credential audit',
    'Claude Code permissions audit',
    'MCP server inventory',
    'AI agent authority inventory',
  ],
};

const shell: React.CSSProperties = {
  maxWidth: 1120,
  margin: '0 auto',
  padding: '0 32px',
};

const codeBox: React.CSSProperties = {
  fontFamily: font.mono,
  fontSize: 14,
  lineHeight: 1.7,
  color: '#ECFEFF',
  background: '#17212A',
  border: '1px solid #30414E',
  borderRadius: radius.base,
  padding: '24px 26px',
  overflowX: 'auto',
  whiteSpace: 'pre',
};

const FACTS = [
  {
    n: '01',
    title: 'Configured reach',
    body: 'Inventories supported agent configuration, declared MCP servers, credential-shaped fields, ambient credential files, and permission rules.',
  },
  {
    n: '02',
    title: 'Private local pass',
    body: 'Parses bounded files in memory. After startup, scanner code launches no configured server or child process and performs no network I/O. Report files are created owner-only.',
  },
  {
    n: '03',
    title: 'Blind spots included',
    body: 'Names unsupported formats, malformed sources, invisible runtime tools, and operation surfaces it could not classify instead of declaring them safe.',
  },
];

const EXIT_CODES = [
  ['1', 'Signals found', 'Review the reachable authority and configuration conditions named in the report.'],
  ['2', 'Malformed input', 'At least one supported configuration source could not be trusted as parsed.'],
  ['3', 'Surface not visible', 'The config-only scan could not see or classify the operation surface. This is not a clean bill of health.'],
];

export default function AuthorityScanPage(): React.ReactElement {
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <SiteNav activePage="" />

      <main>
        <section style={{ padding: '116px 0 88px', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.4, textTransform: 'uppercase', color: color.gold, marginBottom: 24 }}>
              Free alpha · passive local diagnostic
            </div>
            <h1 style={{ fontFamily: font.sans, fontSize: 'clamp(44px, 7vw, 84px)', lineHeight: 0.96, letterSpacing: -3.2, margin: '0 0 28px', maxWidth: 900 }}>
              See what your agents can reach.
            </h1>
            <p style={{ fontSize: 19, lineHeight: 1.7, color: color.t2, maxWidth: 720, margin: '0 0 40px' }}>
              Before you add another guardrail, inventory the authority already sitting beside your agents.
              EMILIA Scan reports configured reach and its own blind spots. The scanner does not launch
              a configured server, test a credential, or call home. npm may download the package before
              the scan starts.
            </p>
            <pre style={{ ...codeBox, maxWidth: 760 }}>npx @emilia-protocol/scan authority</pre>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 24 }}>
              <a
                href="https://www.npmjs.com/package/@emilia-protocol/scan"
                target="_blank"
                rel="noopener noreferrer"
                style={cta.primary}
              >
                Run the local scan
              </a>
              <a
                href="https://github.com/emiliaprotocol/emilia-protocol/tree/main/packages/scan"
                target="_blank"
                rel="noopener noreferrer"
                style={cta.secondary}
              >
                Read every line
              </a>
            </div>
          </div>
        </section>

        <section style={{ padding: '84px 0', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(260px, 100%), 1fr))', gap: 12 }}>
              {FACTS.map((fact) => (
                <div key={fact.n} style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, padding: 28, background: '#FAFAF9' }}>
                  <div style={{ fontFamily: font.mono, color: color.gold, fontSize: 11, letterSpacing: 1.8, marginBottom: 30 }}>{fact.n}</div>
                  <h2 style={{ fontSize: 22, letterSpacing: -0.5, margin: '0 0 12px' }}>{fact.title}</h2>
                  <p style={{ fontSize: 15, lineHeight: 1.72, color: color.t2, margin: 0 }}>{fact.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section style={{ padding: '84px 0', borderBottom: `1px solid ${color.border}` }}>
          <div style={shell}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(340px, 100%), 1fr))', gap: 72, alignItems: 'start' }}>
              <div>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                  Honest by default
                </div>
                <h2 style={{ fontSize: 'clamp(30px, 4vw, 48px)', lineHeight: 1.05, letterSpacing: -1.6, margin: 0 }}>
                  No reassuring green check from an incomplete scan.
                </h2>
              </div>
              <div>
                {EXIT_CODES.map(([code, title, body]) => (
                  <div key={code} style={{ display: 'grid', gridTemplateColumns: '52px 1fr', gap: 18, padding: '22px 0', borderTop: `1px solid ${color.border}` }}>
                    <span style={{ fontFamily: font.mono, fontSize: 20, color: color.gold }}>{code}</span>
                    <div>
                      <div style={{ fontWeight: 700, marginBottom: 6 }}>{title}</div>
                      <div style={{ fontSize: 15, lineHeight: 1.7, color: color.t2 }}>{body}</div>
                    </div>
                  </div>
                ))}
                <p style={{ fontSize: 13, lineHeight: 1.7, color: color.t3, marginTop: 22 }}>
                  Exit code 0 is intentionally unavailable in configuration-only mode because the scanner
                  does not launch servers and therefore cannot establish complete operation coverage.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section style={{ padding: '84px 0 104px' }}>
          <div style={shell}>
            <div style={{ maxWidth: 760 }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Inventory first. Classify second. Enforce separately.
              </div>
              <h2 style={{ fontSize: 'clamp(30px, 4vw, 48px)', lineHeight: 1.08, letterSpacing: -1.6, margin: '0 0 22px' }}>
                The scanner tells you where to look. It does not claim the action is authorized.
              </h2>
              <p style={{ fontSize: 16, lineHeight: 1.75, color: color.t2, margin: '0 0 28px' }}>
                Give the same package an MCP tool list or OpenAPI document to propose which visible
                operations may need action-bound evidence. Review that proposal yourself. Nothing is
                enforced until a guard completely mediates the real executor path under your pinned policy and keys.
              </p>
              <pre style={codeBox}>{`npx @emilia-protocol/scan ./tools.json\nnpx @emilia-protocol/scan ./openapi.json`}</pre>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(190px, 100%), 1fr))', gap: 12, marginTop: 24 }}>
                {[
                  ['01', 'Scan locally'],
                  ['02', 'Choose one consequential tool'],
                  ['03', 'Mediate its real executor path'],
                ].map(([step, label]) => (
                  <div key={step} style={{ border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px', background: '#FAFAF9' }}>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, marginBottom: 8 }}>{step}</div>
                    <div style={{ fontWeight: 700, fontSize: 14 }}>{label}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
                <Link href="/agent-guard" style={cta.primary}>Protect a flagged MCP tool</Link>
                <Link href="/mcp" style={cta.secondary}>See the MCP integration</Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <SiteFooter />
    </div>
  );
}
