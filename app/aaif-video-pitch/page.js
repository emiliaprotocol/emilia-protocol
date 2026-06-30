// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';
import { color, cta, font, radius } from '@/lib/tokens';
import registryIndex from '../../packages/fire-drill/registry-index.json';
import reports from '../../packages/fire-drill/reports.json';

export const metadata = {
  title: 'AAIF Video Pitch Recording Kit - EMILIA Protocol',
  description:
    'A recording cockpit for the AAIF technical committee pitch: the gap, the live Receipt Required attack sequence, proof points, ecosystem signal, and the non-binding ask.',
  alternates: { canonical: '/aaif-video-pitch' },
  robots: { index: false, follow: false },
};

const repoUrl = 'https://github.com/emiliaprotocol/emilia-protocol';
const draftUrl = 'https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/';

const shots = [
  ['0:00-0:25', 'Hook', 'AI agents are starting to take irreversible actions.'],
  ['0:25-0:55', 'The gap', 'MCP connects. goose executes. AGENTS.md guides. EMILIA proves the human yes.'],
  ['0:55-2:35', 'Live attack', 'No receipt blocked. Exact receipt runs once. Replay blocked. Forgery rejected.'],
  ['2:35-3:25', 'Real and small', 'Active individual I-D, Apache-2.0, JS/Python/Go verifiers, offline checks.'],
  ['3:25-4:05', 'Ecosystem proof', 'Registry scan plus RR-1 maintainer credential.'],
  ['4:05-4:30', 'Ask', 'Early non-binding read on fit and where this belongs.'],
];

const layerRows = [
  ['MCP', 'connects agents to tools'],
  ['goose', 'executes the agent workflow'],
  ['AGENTS.md', 'guides local behavior'],
  ['EMILIA', 'proves a named human authorized the exact irreversible action'],
];

const rrChecks = [
  ['Missing receipt', '428 blocked'],
  ['Valid receipt', 'runs once'],
  ['Same receipt', 'replay refused'],
  ['Forged receipt', 'signature rejected'],
];

const links = [
  ['/try/receipt-required', 'Live attack demo'],
  ['/fire-drill/registry', 'MCP registry index'],
  ['/fire-drill/rr-1', 'RR-1 badge'],
  [repoUrl, 'GitHub repo'],
];

export default function AaifVideoPitchPage() {
  const publishedReports = reports.reports.filter((r) => r.published).length;

  return (
    <main style={s.page}>
      <style>{`
        #ep-eu-ai-act-banner { display: none !important; }
        nextjs-portal { display: none !important; }
        @media (max-width: 900px) {
          .aaif-deck-grid,
          .aaif-runbook { grid-template-columns: 1fr !important; }
          .aaif-stats { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 640px) {
          .aaif-hero { padding: 52px 20px 24px !important; }
          .aaif-layer-row,
          .aaif-shot { grid-template-columns: 1fr !important; }
          .aaif-check-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
      <header style={s.topbar}>
        <Link href="/" style={s.brand}>EMILIA</Link>
        <div style={s.topMeta}>AAIF recording kit / target runtime 4:30</div>
        <nav style={s.topLinks}>
          {links.map(([href, label]) => (
            <a key={href} href={href} style={s.topLink} target={href.startsWith('http') ? '_blank' : undefined} rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}>
              {label}
            </a>
          ))}
        </nav>
      </header>

      <section style={s.hero} className="aaif-hero">
        <div style={s.heroText}>
          <div style={s.eyebrow}>TITLE CARD / 0:00</div>
          <h1 style={s.h1}>AI agents are starting to take irreversible actions.</h1>
          <p style={s.lead}>
            Moving money. Deleting repositories. Changing payout accounts. The open question is what proves a named human authorized the exact action before it ran.
          </p>
        </div>
        <div style={s.lowerThird}>
          <span style={s.pill}>draft-schrock-ep-authorization-receipts</span>
          <span style={s.pill}>Apache-2.0</span>
          <span style={s.pill}>JS / Python / Go verifiers</span>
          <span style={s.pill}>offline-verifiable</span>
        </div>
      </section>

      <section style={s.deckGrid} className="aaif-deck-grid">
        <article style={s.panel}>
          <div style={s.eyebrow}>THE GAP / 0:25</div>
          <h2 style={s.h2}>The stack guides and connects agents. It does not create portable authorization evidence.</h2>
          <div style={s.layerStack}>
            {layerRows.map(([name, job], index) => (
              <div key={name} className="aaif-layer-row" style={{ ...s.layerRow, ...(index === layerRows.length - 1 ? s.layerEmilia : null) }}>
                <strong>{name}</strong>
                <span>{job}</span>
              </div>
            ))}
          </div>
          <p style={s.statement}>Decision logs are testimony. Receipts are evidence.</p>
        </article>

        <article style={s.panel}>
          <div style={s.eyebrow}>LIVE DEMO / 0:55</div>
          <h2 style={s.h2}>Try to break the action layer.</h2>
          <p style={s.body}>Record the live page, then let the six states breathe. This is the moment that should land.</p>
          <div style={s.checkGrid} className="aaif-check-grid">
            {rrChecks.map(([label, result]) => (
              <div key={label} style={s.check}>
                <span>{label}</span>
                <strong>{result}</strong>
              </div>
            ))}
          </div>
          <Link href="/try/receipt-required" style={s.primaryLink}>Open live demo</Link>
        </article>

        <article style={s.panel}>
          <div style={s.eyebrow}>REAL AND SMALL / 2:35</div>
          <h2 style={s.h2}>A primitive, not a platform pitch.</h2>
          <ul style={s.bullets}>
            <li>Active individual Internet-Draft, not an IETF endorsement.</li>
            <li>Reference verifiers in JavaScript, Python, and Go agree on shared conformance vectors.</li>
            <li>26 TLA+ safety properties and Alloy checks are machine-checked in CI.</li>
            <li>No account or backend for the local demo: <code>npx @emilia-protocol/issue demo</code>.</li>
          </ul>
          <a href={draftUrl} style={s.secondaryLink} target="_blank" rel="noopener noreferrer">Open datatracker draft</a>
        </article>

        <article style={s.panel}>
          <div style={s.eyebrow}>ECOSYSTEM PROOF / 3:25</div>
          <h2 style={s.h2}>The maintainer path is a badge, not a scold.</h2>
          <div style={s.stats} className="aaif-stats">
            <div style={s.stat}>
              <strong style={s.statNumber}>{registryIndex.servers_scanned.toLocaleString()}</strong>
              <span style={s.statLabel}>MCP servers scanned</span>
            </div>
            <div style={s.stat}>
              <strong style={s.statNumber}>{registryIndex.pct_advertise_high_risk}%</strong>
              <span style={s.statLabel}>advertise high-risk capability</span>
            </div>
            <div style={s.stat}>
              <strong style={s.statNumber}>{publishedReports}</strong>
              <span style={s.statLabel}>published fire-drill reports</span>
            </div>
          </div>
          <p style={s.body}>RR-1 says: your most dangerous action is safer than the ecosystem default.</p>
          <div style={s.rowLinks}>
            <Link href="/fire-drill/registry" style={s.secondaryLink}>Registry index</Link>
            <Link href="/fire-drill/rr-1" style={s.secondaryLink}>RR-1 page</Link>
          </div>
        </article>
      </section>

      <section style={s.closeCard}>
        <div style={s.eyebrow}>CLOSING CARD / 4:05</div>
        <h2 style={s.closeTitle}>If this is the missing human-authorization layer, where should it belong?</h2>
        <p style={s.closeBody}>Early, non-binding read on fit. Composes with MCP, goose, and AGENTS.md. Apache-2.0 reference implementation.</p>
        <div style={s.closeLinks}>
          <span>team@emiliaprotocol.ai</span>
          <a href={repoUrl} style={s.closeLink} target="_blank" rel="noopener noreferrer">github.com/emiliaprotocol/emilia-protocol</a>
        </div>
      </section>

      <section style={s.runbook} className="aaif-runbook">
        <div>
          <div style={s.eyebrow}>SHOT LIST</div>
          <h2 style={s.h2}>Keep the take calm and under five minutes.</h2>
        </div>
        <div style={s.shots}>
          {shots.map(([time, label, line]) => (
            <div key={time} className="aaif-shot" style={s.shot}>
              <span>{time}</span>
              <strong>{label}</strong>
              <p style={s.shotLine}>{line}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

const s = {
  page: {
    minHeight: '100vh',
    background: '#171412',
    color: '#FAFAF9',
    fontFamily: font.sans,
  },
  topbar: {
    minHeight: 68,
    display: 'flex',
    alignItems: 'center',
    gap: 18,
    padding: '0 28px',
    borderBottom: '1px solid rgba(250,250,249,0.14)',
    flexWrap: 'wrap',
  },
  brand: {
    color: '#FAFAF9',
    textDecoration: 'none',
    fontFamily: font.mono,
    fontWeight: 700,
    fontSize: 18,
    letterSpacing: 5,
  },
  topMeta: {
    fontFamily: font.mono,
    fontSize: 11,
    color: 'rgba(250,250,249,0.52)',
    marginRight: 'auto',
  },
  topLinks: {
    display: 'flex',
    gap: 8,
    flexWrap: 'wrap',
  },
  topLink: {
    color: '#FAFAF9',
    textDecoration: 'none',
    fontFamily: font.mono,
    fontSize: 11,
    border: '1px solid rgba(250,250,249,0.16)',
    borderRadius: radius.sm,
    padding: '8px 10px',
  },
  hero: {
    minHeight: 'calc(100vh - 68px)',
    display: 'grid',
    alignContent: 'space-between',
    padding: '76px 32px 32px',
    borderBottom: '1px solid rgba(250,250,249,0.14)',
  },
  heroText: {
    maxWidth: 1120,
    margin: '0 auto',
    width: '100%',
  },
  eyebrow: {
    fontFamily: font.mono,
    fontSize: 11,
    letterSpacing: 2.3,
    textTransform: 'uppercase',
    color: color.gold,
    marginBottom: 18,
  },
  h1: {
    margin: 0,
    maxWidth: 1020,
    fontSize: 'clamp(56px, 9vw, 132px)',
    lineHeight: 0.88,
    letterSpacing: 0,
  },
  lead: {
    maxWidth: 760,
    margin: '28px 0 0',
    color: 'rgba(250,250,249,0.72)',
    fontSize: 20,
    lineHeight: 1.6,
  },
  lowerThird: {
    maxWidth: 1120,
    width: '100%',
    margin: '0 auto',
    display: 'flex',
    gap: 8,
    flexWrap: 'wrap',
  },
  pill: {
    border: '1px solid rgba(250,250,249,0.16)',
    borderRadius: radius.sm,
    padding: '9px 11px',
    color: 'rgba(250,250,249,0.72)',
    fontFamily: font.mono,
    fontSize: 11,
  },
  deckGrid: {
    maxWidth: 1220,
    margin: '0 auto',
    padding: '44px 28px',
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: 16,
  },
  panel: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.base,
    background: '#211D1A',
    padding: 26,
    minHeight: 390,
  },
  h2: {
    margin: 0,
    fontSize: 'clamp(26px, 3vw, 40px)',
    lineHeight: 1.04,
    letterSpacing: 0,
  },
  body: {
    margin: '18px 0 0',
    color: 'rgba(250,250,249,0.68)',
    fontSize: 16,
    lineHeight: 1.65,
  },
  layerStack: {
    display: 'grid',
    gap: 10,
    marginTop: 26,
  },
  layerRow: {
    display: 'grid',
    gridTemplateColumns: '140px minmax(0, 1fr)',
    gap: 16,
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: '14px 16px',
    fontFamily: font.mono,
    color: 'rgba(250,250,249,0.72)',
  },
  layerEmilia: {
    borderColor: color.gold,
    background: 'rgba(176,141,53,0.16)',
    color: '#FAFAF9',
  },
  statement: {
    margin: '24px 0 0',
    fontFamily: font.mono,
    color: color.gold,
    fontSize: 14,
  },
  checkGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: 10,
    marginTop: 24,
  },
  check: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: 14,
    display: 'grid',
    gap: 8,
    fontFamily: font.mono,
  },
  primaryLink: {
    ...cta.primary,
    marginTop: 24,
    background: '#FAFAF9',
    color: '#171412',
  },
  secondaryLink: {
    ...cta.secondary,
    marginTop: 22,
    color: '#FAFAF9',
    border: '1px solid rgba(250,250,249,0.24)',
  },
  bullets: {
    margin: '22px 0 0',
    paddingLeft: 18,
    color: 'rgba(250,250,249,0.74)',
    lineHeight: 1.8,
    fontSize: 15,
  },
  stats: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
    gap: 10,
    marginTop: 24,
  },
  stat: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: 14,
    display: 'grid',
    gap: 8,
  },
  statNumber: {
    fontSize: 28,
    lineHeight: 1,
    color: '#FAFAF9',
  },
  statLabel: {
    color: 'rgba(250,250,249,0.62)',
    fontFamily: font.mono,
    fontSize: 11,
    lineHeight: 1.4,
  },
  rowLinks: {
    display: 'flex',
    gap: 10,
    flexWrap: 'wrap',
  },
  closeCard: {
    maxWidth: 1220,
    margin: '0 auto',
    padding: '72px 28px 86px',
    borderTop: '1px solid rgba(250,250,249,0.14)',
  },
  closeTitle: {
    margin: 0,
    maxWidth: 980,
    fontSize: 'clamp(42px, 6vw, 82px)',
    lineHeight: 0.96,
    letterSpacing: 0,
  },
  closeBody: {
    maxWidth: 720,
    margin: '24px 0 0',
    color: 'rgba(250,250,249,0.7)',
    fontSize: 18,
    lineHeight: 1.6,
  },
  closeLinks: {
    display: 'flex',
    gap: 18,
    flexWrap: 'wrap',
    marginTop: 34,
    fontFamily: font.mono,
    fontSize: 13,
    color: color.gold,
  },
  closeLink: {
    color: color.gold,
    textDecoration: 'none',
  },
  runbook: {
    maxWidth: 1220,
    margin: '0 auto',
    padding: '36px 28px 90px',
    display: 'grid',
    gridTemplateColumns: 'minmax(240px, 0.6fr) minmax(0, 1fr)',
    gap: 20,
    borderTop: '1px solid rgba(250,250,249,0.14)',
  },
  shots: {
    display: 'grid',
    gap: 8,
  },
  shot: {
    display: 'grid',
    gridTemplateColumns: '88px 130px minmax(0, 1fr)',
    gap: 14,
    alignItems: 'baseline',
    border: '1px solid rgba(250,250,249,0.12)',
    borderRadius: radius.sm,
    padding: '12px 14px',
    fontFamily: font.mono,
    color: 'rgba(250,250,249,0.72)',
  },
  shotLine: {
    margin: 0,
    lineHeight: 1.45,
  },
};
