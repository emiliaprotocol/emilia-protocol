// SPDX-License-Identifier: Apache-2.0

import Link from 'next/link';
import proofStatsData from '@/lib/proof-stats.json';
import { color, cta, font, radius } from '@/lib/tokens';
import registryIndex from '../../packages/fire-drill/registry-index.json';
import reports from '../../packages/fire-drill/reports.json';

export const metadata = {
  title: 'EMILIA for AAIF - Human Authorization Receipts',
  description:
    'A concise technical overview of EMILIA: offline-verifiable human authorization receipts for irreversible AI agent actions.',
  alternates: { canonical: '/aaif-video-pitch' },
  robots: { index: false, follow: false },
};

const repoUrl = 'https://github.com/emiliaprotocol/emilia-protocol';
const draftUrl = 'https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/';
const scittProfileUrl = `${repoUrl}/blob/main/docs/EP-RECEIPT-SCITT-PROFILE.md`;
const scittHarnessUrl = `${repoUrl}/blob/main/examples/scitt/ep-receipt-scitt-end-to-end.mjs`;

const landscapeRings = [
  ['MCP / tools', 'connection and capability surface'],
  ['OAuth / WIMSE / identity', 'who or what is calling'],
  ['RATS / SCITT / logs', 'attestation and transparency'],
  ['Agent frameworks / AGENTS.md', 'execution and guidance'],
];

const stackRows = [
  ['MCP', 'connects agents to tools'],
  ['goose', 'runs the agent workflow'],
  ['AGENTS.md', 'guides local behavior'],
  ['EMILIA', 'proves a named human authorized the exact irreversible action'],
];

const rrChecks = [
  ['Missing receipt', '428 blocked'],
  ['Valid receipt', 'runs once'],
  ['Same receipt', 'replay refused'],
  ['Forged receipt', 'signature rejected'],
];

const scittChecks = [
  ['Signed Statement', 'COSE_Sign1'],
  ['Register', 'SCRAPI /entries'],
  ['Receipt', 'inclusion verified'],
  ['Boundary', 'SCITT logs; EP authorizes'],
];

const proofStats = [
  [proofStatsData.tests.passed.toLocaleString('en-US'), 'automated tests'],
  ['26', 'TLA+ safety properties'],
  ['35 / 22', 'Alloy facts / assertions'],
  ['9', 'cross-language conformance suites'],
];

const capabilityCards = [
  ['Authorization receipts', 'Single human signs the exact action before execution.', '/spec'],
  ['Quorum', 'M-of-N or ordered two-person rule for highest-stakes actions.', '/quorum'],
  ['Evidence graph', 'Compose authorization, policy, and identity into one offline-verifiable graph — who authorized, what ran, under which policy.', '/standards'],
  ['Human control', 'Defense and public-sector oversight mapped to verifiable receipts.', '/human-control'],
];

const objections = [
  ['"Isn’t this just SCITT?"', 'SCITT proves a statement was logged. EP proves who authorized — and rides as a SCITT Signed Statement. Composes, doesn’t compete.'],
  ['"Isn’t this OAuth / delegation?"', 'Those grant a machine a scope. EP proves a named human approved this exact action. Above identity, not instead of it.'],
  ['"Why not just log the approval?"', 'A log is operator-editable testimony. An EP receipt is offline-verifiable evidence — bound to the action, one-time, no trust in the operator.'],
  ['"Doesn’t per-action sign-off kill latency?"', 'Only irreversible actions gate — not every call. Pre-authorization, scoped delegation, and quorum carry the throughput.'],
  ['"Where does it standardize?"', 'Individual IETF I-D cluster — receipts + quorum + evidence-chain — composing with SCITT / RFC 9943. That’s the open question we bring.'],
];

const links = [
  ['#gap', 'Gap'],
  ['#demo', 'Demo'],
  ['#scitt', 'SCITT'],
  ['#surfaces', 'Surfaces'],
  ['#qa', 'Q&A'],
  ['#ask', 'Ask'],
];

export default function AaifVideoPitchPage() {
  const publishedReports = reports.reports.filter((r) => r.published).length;

  return (
    <main style={s.page} className="aaif-deck">
      <style>{`
        html { scroll-behavior: smooth; }
        #ep-eu-ai-act-banner { display: none !important; }
        nextjs-portal { display: none !important; }
        .aaif-deck { scroll-snap-type: y mandatory; overflow-y: auto; height: 100vh; }
        .aaif-deck > section { scroll-snap-align: start; scroll-snap-stop: always; }
        @media (max-width: 900px) {
          .aaif-stats { grid-template-columns: 1fr !important; }
          .aaif-proof-grid { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
          .aaif-void-map { grid-template-columns: 1fr !important; }
        }
        @media (max-width: 640px) {
          .aaif-deck { scroll-snap-type: y proximity; }
          .aaif-hero, .aaif-slide { padding: 52px 20px 32px !important; }
          .aaif-layer-row { grid-template-columns: 1fr !important; }
          .aaif-check-grid { grid-template-columns: 1fr !important; }
          .aaif-proof-grid { grid-template-columns: 1fr !important; }
          .aaif-ring-grid { grid-template-columns: 1fr !important; }
          .aaif-qa-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
      <header style={s.topbar}>
        <Link href="/" style={s.brand}>EMILIA</Link>
        <div style={s.topMeta}>Human authorization receipts for AI agent actions</div>
        <nav style={s.topLinks}>
          {links.map(([href, label]) => (
            <a key={href} href={href} style={s.topLink}>
              {label}
            </a>
          ))}
        </nav>
      </header>

      <section style={s.hero} className="aaif-hero">
        <div style={s.heroText}>
          <div style={s.eyebrow}>EMILIA FOR AAIF</div>
          <h1 style={s.h1}>The missing human-proof layer for agent actions.</h1>
          <p style={s.lead}>
            The agent stack is filling in around identity, tools, execution, and logs. The void in the middle is portable proof that a named human authorized one exact irreversible action before it ran.
          </p>
        </div>
        <div style={{ margin: '28px auto 4px', maxWidth: 900, width: '100%' }}>
          <video
            autoPlay muted loop playsInline preload="metadata"
            poster="/hero/emilia-sequence-poster.jpg"
            aria-label="Automated agent control: each high-risk action is scanned, then AUTHORIZED with a named human authorizer or DENIED when no human authorizer is available."
            style={{
              width: '100%', aspectRatio: '16 / 9', objectFit: 'cover',
              borderRadius: 14, border: `1px solid ${color.border}`,
              display: 'block', background: '#0b0b0d',
            }}
          >
            <source src="/hero/emilia-sequence.mp4" type="video/mp4" />
          </video>
        </div>
        <div style={s.lowerThird}>
          <span style={s.pill}>draft-schrock-ep-authorization-receipts</span>
          <span style={s.pill}>Apache-2.0</span>
          <span style={s.pill}>JS / Python / Go verifiers</span>
          <span style={s.pill}>offline-verifiable</span>
        </div>
      </section>

      <section id="gap" style={{ ...s.slide, ...s.anchor }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>01 · THE LANDSCAPE GAP</div>
          <h2 style={s.h2}>Many drafts describe the agent stack. The missing primitive is proof of human authorization.</h2>
          <div style={s.voidMap} className="aaif-void-map">
            <div style={s.ringGrid} className="aaif-ring-grid">
              {landscapeRings.map(([name, job]) => (
                <div key={name} style={s.ringCard}>
                  <strong style={s.ringTitle}>{name}</strong>
                  <span style={s.ringBody}>{job}</span>
                </div>
              ))}
            </div>
            <div style={s.voidCenter}>
              <span style={s.voidLabel}>BLACK VOID</span>
              <strong style={s.voidQuestion}>Who authorized this exact irreversible action before execution?</strong>
              <p style={s.voidBody}>EMILIA fills this with an offline-verifiable receipt.</p>
            </div>
          </div>
          <div style={s.rowLinks}>
            <Link href="/standards" style={s.secondaryLink}>Open standards map</Link>
            <a href={draftUrl} style={s.secondaryLink} target="_blank" rel="noopener noreferrer">Open I-D</a>
          </div>
        </div>
      </section>

      <section style={s.slide} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>02 · WHERE IT SITS</div>
          <h2 style={s.h2}>A small layer between intent and mutation.</h2>
          <div style={s.layerStack}>
            {stackRows.map(([name, job], index) => (
              <div key={name} className="aaif-layer-row" style={{ ...s.layerRow, ...(index === stackRows.length - 1 ? s.layerEmilia : null) }}>
                <strong>{name}</strong>
                <span>{job}</span>
              </div>
            ))}
          </div>
          <p style={s.statement}>Decision logs are testimony. Receipts are evidence.</p>
        </div>
      </section>

      <section id="demo" style={{ ...s.slide, ...s.anchor }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>03 · LIVE DEMO</div>
          <h2 style={s.h2}>Try to break the action layer.</h2>
          <p style={s.body}>An irreversible action is blocked without a receipt, runs once with an exact-action receipt, and rejects replay or tampering.</p>
          <div style={s.checkGrid} className="aaif-check-grid">
            {rrChecks.map(([label, result]) => (
              <div key={label} style={s.check}>
                <span>{label}</span>
                <strong>{result}</strong>
              </div>
            ))}
          </div>
          <Link href="/try/receipt-required" style={s.primaryLink}>Open live demo</Link>
        </div>
      </section>

      <section id="scitt" style={{ ...s.slide, ...s.anchor }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>04 · SCITT COMPOSITION PROOF</div>
          <h2 style={s.h2}>An authorization receipt can ride as a SCITT Signed Statement.</h2>
          <p style={s.body}>The end-to-end harness wraps the same canonical EP payload as COSE_Sign1, registers it through the SCRAPI path, and verifies mock transparency evidence in CI. SCITT proves the statement was logged; EMILIA proves who authorized the action.</p>
          <div style={s.checkGrid} className="aaif-check-grid">
            {scittChecks.map(([label, result]) => (
              <div key={label} style={s.check}>
                <span>{label}</span>
                <strong>{result}</strong>
              </div>
            ))}
          </div>
          <pre style={s.command}>node examples/scitt/ep-receipt-scitt-end-to-end.mjs</pre>
          <div style={s.rowLinks}>
            <a href={scittProfileUrl} style={s.secondaryLink} target="_blank" rel="noopener noreferrer">SCITT profile</a>
            <a href={scittHarnessUrl} style={s.secondaryLink} target="_blank" rel="noopener noreferrer">Harness</a>
          </div>
        </div>
      </section>

      <section id="surfaces" style={{ ...s.slide, ...s.anchor }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>05 · HIGHER-STAKES SURFACES</div>
          <h2 style={s.h2}>Single approval, quorum, and human-control profiles use the same receipt spine.</h2>
          <div style={s.capabilityGrid}>
            {capabilityCards.map(([name, body, href]) => (
              <Link key={name} href={href} style={s.capabilityCard}>
                <strong style={s.capabilityTitle}>{name}</strong>
                <span style={s.capabilityBody}>{body}</span>
              </Link>
            ))}
          </div>
          <p style={s.body}>The defense-facing human-control surface maps receipt evidence to DoD Directive 3000.09, EU AI Act Article 14, NIST AI RMF, and the LAWS debate - carefully scoped as authorization proof, not proof of wisdom.</p>
        </div>
      </section>

      <section style={s.slide} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>BUILT, TESTED, LIGHTWEIGHT</div>
          <h2 style={s.h2}>Small enough to try. Serious enough to review.</h2>
          <div style={s.proofGrid} className="aaif-proof-grid">
            {proofStats.map(([value, label]) => (
              <div key={label} style={s.proofStat}>
                <strong style={s.proofNumber}>{value}</strong>
                <span style={s.proofLabel}>{label}</span>
              </div>
            ))}
          </div>
          <pre style={s.command}>npx @emilia-protocol/issue demo</pre>
        </div>
      </section>

      <section style={s.slide} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>REAL AND SMALL</div>
          <h2 style={s.h2}>A primitive, not a platform pitch.</h2>
          <ul style={s.bullets}>
            <li>Active individual Internet-Draft, not an IETF endorsement.</li>
            <li>Reference verifiers in JavaScript, Python, and Go agree on shared conformance vectors.</li>
            <li>26 TLA+ safety properties and Alloy checks are machine-checked in CI.</li>
            <li>No account or backend for the local demo: <code>npx @emilia-protocol/issue demo</code>.</li>
          </ul>
          <a href={draftUrl} style={s.secondaryLink} target="_blank" rel="noopener noreferrer">Open datatracker draft</a>
        </div>
      </section>

      <section style={s.slide} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>ECOSYSTEM PROOF</div>
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
        </div>
      </section>

      <section id="qa" style={{ ...s.slide, ...s.anchor }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>OBJECTIONS, ANSWERED</div>
          <h2 style={s.h2}>The five questions — and the one-line answers.</h2>
          <div style={s.qaGrid} className="aaif-qa-grid">
            {objections.map(([q, a]) => (
              <div key={q} style={s.qaCard}>
                <strong style={s.qaQ}>{q}</strong>
                <span style={s.qaA}>{a}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="ask" style={{ ...s.slide, ...s.anchor, borderBottom: 'none' }} className="aaif-slide">
        <div style={s.slideInner}>
          <div style={s.eyebrow}>06 · THE ASK</div>
          <h2 style={s.closeTitle}>If this is the missing human-authorization layer, where should it belong?</h2>
          <p style={s.closeBody}>Early, non-binding read on fit. Composes with MCP, goose, and AGENTS.md. Apache-2.0 reference implementation.</p>
          <div style={s.closeLinks}>
            <span>team@emiliaprotocol.ai</span>
            <a href={repoUrl} style={s.closeLink} target="_blank" rel="noopener noreferrer">github.com/emiliaprotocol/emilia-protocol</a>
          </div>
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
    position: 'sticky',
    top: 0,
    zIndex: 20,
    minHeight: 68,
    display: 'flex',
    alignItems: 'center',
    gap: 18,
    padding: '0 28px',
    borderBottom: '1px solid rgba(250,250,249,0.14)',
    flexWrap: 'wrap',
    background: 'rgba(23,20,18,0.94)',
    backdropFilter: 'blur(16px)',
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
  slide: {
    minHeight: 'calc(100vh - 68px)',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center',
    padding: '64px 32px',
    borderBottom: '1px solid rgba(250,250,249,0.14)',
  },
  slideInner: {
    maxWidth: 1040,
    margin: '0 auto',
    width: '100%',
  },
  anchor: {
    scrollMarginTop: 68,
  },
  h2: {
    margin: 0,
    fontSize: 'clamp(26px, 3vw, 40px)',
    lineHeight: 1.04,
    letterSpacing: 0,
  },
  voidMap: {
    display: 'grid',
    gridTemplateColumns: 'minmax(0, 1fr) minmax(280px, 0.78fr)',
    gap: 14,
    marginTop: 26,
  },
  ringGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: 10,
  },
  ringCard: {
    minHeight: 92,
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: 16,
    display: 'grid',
    alignContent: 'space-between',
    gap: 12,
    fontFamily: font.mono,
    color: 'rgba(250,250,249,0.7)',
  },
  ringTitle: {
    color: '#FAFAF9',
    fontSize: 14,
  },
  ringBody: {
    fontSize: 12,
    lineHeight: 1.45,
  },
  voidCenter: {
    border: `1px solid ${color.gold}`,
    borderRadius: radius.base,
    padding: 18,
    background: 'rgba(176,141,53,0.14)',
    display: 'grid',
    alignContent: 'center',
    gap: 12,
    minHeight: 194,
  },
  voidLabel: {
    fontFamily: font.mono,
    color: color.gold,
    fontSize: 11,
    letterSpacing: 1.8,
  },
  voidQuestion: {
    color: '#FAFAF9',
    fontSize: 24,
    lineHeight: 1.08,
  },
  voidBody: {
    margin: 0,
    color: 'rgba(250,250,249,0.72)',
    lineHeight: 1.5,
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
  qaGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
    gap: 12,
    marginTop: 26,
  },
  qaCard: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    borderLeft: `3px solid ${color.gold}`,
    padding: '16px 18px',
    display: 'grid',
    gap: 8,
    background: 'rgba(250,250,249,0.03)',
  },
  qaQ: {
    fontSize: 16,
    color: '#FAFAF9',
    lineHeight: 1.25,
  },
  qaA: {
    fontSize: 14,
    color: 'rgba(250,250,249,0.72)',
    lineHeight: 1.55,
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
  capabilityGrid: {
    display: 'grid',
    gap: 10,
    marginTop: 22,
  },
  capabilityCard: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: 15,
    display: 'grid',
    gap: 8,
    color: '#FAFAF9',
    textDecoration: 'none',
  },
  capabilityTitle: {
    fontSize: 16,
  },
  capabilityBody: {
    color: 'rgba(250,250,249,0.66)',
    lineHeight: 1.5,
  },
  proofGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
    gap: 10,
    marginTop: 24,
  },
  proofStat: {
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: 14,
    display: 'grid',
    gap: 8,
    minHeight: 104,
  },
  proofNumber: {
    fontSize: 32,
    lineHeight: 1,
    color: '#FAFAF9',
  },
  proofLabel: {
    color: 'rgba(250,250,249,0.62)',
    fontFamily: font.mono,
    fontSize: 11,
    lineHeight: 1.35,
  },
  command: {
    margin: '22px 0 0',
    border: '1px solid rgba(250,250,249,0.14)',
    borderRadius: radius.sm,
    padding: '14px 16px',
    color: color.gold,
    background: '#0F0D0B',
    fontFamily: font.mono,
    fontSize: 14,
    overflowX: 'auto',
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
};
