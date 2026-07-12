'use client';

import Link from 'next/link';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import EmailCapture from '@/components/EmailCapture';
import ProofBlock from '@/components/ProofBlock';
import { styles, cta, color, font, radius } from '@/lib/tokens';
import proofStats from '@/lib/proof-stats.json';

// ─────────────────────────────────────────────────────────────────────────────
// Homepage — mission-led buyer flow.
// The first viewport establishes why the agentic era needs shared trust
// infrastructure. Detailed mechanics and machine-verifiable evidence remain
// available one click away on /protocol and /proof.
// ─────────────────────────────────────────────────────────────────────────────

// Stats — independently verifiable in the repo:
//   test cases (per lib/proof-stats.json) — `node scripts/generate-proof-stats.mjs`
//   26 TLA+ invariants verified — formal/PROOF_STATUS.md (T1–T26)
//   35 Alloy facts — formal/Alloy/EP.als
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md
//   Apache 2.0 — LICENSE
const TEST_CASES = Number(proofStats.tests?.total || 0).toLocaleString('en-US');
const TLA_INVARIANTS = String(proofStats.tla?.invariants || 26);
const TAMARIN_OBLIGATIONS = String(proofStats.tamarin?.verifiedObligations || 0);
const SECURITY_CLAIMS = String(proofStats.securityCase?.claims || 0);
const CONFORMANCE_VECTORS = String(proofStats.conformance?.vectors || 0);

const PROBLEMS = [
  { num: '01', title: 'The vendor wire that passed',     body: 'A payment destination changed inside a valid session, approved through the normal process, to a vendor whose bank details quietly moved. Business email compromise — not a hack.' },
  { num: '02', title: 'The beneficiary swap',            body: 'A remittance beneficiary was updated through approved channels. The system saw a legitimate change and let the money go.' },
  { num: '03', title: 'The production credential',       body: 'An infrastructure credential was rotated and a deploy was pushed without action-bound authorization. Every access was valid; the blast radius was not.' },
  { num: '04', title: 'The agent that executed',         body: 'An AI agent with broad tool access ran a high-risk, irreversible action. No human assumed responsibility for that specific operation.' },
];

const SURFACES = [
  { title: 'EMILIA Gate — the Consequence Firewall', body: 'The productized firewall for machine action. Deny-by-default at the actuator boundary: a consequential action runs only with a valid, sufficiently-assured, non-replayed receipt — then emits proof it ran. Software, cloud, and robots. Antivirus scanned files; firewalls filtered packets; EMILIA verifies actions.', href: '/gate', accent: color.gold, tags: ['CONSEQUENCE FIREWALL', 'SHIPPED'] },
  { title: 'MCP & Agent Tool-Calls',            body: 'Wrap a dangerous MCP tool — release_payment, delete_repo, deploy_production — so it refuses to run without a receipt. One wrapper, fail-closed, works with any framework. This is the developer wedge.', href: '/mcp',                accent: color.t2,   tags: ['MCP', 'TOOL-CALL ENFORCEMENT']   },
  { title: 'Energy — Verifiable Demand Response (GRACE)', body: 'Authorize, shed, measure, and prove datacenter curtailment so the grid pays against cryptographic proof, not self-report. COSA moves the megawatts; EMILIA proves the move was authorized and delivered.', href: '/grace', accent: color.green, tags: ['GRACE', 'PROOF-OF-CURTAILMENT'] },
  { title: 'Financial — Money Movement',         body: 'Ceremony-grade authorization on wire releases, beneficiary changes, account modifications, and privileged treasury actions before funds move.', href: '/finguard',           accent: color.blue,  tags: ['BEC PREVENTION', 'SOX-READY']    },
  { title: 'Government — Benefit Integrity',     body: 'Bind identity, authority, and action context before a benefit determination, redirect, or override. Accountable decisions, due process proven.', href: '/govguard',           accent: color.green, tags: ['NIST AI RMF', 'EU AI ACT']       },
  { title: 'Enterprise Privileged Actions',      body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise', accent: color.gold,  tags: ['ZERO TRUST', 'PAM LAYER']        },
];

// The customer-facing model: Observe → Verify → Own → Seal. The underlying
// technical layers (Eye → Handshake → Signoff → Commit) live on /protocol; the
// enforcement bundle (Verify + Own + Seal) is packaged for buyers as EMILIA Gate.
const HOW_IT_WORKS = [
  { step: '01', accent: color.green, label: 'Observe',  body: 'Start in observe mode: see every irreversible action that would require stronger approval — payments, overrides, vendor changes, autonomous AI actions — with zero blocking. The safe on-ramp before you enforce anything.' },
  { step: '02', accent: color.blue,  label: 'Verify',   body: 'EMILIA Gate sits between approval and execution. Before a high-risk write reaches the system of record, it binds verified actor identity, authority chain, policy-pinned action context, and a one-time nonce.' },
  { step: '03', accent: color.gold,  label: 'Own',      body: 'Where policy requires it, a named, accountable human signs off on the exact action — on their own device, bound to the exact action hash. Self-approval fails by construction. For the highest-stakes actions, a multi-party quorum — the two-person rule, in order, each human bound to the exact action — is enforced before execution.' },
  { step: '04', accent: color.t2,    label: 'Seal',     body: 'A signed, Merkle-anchored authorization receipt is produced — an auditor-grade evidence packet, publicly verifiable offline with `npm install @emilia-protocol/verify`.' },
];

// Eight bindings — the mechanical reasons a high-risk action can't be faked or
// hidden in an EMILIA-integrated path. Each line names the attack it closes.
const BINDINGS = [
  { n: '01', accent: color.green, label: 'Reject before mutation',   body: 'Consume must succeed before the write runs. An unauthorized action is stopped, not logged after the fact.' },
  { n: '02', accent: color.blue,  label: 'Exact-action binding',     body: 'The receipt binds the action hash, and (with the experimental display-attestation profile) a hash of the rendered context — narrowing the “signed the wrong thing” gap between the bytes signed and what the approver saw.' },
  { n: '03', accent: color.gold,  label: 'Policy binding',           body: 'The receipt binds the policy content that was in force, not just a policy name or version label.' },
  { n: '04', accent: color.green, label: 'Authority binding',        body: 'Holding a credential is separate from holding permission to approve. The authority registry proves the signer was allowed to.' },
  { n: '05', accent: color.blue,  label: 'Class-A enforcement',      body: 'High-risk actions require a passkey / WebAuthn device signoff — or stronger. Weaker assurance fails closed.' },
  { n: '06', accent: color.gold,  label: 'Execution attestation',    body: 'After approval, an attestation proves what actually ran — and flags drift between the approved and executed action.' },
  { n: '07', accent: color.green, label: 'Strict offline verifier',  body: 'Outside parties verify pinned keys, RP identity, and policy hash without trusting EMILIA’s server. npm install @emilia-protocol/verify.' },
  { n: '08', accent: color.blue,  label: 'SDK wrapper',              body: 'Developers adopt the invariant directly around a dangerous write with requireReceipt(...) — no rebuild of the call site.' },
];

const DEV_TOOLS = [
  { title: 'Verify It Yourself', body: 'Drop a receipt or a Face ID device signoff and watch every cryptographic check verify — entirely in your browser, nothing uploaded, no account, no EP server trusted.', code: '/verify', href: '/verify', accent: color.green, dark: true  },
  { title: 'Trust Playground', body: 'Walk through the EP lifecycle interactively. Create entities, issue receipts, run handshakes — all from one page.',                 code: '/playground',       href: '/playground', accent: color.blue,  dark: false },
  { title: 'Trust Explorer',   body: 'Verify any receipt, proof, or entity. Like Etherscan for trust. Public, transparent, cryptographically verified.',                   code: '/explorer',         href: '/explorer',   accent: color.gold,  dark: false },
  { title: 'Embed Widget',     body: 'Drop a trust badge on any page. One script tag, one web component. Live data from the EP operator.',                                code: '<ep-trust-badge />', href: '/adopt',      accent: color.t2,    dark: false },
];

// Max-width container
const C = ({ children }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>{children}</div>
);

// Fingerprint-style inset shadow: subtle internal depth without harsh outset shadow.
const INSET = 'rgba(228,229,225,0.35) 0 1px 0 0 inset, rgba(110,111,109,0.08) 0 -1px 0 0 inset';

// ── Motion animation presets ────────────────────────────────────────────────
// All scroll reveals use Motion whileInView — no manual IntersectionObserver,
// no class-toggling, no timing hacks. Motion handles edge cases internally.
const EASE = [0.23, 1, 0.32, 1];

// Scroll-triggered rise: used for every section below the hero.
// Keep opacity at 1 by default so no-JS, crawler, PDF, and full-page screenshot
// renders never capture a blank page before intersection events fire.
// viewport.once:true means it animates once and stays visible.
const reveal = (delay = 0) => ({
  initial: { opacity: 1, y: 18 },
  whileInView: { y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.58, delay, ease: EASE },
});

// Above-fold hero elements: triggered by animate (not scroll) so they play
// immediately on load regardless of viewport position. Opacity stays 1 by
// default (same reason as `reveal` above) so the hero headline, CTAs, and
// film are never blank for no-JS, crawler, PDF, or pre-hydration full-page
// screenshot renders — only the rise animates once JS runs.
const heroIn = (delay = 0) => ({
  initial: { opacity: 1, y: 14 },
  animate: { y: 0 },
  transition: { duration: 0.6, delay, ease: EASE },
});

export default function HomePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO — one quiet idea before any machinery ───────── */}
      <section className="ep-home-calm-hero">
        <C>
          <motion.div className="ep-home-calm-copy" {...heroIn(0)}>
            <div className="ep-home-calm-kicker">EMILIA Protocol</div>
            <h1>Building the foundation of trust for the agentic era.</h1>
            <p className="ep-home-calm-lede">
              AI is moving from answering questions to taking consequential action.
            </p>
            <p className="ep-home-calm-detail">
              EMILIA is the open trust layer that binds identity, authority, and approval
              to the exact action before execution, then leaves evidence anyone can verify.
            </p>
            <div className="ep-home-calm-actions">
              <Link href="/protocol" className="ep-cta" style={cta.primary}>Explore the protocol</Link>
            </div>
          </motion.div>
        </C>
      </section>

      {/* ── TECHNICAL FOUNDATION — a quiet proof line, not the story ─ */}
      <section className="ep-home-technical-band" aria-label="Technical foundation">
        <C>
          <div className="ep-home-technical-line">
            <div className="ep-home-technical-title">
              <strong>Technical foundation</strong>
              <span>Open protocol</span>
            </div>
            <div className="ep-home-technical-facts">
              <span>IETF Internet-Drafts</span>
              <span>Apache 2.0</span>
              <span>{TAMARIN_OBLIGATIONS} composed attack-model obligations</span>
              <span>{SECURITY_CLAIMS} executable security claims</span>
              <span>{CONFORMANCE_VECTORS} conformance vectors</span>
              <span>CF-1 conformance</span>
            </div>
            <Link href="/proof" className="ep-home-technical-link">Inspect the proof →</Link>
          </div>
        </C>
      </section>

      {/* ── THE GAP (pain — buyer feels it in 5 seconds) ───────── */}
      <section style={{ padding: '96px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 780 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>The gap</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              Auth gets an agent a token. It doesn&apos;t prove a human authorized the action.
            </h2>
            <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.72, maxWidth: 640, marginTop: 20 }}>
              An agent can have valid access and still do the wrong thing: change a vendor bank
              account, release funds, delete a repo, export records, or approve a regulated
              decision. Decision logs say what happened after the fact. EMILIA creates portable
              evidence <em style={{ fontStyle: 'normal', color: color.t1, fontWeight: 600 }}>before</em> the mutation runs.
            </p>
          </motion.div>
        </C>
      </section>

      {/* ── THE INVARIANT (product) ────────────────────────────── */}
      <section style={{ padding: '72px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 780 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>The invariant</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: '0 0 24px' }}>
              No valid receipt, no mutation.
            </h2>
            <div style={{ borderTop: `1px solid ${color.border}`, maxWidth: 620 }}>
              {[
                ['Missing receipt', 'blocked before execution'],
                ['Valid receipt', 'action runs once'],
                ['Replay', 'refused'],
                ['Tampering', 'rejected'],
                ['Evidence packet', 'verifiable offline'],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'baseline', gap: 12, padding: '13px 0', borderBottom: `1px solid ${color.border}` }}>
                  <span style={{ fontFamily: font.mono, fontSize: 13, color: color.t1, minWidth: 170 }}>{k}</span>
                  <span style={{ fontFamily: font.mono, fontSize: 12, color: color.gold }}>→</span>
                  <span style={{ fontFamily: font.sans, fontSize: 14, color: color.t2 }}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 28 }}>
              <Link href="/demo" className="ep-cta-secondary" style={cta.secondary}>Try the Receipt Required demo →</Link>
            </div>
          </motion.div>
        </C>
      </section>

      {/* ── THE WEDGE (payment destination changes) ────────────── */}
      <section style={{ padding: '72px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 780 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>The wedge</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              Start with the action fraud teams already fear: payment destination changes.
            </h2>
            <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.72, maxWidth: 640, marginTop: 20 }}>
              Vendor bank-detail changes and beneficiary updates are where valid access turns into
              real loss. EMILIA requires a named human to approve the exact change before money
              moves, then exports an evidence packet an auditor, insurer, or regulator can verify
              without trusting your app.
            </p>
          </motion.div>
        </C>
      </section>

      {/* ── THE POSITION (Arcade = market validation, below fold) ─ */}
      <section style={{ padding: '72px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 940 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>The position</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              Not the passport — passport control, and the stamp.
            </h2>
            <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.72, maxWidth: 640, marginTop: 20 }}>
              Arcade validated the agent-action category. Identity says <em>which machine</em> is acting;
              tool-auth says it <em>may call</em> a tool. EMILIA is the open, offline-verifiable
              evidence layer none of them produce: proof a named human authorized <em>this exact action</em>.
            </p>
            <figure style={{ margin: '32px 0 0' }}>
              {/* eslint-disable-next-line @next/next/no-img-element -- static SVG diagram; next/image doesn't optimize SVG */}
              <img
                src="/diagrams/agent-action-stack.svg"
                alt="Agent-action pipeline: an AI agent's action passes identity (passport), permission (visa), then EMILIA — passport control (deny-by-default Gate) plus the stamp (a named human's offline-verifiable authorization receipt) — before it runs; no valid stamp, no execution."
                style={{ width: '100%', height: 'auto', display: 'block', borderRadius: 14, border: `1px solid ${color.border}` }}
              />
            </figure>
            <div style={{ marginTop: 28, borderTop: `1px solid ${color.border}`, paddingTop: 20, maxWidth: 640 }}>
              {[
                ['MCP', 'connects agents to tools'],
                ['Eve & agent runtimes', 'execute workflows'],
                ['Arcade-style systems', 'handle tool auth'],
                ['SCITT', 'logs signed statements'],
                ['EMILIA', 'proves who authorized the irreversible action'],
              ].map(([k, v], i) => (
                <div key={k} style={{ display: 'flex', alignItems: 'baseline', gap: 12, padding: '10px 0' }}>
                  <span style={{ fontFamily: font.mono, fontSize: 13, color: i === 4 ? color.gold : color.t1, minWidth: 190 }}>{k}</span>
                  <span style={{ fontFamily: font.sans, fontSize: 14, color: color.t2 }}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 24 }}>
              <Link href="/standards" className="ep-cta-secondary" style={cta.secondary}>Open the standards map →</Link>
            </div>
          </motion.div>
        </C>
      </section>

      {/* ── THE WALL OF REGRET (buyer emotion — before the math) ─ */}
      <section style={{ padding: '104px 0 0' }}>
        <C>
          <div className="ep-home-grid-regret" style={{ display: 'grid', gridTemplateColumns: '5fr 7fr', gap: 80, alignItems: 'start' }}>
            {/* Sticky editorial label */}
            <motion.div className="ep-home-sticky" {...reveal()} style={{ position: 'sticky', top: 96 }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                The Wall of Regret
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(22px, 2.5vw, 34px)',
                letterSpacing: -0.75, lineHeight: 1.18, color: color.t1, marginBottom: 20,
              }}>
                Every one of these passed. None of them had an owner.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.72 }}>
                The actions that drain accounts and break production are rarely
                &ldquo;hacks.&rdquo; They&rsquo;re authenticated users, legitimate tools, approved
                channels — and afterward, no one can say <em style={{ fontStyle: 'normal', fontWeight: 600, color: color.t1 }}>who approved this</em>.
                That unanswered question is the whole problem.
              </p>
            </motion.div>

            {/* Problem rows — ep-problem-row gives left-bar gold hover */}
            <motion.div {...reveal(0.08)} style={{ borderTop: `1px solid ${color.border}` }}>
              {PROBLEMS.map((p, i) => (
                <div key={i} className="ep-problem-row" style={{
                  position: 'relative', overflow: 'hidden',
                  padding: '36px 16px 36px 28px',
                  borderBottom: `1px solid ${color.border}`,
                }}>
                  {/* Ghost large number — more prominent */}
                  <div aria-hidden style={{
                    position: 'absolute', right: -4, top: -12,
                    fontFamily: font.mono, fontWeight: 700, fontSize: 104,
                    color: 'rgba(12,10,9,0.04)', pointerEvents: 'none',
                    lineHeight: 1, userSelect: 'none',
                  }}>
                    {p.num}
                  </div>
                  <div style={{ position: 'relative', zIndex: 1 }}>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 10 }}>
                      {p.num}
                    </div>
                    <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, marginBottom: 8, color: color.t1 }}>
                      {p.title}
                    </h3>
                    <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, margin: 0 }}>
                      {p.body}
                    </p>
                  </div>
                </div>
              ))}
              <div style={{ padding: '32px 16px 8px 28px' }}>
                <p style={{ fontSize: 16, color: color.t1, lineHeight: 1.6, margin: 0, fontWeight: 600 }}>
                  Who approved this? In every case, no one could say.
                </p>
                <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, margin: '8px 0 0' }}>
                  EMILIA assigns a named human owner <em style={{ fontStyle: 'normal', fontWeight: 600, color: color.t1 }}>before</em> the
                  action runs — so the question always has an answer, on the record, that anyone can verify.
                </p>
              </div>
            </motion.div>
          </div>
        </C>
      </section>

      {/* ── PROOF — formal-verification anchor (the spear tip) ─── */}
      <section style={{ padding: '96px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <ProofBlock />
        </C>
      </section>

      {/* ── HOW IT WORKS — editorial stepped rows ─────────────── */}
      <section style={{ padding: '104px 0 80px', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <motion.div {...reveal()} style={{ marginBottom: 64 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
              How EMILIA Works
            </div>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(26px, 3vw, 40px)',
              letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 520,
            }}>
              A control layer between approval and execution.
            </h2>
          </motion.div>

          {/* Steps as horizontal editorial rows — no card boxes */}
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {HOW_IT_WORKS.map((item, i) => (
              <motion.div
                key={i}
                className="ep-home-grid-step"
                {...reveal(i * 0.06)}
                style={{
                  display: 'grid', gridTemplateColumns: '140px 1fr',
                  gap: 56, alignItems: 'start',
                  padding: '44px 0',
                  borderBottom: `1px solid ${color.border}`,
                }}
              >
                {/* Step tag */}
                <div>
                  <div style={{
                    fontFamily: font.mono, fontSize: 10, letterSpacing: 2,
                    textTransform: 'uppercase', color: item.accent, marginBottom: 10,
                  }}>
                    {item.step}
                  </div>
                  <div style={{
                    fontFamily: font.mono, fontSize: 11, fontWeight: 600,
                    letterSpacing: 1.5, textTransform: 'uppercase', color: color.t1, lineHeight: 1.4,
                  }}>
                    {item.label}
                  </div>
                </div>
                {/* Step body */}
                <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.72, maxWidth: 600, margin: 0 }}>
                  {item.body}
                </p>
              </motion.div>
            ))}
          </div>

          <div style={{ marginTop: 36 }}>
            <Link href="/r/example" style={{
              fontFamily: font.mono, fontSize: 11, color: color.gold,
              letterSpacing: 1.5, textTransform: 'uppercase',
              textDecoration: 'underline', textUnderlineOffset: 4,
            }}>
              See a real receipt →
            </Link>
          </div>
        </C>
      </section>

      {/* ── EIGHT BINDINGS — why it's hard to dismiss ─────────── */}
      <section style={{ padding: '104px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <motion.div {...reveal()} style={{ marginBottom: 56, maxWidth: 640 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
              Why it&rsquo;s hard to dismiss
            </div>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(26px, 3vw, 40px)',
              letterSpacing: -1, lineHeight: 1.15, color: color.t1,
            }}>
              Eight bindings, one invariant.
            </h2>
            <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.72, marginTop: 20 }}>
              If an agent or system changes money, permissions, code, records, or regulated state through an
              EMILIA-integrated path, it is either rejected before mutation or it produces an offline-verifiable
              receipt proving the exact action, policy, authority, signoff strength, and execution binding.
              Each line below names the attack it closes.
            </p>
          </motion.div>

          <div className="ep-home-grid-2" style={{
            display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)',
            borderTop: `1px solid ${color.border}`, borderLeft: `1px solid ${color.border}`,
          }}>
            {BINDINGS.map((b, i) => (
              <motion.div
                key={b.n}
                {...reveal((i % 2) * 0.05)}
                style={{
                  display: 'flex', gap: 16, alignItems: 'flex-start',
                  padding: '30px 28px',
                  borderRight: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`,
                }}
              >
                <div style={{ width: 3, alignSelf: 'stretch', background: b.accent, flexShrink: 0, borderRadius: 2 }} />
                <div>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'baseline', marginBottom: 8 }}>
                    <span style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, color: color.t3 }}>{b.n}</span>
                    <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase', color: color.t1 }}>{b.label}</span>
                  </div>
                  <p style={{ fontSize: 14.5, color: color.t2, lineHeight: 1.65, margin: 0 }}>{b.body}</p>
                </div>
              </motion.div>
            ))}
          </div>

          <motion.div {...reveal(0.1)} style={{ marginTop: 40, maxWidth: 640 }}>
            <p style={{ fontFamily: font.sans, fontSize: 'clamp(18px, 2vw, 22px)', fontWeight: 600, color: color.t1, lineHeight: 1.5, letterSpacing: -0.3, margin: 0 }}>
              No receipt, no irreversible action.{' '}
              <span style={{ color: color.t2, fontWeight: 400 }}>If it runs, anyone can verify who authorized exactly what.</span>
            </p>
          </motion.div>
        </C>
      </section>

      {/* ── DEVELOPER WEDGE — MCP tool-call enforcement (the crank) ─ */}
      <section style={{ padding: '104px 0', background: '#1C1917', color: '#FAFAF9' }}>
        <C>
          <div className="ep-home-grid-2" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }}>
            <motion.div {...reveal()}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                The developer wedge
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(26px, 3vw, 40px)',
                letterSpacing: -1, lineHeight: 1.12, color: '#FAFAF9', margin: 0,
              }}>
                Wrap dangerous tools.<br />Require receipts.<br />Verify forever.
              </h2>
              <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.72)', lineHeight: 1.72, marginTop: 22, maxWidth: 460 }}>
                MCP is already the tool-action layer for agents. EMILIA is one wrapper around the
                irreversible ones — <em style={{ fontStyle: 'normal', color: '#FAFAF9' }}>release_payment</em>, <em style={{ fontStyle: 'normal', color: '#FAFAF9' }}>delete_repo</em>, <em style={{ fontStyle: 'normal', color: '#FAFAF9' }}>deploy_production</em> — so the
                tool refuses to run without a receipt. Verticals like FinGuard and GovGuard are where
                this is already proving out; the tool-call wrapper is how you adopt it.
              </p>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
                <Link href="/mcp" className="ep-cta" style={{ ...cta.primary }}>MCP guard →</Link>
                <Link href="/quickstart" className="ep-cta-secondary" style={{ ...cta.secondary, color: '#FAFAF9', borderColor: 'rgba(250,250,249,0.3)' }}>Quickstart</Link>
              </div>
            </motion.div>

            <motion.div {...reveal(0.1)} style={{
              fontFamily: font.mono, fontSize: 13, lineHeight: 1.7,
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: radius.base, padding: '24px 26px', color: 'rgba(250,250,249,0.92)', overflowX: 'auto',
            }}>
              <div style={{ color: 'rgba(250,250,249,0.45)' }}>{'// one wrapper around your tool dispatcher'}</div>
              <div><span style={{ color: color.gold }}>import</span> {'{ withMcpGuard }'} <span style={{ color: color.gold }}>from</span> <span style={{ color: '#9BE7A0' }}>'@emilia-protocol/mcp-guard'</span></div>
              <div style={{ height: 12 }} />
              <div><span style={{ color: color.gold }}>const</span> guarded = <span style={{ color: '#9BE7A0' }}>withMcpGuard</span>(handleTool, {'{'}</div>
              <div>&nbsp;&nbsp;annotations: {'{'}</div>
              <div>&nbsp;&nbsp;&nbsp;&nbsp;release_payment:&nbsp;&nbsp;{'{'} irreversible: <span style={{ color: '#9BE7A0' }}>true</span>, action: <span style={{ color: '#9BE7A0' }}>'payment.release'</span> {'}'},</div>
              <div>&nbsp;&nbsp;&nbsp;&nbsp;delete_repo:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{'{'} irreversible: <span style={{ color: '#9BE7A0' }}>true</span>, action: <span style={{ color: '#9BE7A0' }}>'github.repo.delete'</span> {'}'},</div>
              <div>&nbsp;&nbsp;&nbsp;&nbsp;deploy_production: {'{'} irreversible: <span style={{ color: '#9BE7A0' }}>true</span>, action: <span style={{ color: '#9BE7A0' }}>'deploy.production'</span> {'}'},</div>
              <div>&nbsp;&nbsp;{'}'},</div>
              <div>{'}'}) <span style={{ color: 'rgba(250,250,249,0.45)' }}>{'// missing receipt → refused, never a silent pass'}</span></div>
              <div style={{ height: 16 }} />
              <div style={{ color: 'rgba(250,250,249,0.45)' }}>{'// see it in 60s, fully offline:'}</div>
              <div>$ node examples/mcp/payment-server.mjs</div>
            </motion.div>
          </div>
        </C>
      </section>

      {/* ── CONTROL SURFACES ──────────────────────────────────── */}
      <section style={{
        padding: '104px 0',
        background: 'rgba(245,244,240,0.45)',
        borderTop: `1px solid ${color.border}`,
        borderBottom: `1px solid ${color.border}`,
      }}>
        <C>
          <motion.div {...reveal()} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 48 }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Control Surfaces
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(24px, 2.8vw, 38px)',
                letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 540,
              }}>
                When an agent acts on money or someone&rsquo;s livelihood, identity isn&rsquo;t enough
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 480, marginTop: 16 }}>
                The same tool-call wrapper, proven where the stakes are highest. Identity and access tools check <em style={{ fontStyle: 'normal', color: color.t1 }}>who</em> is acting. EMILIA checks whether <em style={{ fontStyle: 'normal', color: color.t1 }}>this exact action</em> should happen &mdash; and binds a named, accountable human to it.{' '}
                <Link href="/why-emilia" style={{ color: color.gold, textDecoration: 'underline', textUnderlineOffset: 3 }}>vs. legacy controls &rarr;</Link>
              </p>
            </div>
            <a href="/use-cases" style={{
              fontFamily: font.mono, fontSize: 10, color: color.t3,
              letterSpacing: 1.5, textTransform: 'uppercase',
              textDecoration: 'none', whiteSpace: 'nowrap', flexShrink: 0,
            }}>
              All use cases →
            </a>
          </motion.div>

          <div className="ep-home-grid-2" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            {SURFACES.map((s, i) => (
              <motion.a
                key={i}
                href={s.href}
                className="ep-card-lift"
                {...reveal(i * 0.07)}
                style={{
                  display: 'flex', flexDirection: 'column',
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderLeft: `3px solid ${s.accent}`,
                  borderRadius: radius.base,
                  padding: '32px 32px 32px 28px',
                  textDecoration: 'none',
                  boxShadow: INSET,
                }}
              >
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, marginBottom: 10, color: color.t1 }}>
                  {s.title}
                </h3>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, flexGrow: 1, marginBottom: 20 }}>
                  {s.body}
                </p>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {s.tags.map(t => (
                    <span key={t} style={{
                      fontFamily: font.mono, fontSize: 9, letterSpacing: 0.8,
                      textTransform: 'uppercase', color: color.t3,
                      padding: '4px 9px',
                      background: 'rgba(245,244,240,0.8)',
                      border: `1px solid ${color.border}`, borderRadius: 2,
                    }}>
                      {t}
                    </span>
                  ))}
                </div>
              </motion.a>
            ))}
          </div>
        </C>
      </section>

      {/* ── DEVELOPER TOOLS ──────────────────────────────────── */}
      <section style={{ padding: '104px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <motion.div {...reveal()} style={{ marginBottom: 48 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
              Implementation Surface
            </div>
            <div className="ep-home-section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 32 }}>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(24px, 2.8vw, 38px)',
                letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 400,
              }}>
                Start anywhere. Go as far as you need.
              </h2>
              <p style={{ fontSize: 14, color: color.t2, maxWidth: 320, textAlign: 'right', lineHeight: 1.65, flexShrink: 0 }}>
                Zero-dependency verification. Interactive playground.<br />Embeddable trust badges. Integrate in minutes.
              </p>
            </div>
          </motion.div>

          <div className="ep-home-grid-tools" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {DEV_TOOLS.map((item, i) => (
              <motion.a key={i} href={item.href} className="ep-card-lift" {...reveal(i * 0.07)} style={{
                background: color.card,
                border: `1px solid ${color.border}`,
                borderTop: `3px solid ${item.accent}`,
                borderRadius: radius.base,
                padding: '24px',
                textDecoration: 'none', display: 'flex', flexDirection: 'column',
                minHeight: 200,
                boxShadow: INSET,
              }}>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, marginBottom: 8, color: color.t1 }}>
                  {item.title}
                </h3>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65, flexGrow: 1, marginBottom: 16 }}>
                  {item.body}
                </p>
                {/* Terminal-style code snippet */}
                <div style={{
                  fontFamily: font.mono, fontSize: 10, letterSpacing: 0.1,
                  background: item.dark ? color.t1 : '#F5F4F0',
                  color: item.dark ? '#B8B4B0' : color.t3,
                  border: item.dark ? 'none' : `1px solid ${color.border}`,
                  padding: '8px 12px', borderRadius: 4,
                  overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis',
                }}>
                  {item.code}
                </div>
              </motion.a>
            ))}
          </div>
        </C>
      </section>

      {/* ── CTA — DARK ───────────────────────────────────────── */}
      <section style={{
        position: 'relative', overflow: 'hidden',
        padding: '104px 0 80px',
        background: '#1C1917',
        borderTop: `3px solid ${color.gold}`,
      }}>
        {/* Subtle dot-grid overlay — more refined than radial gradient */}
        <div aria-hidden style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          backgroundImage: `radial-gradient(circle, rgba(176,141,53,0.06) 1px, transparent 1px)`,
          backgroundSize: '36px 36px',
        }} />
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 720 }}>
            <div style={{
              fontFamily: font.mono, fontSize: 10, letterSpacing: 2,
              textTransform: 'uppercase', color: 'rgba(176,141,53,0.55)',
              marginBottom: 24,
            }}>
              Get started
            </div>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(32px, 4.5vw, 60px)',
              letterSpacing: -2.5, lineHeight: 0.97,
              marginBottom: 16, color: '#FAFAF9',
            }}>
              Three doors.<br />One protocol.
            </h2>
            <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', lineHeight: 1.6, maxWidth: 480, margin: 0 }}>
              Start free and self-hosted, add the managed control plane when you scale, or bring it
              on-prem with the assurance a bank or agency needs to clear you.
            </p>
          </motion.div>

          <motion.div className="ep-home-grid-cta" {...reveal(0.08)} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 44 }}>
            {[
              { kind: 'Developer', accent: color.green, title: 'Start with EP Core', body: 'Free and Apache 2.0. Grab a sandbox API key in 30 seconds — or self-host the SDK, MCP server, and Agent Guard.', label: 'Start free', href: '/signup', btn: { background: '#FAFAF9', color: '#1C1917' } },
              { kind: 'Team', accent: color.blue, title: 'Run it on EP Cloud', body: 'Hosted control plane — managed policy registry, signoff orchestration, and auditor-grade evidence, no infrastructure to run.', label: 'See pricing', href: '/pricing', btn: { background: color.gold, color: '#FAFAF9' } },
              { kind: 'Enterprise', accent: color.gold, title: 'On-prem + assurance', body: 'VPC and air-gapped deployment; SAML/OIDC SSO + SCIM provisioning built in. Sector packs, compliance mappings, SLA. Procurement-ready paperwork.', label: 'Talk to us', href: '/partners', btn: null },
            ].map((d) => (
              <div key={d.kind} style={{ display: 'flex', flexDirection: 'column', border: '1px solid rgba(255,255,255,0.12)', borderTop: `3px solid ${d.accent}`, borderRadius: radius.base, padding: '28px 26px', background: 'rgba(255,255,255,0.02)' }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: d.accent, marginBottom: 12 }}>{d.kind}</div>
                <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 18, color: '#FAFAF9', marginBottom: 8 }}>{d.title}</div>
                <p style={{ fontSize: 14, color: 'rgba(250,250,249,0.6)', lineHeight: 1.6, marginBottom: 22, flexGrow: 1 }}>{d.body}</p>
                <Link
                  href={d.href}
                  className={d.btn ? 'ep-cta' : 'ep-cta-secondary'}
                  style={d.btn
                    ? { ...cta.primary, ...d.btn, width: '100%', justifyContent: 'center' }
                    : { ...cta.secondary, color: 'rgba(250,250,249,0.85)', borderColor: 'rgba(255,255,255,0.18)', width: '100%', justifyContent: 'center' }}
                >
                  {d.label}
                </Link>
              </div>
            ))}
          </motion.div>
        </C>

        {/* Footer data ticker */}
        <div className="ep-home-footer-ticker" aria-hidden style={{
          position: 'absolute', bottom: 0, left: 0, right: 0,
          borderTop: '1px solid rgba(255,255,255,0.07)',
          padding: '10px 32px',
          display: 'flex', justifyContent: 'space-between', gap: 24,
          fontFamily: font.mono, fontSize: 9,
          color: 'rgba(255,255,255,0.22)', letterSpacing: 1.5, textTransform: 'uppercase',
        }}>
          <span>Compliance: NIST AI RMF · EU AI ACT</span>
          <span>Test cases: {TEST_CASES} · all applicable pass</span>
          <span>Formal verification: {TLA_INVARIANTS} theorems · 0 errors</span>
        </div>
      </section>

      <EmailCapture
        eyebrow="Stay in the loop"
        heading="Follow the protocol as it ships."
        sub="Updates on the standard, the verifier, and pilots — sent only when there’s something worth your time. No spam."
      />

      <SiteFooter />
    </div>
  );
}
