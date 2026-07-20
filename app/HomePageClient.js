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
// Interactive homepage experience. Metadata lives in app/page.js so the root
// route can own a self-referencing canonical without making this component
// server-rendered.
//
// Product-led buyer flow. The mission remains, but the first
// viewport names the control, the consequence boundary, and the live proof.
// ─────────────────────────────────────────────────────────────────────────────

// Stats — independently verifiable in the repo:
//   test cases (per lib/proof-stats.json) — `node scripts/generate-proof-stats.mjs`
//   26 TLA+ invariants verified — formal/PROOF_STATUS.md (T1–T26)
//   35 Alloy facts — formal/Alloy/EP.als
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md
//   Apache 2.0 — LICENSE
const TEST_CASES = Number(proofStats.tests?.total || 0).toLocaleString('en-US');
const TAMARIN_OBLIGATIONS = String(proofStats.tamarin?.verifiedObligations || 0);
const TAMARIN_ATTACK_TRACES = String(proofStats.tamarin?.deliberatelyUnsafeCounterexamples || 0);
const SECURITY_CLAIMS = String(proofStats.securityCase?.claims || 0);
const CONFORMANCE_VECTORS = String(proofStats.conformance?.vectors || 0);

const PROBLEMS = [
  { num: '01', title: 'A vendor destination changes',     body: 'The session and operator can both be valid while the beneficiary details are wrong. Authentication does not establish that this exact destination was authorized.' },
  { num: '02', title: 'A beneficiary is replaced',        body: 'A legitimate account-change workflow can still route funds to the wrong party when the material fields are not bound to a fresh approval.' },
  { num: '03', title: 'A production credential rotates', body: 'Valid infrastructure access can authorize a broad class of operations without recording who accepted the exact deploy, scope, and consequence.' },
  { num: '04', title: 'An agent invokes a dangerous tool', body: 'A capable agent can hold valid access and still execute a consequential action for which no accountable human accepted responsibility.' },
];

const SURFACES = [
  { title: 'MCP and privileged tool-call profile', body: 'Wrap release_payment, delete_repo, or deploy_production so the tool returns Receipt Required before mutation. This is the developer adoption path into EMILIA Gate.', href: '/mcp', accent: color.t2, tags: ['MCP', 'DEVELOPER ON-RAMP'] },
  { title: 'Government action profile', body: 'Apply Gate to disbursements, benefit-routing changes, provider enrollment, and accountable overrides at the system-of-record boundary.', href: '/govguard', accent: color.green, tags: ['GATE PROFILE', 'GOVERNMENT'] },
  { title: 'Financial action profile', body: 'Apply the same Gate to wire releases, beneficiary changes, account modifications, and privileged treasury operations before funds move.', href: '/finguard', accent: color.blue, tags: ['GATE PROFILE', 'FINANCIAL'] },
  { title: 'Energy action profile — GRACE', body: 'Apply Gate to bounded curtailment commands and preserve authorization, execution acknowledgment, and effect evidence without claiming meter truth.', href: '/grace', accent: color.green, tags: ['GATE PROFILE', 'ENERGY'] },
  { title: 'Enterprise privileged-action profile', body: 'Require bound authority for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise', accent: color.gold, tags: ['GATE PROFILE', 'ENTERPRISE'] },
  { title: 'Multi-party approval profile', body: 'Use ordered, distinct-human approval when one person is not enough. The same exact action remains bound across every approval in the quorum.', href: '/quorum', accent: color.gold, tags: ['GATE PROFILE', 'QUORUM'] },
];

const STACK_LAYERS = [
  {
    label: 'Prevent',
    title: 'EMILIA Gate',
    body: 'The commercial enforcement product. It challenges, verifies, consumes, and records protected actions at an integrated execution boundary.',
    href: '/gate',
    accent: color.gold,
  },
  {
    label: 'Prove',
    title: 'EMILIA Protocol',
    body: 'The open formats, verifier, vectors, and interoperability substrate. Verification remains reproducible without an EMILIA service.',
    href: '/protocol',
    accent: color.blue,
  },
  {
    label: 'Decide',
    title: 'Approver Apps',
    body: 'The iOS, Android, and embeddable SDK ceremony that locks a device-bound decision to the exact CAID, then tracks quorum, consumption, and outcome.',
    href: '/product/accountable-signoff',
    accent: color.green,
  },
  {
    label: 'Re-perform',
    title: 'Assurance Plane',
    body: 'Managed re-performance, conformance records, continuous evidence, and technical packages for auditors and underwriters.',
    href: '/assurance',
    accent: color.t2,
  },
];

// The customer-facing model: Observe → Verify → Own → Seal. The underlying
// technical layers (Eye → Handshake → Signoff → Commit) live on /protocol; the
// enforcement bundle (Verify + Own + Seal) is packaged for buyers as EMILIA Gate.
const HOW_IT_WORKS = [
  { step: '01', accent: color.green, label: 'Observe',  body: 'Start in observe mode: see which configured actions would require stronger approval — payments, overrides, vendor changes, autonomous AI actions — without blocking them.' },
  { step: '02', accent: color.blue,  label: 'Verify',   body: 'EMILIA Gate sits between approval and execution. Before a high-risk write reaches the system of record, it binds verified actor identity, authority chain, policy-pinned action context, and a one-time nonce.' },
  { step: '03', accent: color.gold,  label: 'Own',      body: 'Where policy requires it, a directory-bound approver signs off on the exact action — on an enrolled device, bound to the exact action hash. Profiles can require initiator exclusion and an ordered, distinct-human quorum before execution.' },
  { step: '04', accent: color.t2,    label: 'Seal',     body: 'Signed, portable authorization evidence is produced for offline verification under the relying party’s pinned inputs with `npm install @emilia-protocol/verify`; deployments can add transparency anchoring when required.' },
];

// Eight bindings — the mechanical reasons a high-risk action can't be faked or
// hidden in an EMILIA-integrated path. Each line names the attack it closes.
const BINDINGS = [
  { n: '01', accent: color.green, label: 'Reject before mutation',   body: 'Consume must succeed before the write runs. An unauthorized action is stopped, not logged after the fact.' },
  { n: '02', accent: color.blue,  label: 'Exact-action binding',     body: 'The receipt binds the action hash, and (with the experimental display-attestation profile) a hash of the rendered context — narrowing the “signed the wrong thing” gap between the bytes signed and what the approver saw.' },
  { n: '03', accent: color.gold,  label: 'Policy binding',           body: 'The receipt binds the policy content that was in force, not just a policy name or version label.' },
  { n: '04', accent: color.green, label: 'Authority binding',        body: 'Holding a credential is separate from holding permission to approve. Gate evaluates the signer against the relying party’s pinned authority sources and scope.' },
  { n: '05', accent: color.blue,  label: 'Class-A enforcement',      body: 'High-risk actions require a passkey / WebAuthn device signoff — or stronger. Weaker assurance fails closed.' },
  { n: '06', accent: color.gold,  label: 'Execution attestation',    body: 'After approval, the executor can attest what it reports running. The verifier detects drift from the approved action without treating that statement as proof of physical truth.' },
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
/** @type {readonly [number, number, number, number]} */
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
      <section className="ep-home-calm-hero" aria-labelledby="home-trust-thesis">
        <C>
          <motion.div className="ep-home-calm-copy" {...heroIn(0)}>
            <div className="ep-home-calm-kicker">
              EMILIA Gate <span>· The Consequence Firewall</span>
            </div>
            <h1 id="home-trust-thesis">Stop consequential machine actions before they become irreversible.</h1>
            <p style={{ fontFamily: font.mono, fontSize: 14, fontWeight: 600, color: color.gold, margin: '22px 0 0' }}>
              Protocol proves. Gate prevents.
            </p>
            <p className="ep-home-calm-lede">
              EMILIA Gate sits immediately before money moves, infrastructure changes, regulated
              records update, or irreversible state changes. It verifies the exact authority and
              evidence the resource owner requires, then consumes accepted authorization once.
            </p>
            <p className="ep-home-calm-detail">
              On every protected path the resource owner fully mediates: no valid evidence, no
              mutation.
            </p>
            <div className="ep-home-calm-actions">
              <Link href="/gate/live" className="ep-home-hero-primary">Open the live Gate</Link>
              <Link href="/gate" className="ep-home-hero-secondary">Review the architecture →</Link>
            </div>
          </motion.div>
        </C>
      </section>

      {/* ── TECHNICAL FOUNDATION — a quiet proof line, not the story ─ */}
      <section className="ep-home-technical-band" aria-label="Technical foundation">
        <C>
          <div className="ep-home-technical-line">
            <div className="ep-home-technical-title">
              <strong>Proof, not promises</strong>
              <span>Machine-checkable</span>
            </div>
            <div className="ep-home-technical-facts">
              <span>IETF Internet-Drafts</span>
              <span>Apache 2.0</span>
              <span>Tamarin: {TAMARIN_OBLIGATIONS} verified lemmas</span>
              <span>{TAMARIN_ATTACK_TRACES} counterexample traces</span>
              <span>{SECURITY_CLAIMS} executable security claims</span>
              <span>{CONFORMANCE_VECTORS} conformance vectors</span>
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
              <Link href="/gate/live" className="ep-cta-secondary" style={cta.secondary}>Run the live Gate →</Link>
            </div>
          </motion.div>
        </C>
      </section>

      {/* ── TWO ENTRY POINTS — adoption and paid deployment ────── */}
      <section style={{ padding: '72px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 780 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>Where to start</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              One Gate. Two practical entry points.
            </h2>
            <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.72, maxWidth: 660, marginTop: 20 }}>
              Developers can protect one privileged MCP tool without changing the rest of the
              agent stack. Regulated operators can begin with one adverse or high-consequence
              workflow at the actual system of record, first in observe mode and then in enforcement.
            </p>
          </motion.div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginTop: 32 }}>
            {[
              {
                label: 'Developer adoption',
                title: 'Return Receipt Required from a dangerous tool.',
                body: 'Protect a privileged MCP call, publish the action requirement, and let the caller retry with exact-action evidence.',
                href: '/mcp',
                cta: 'Protect an MCP tool',
              },
              {
                label: 'Regulated deployment',
                title: 'Put Gate immediately before one consequential decision.',
                body: 'Map the authority rule, capture the human decision through an Approver app, and preserve a record another party can verify.',
                href: '/pilot',
                cta: 'Scope one workflow',
              },
            ].map((entry, index) => (
              <motion.div
                key={entry.label}
                {...reveal(index * 0.07)}
                style={{ borderTop: `2px solid ${index === 0 ? color.blue : color.gold}`, padding: '24px 0 0' }}
              >
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t3 }}>{entry.label}</div>
                <h3 style={{ fontFamily: font.sans, fontSize: 19, lineHeight: 1.35, color: color.t1, margin: '12px 0 10px', maxWidth: 420 }}>{entry.title}</h3>
                <p style={{ fontSize: 14, lineHeight: 1.65, color: color.t2, maxWidth: 460 }}>{entry.body}</p>
                <Link href={entry.href} style={{ fontFamily: font.mono, fontSize: 12, color: color.gold }}>
                  {entry.cta} →
                </Link>
              </motion.div>
            ))}
          </div>
        </C>
      </section>

      {/* ── PRODUCT ARCHITECTURE ───────────────────────────────── */}
      <section style={{ padding: '88px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 760, marginBottom: 36 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>The EMILIA system</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              Four layers. One consequence boundary.
            </h2>
            <p style={{ fontSize: 17, color: color.t2, lineHeight: 1.72, maxWidth: 680, marginTop: 20 }}>
              The product enforces, the apps capture the human decision, the open Protocol
              preserves portable proof, and the Assurance Plane re-performs the record.
            </p>
          </motion.div>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {STACK_LAYERS.map((layer, index) => (
              <motion.a
                key={layer.title}
                href={layer.href}
                className="ep-home-stack-row"
                {...reveal(index * 0.06)}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '120px minmax(180px, 0.65fr) minmax(260px, 1.35fr) 24px',
                  gap: 24,
                  alignItems: 'center',
                  padding: '24px 0',
                  borderBottom: `1px solid ${color.border}`,
                  textDecoration: 'none',
                }}
              >
                <span style={{ fontFamily: font.mono, fontSize: 10, color: layer.accent, letterSpacing: 1.5, textTransform: 'uppercase' }}>{layer.label}</span>
                <strong style={{ fontFamily: font.sans, fontSize: 16, color: color.t1 }}>{layer.title}</strong>
                <span style={{ fontSize: 14, lineHeight: 1.62, color: color.t2 }}>{layer.body}</span>
                <span aria-hidden style={{ color: color.gold }}>→</span>
              </motion.a>
            ))}
          </div>
        </C>
      </section>

      {/* ── INTEROPERABLE CONTROL CHAIN — adjacent layers, not rival claims ─ */}
      <section style={{ padding: '88px 0 0' }}>
        <C>
          <motion.div {...reveal()} style={{ maxWidth: 820 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>Interoperable consequence control</div>
            <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(26px, 3vw, 40px)', letterSpacing: -1, lineHeight: 1.15, color: color.t1, margin: 0 }}>
              Three distinct proofs. One controlled outcome.
            </h2>
            <p style={{ fontSize: 18, color: color.t1, lineHeight: 1.7, maxWidth: 780, marginTop: 22 }}>
              AgentROA governs calls. ORPRG proves policy permitted the effect. EMILIA proves
              exact authorization by an enrolled approver under the relying party&apos;s pinned
              directory, then safely controls consequential outcomes.
            </p>
            <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.72, maxWidth: 700, marginTop: 16 }}>
              CAID correlates native action descriptions only under exact, relying-party-pinned
              mapping profiles. It can return <code>INDETERMINATE</code>, and it never grants
              authority. Gate keeps native verification, material-action matching, human approval,
              and executor-side enforcement separate.
            </p>
            <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.72, maxWidth: 760, marginTop: 16 }}>
              Action Escrow shows the chain on one exact release. If a provider is entered but its
              result cannot be established, Gate refuses blind replay and holds the operation
              indeterminate until authenticated evidence reconciles it. The Assurance Plane then
              re-performs the record against public verification, conformance, and formal-model
              evidence.
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 24 }}>
              <Link href="/action-escrow" className="ep-cta-secondary" style={cta.secondary}>Open Action Escrow →</Link>
              <Link href="/assurance" className="ep-cta-secondary" style={cta.secondary}>Inspect Assurance →</Link>
              <Link href="/observatory" className="ep-cta-secondary" style={cta.secondary}>Review the standards map →</Link>
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
                  EMILIA can require a directory-bound, accountable approver <em style={{ fontStyle: 'normal', fontWeight: 600, color: color.t1 }}>before</em> the
                  protected action runs, then preserve a record an outside party can verify under pinned trust inputs.
                </p>
              </div>
            </motion.div>
          </div>
        </C>
      </section>

      {/* ── PROOF — formal-verification anchor (the spear tip) ─── */}
      <section className="ep-home-proof-section">
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
              receipt binding the exact action, policy, authority, signoff strength, and the executor&rsquo;s execution statement.
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
              On the mediated path: no receipt, no irreversible action.{' '}
              <span style={{ color: color.t2, fontWeight: 400 }}>If it runs, an outside party can verify the recorded authorization under pinned inputs.</span>
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
                tool refuses to run without a receipt. Government, financial, energy, and
                enterprise profiles apply the same Gate to their own action boundaries.
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

      {/* ── GATE SOLUTION PROFILES ───────────────────────────── */}
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
                Gate solution profiles
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(24px, 2.8vw, 38px)',
                letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 540,
              }}>
                One enforcement product, adapted to each action boundary.
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.7, maxWidth: 480, marginTop: 16 }}>
                These are profiles, not separate products. Each supplies action types, material
                fields, assurance floors, and integration guidance to the same EMILIA Gate.{' '}
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
              Three ways in.<br />One consequence boundary.
            </h2>
            <p style={{ fontSize: 16, color: 'rgba(250,250,249,0.6)', lineHeight: 1.6, maxWidth: 480, margin: 0 }}>
              Protect one tool, deploy the managed Gate, or re-perform the evidence. The open
              Protocol stays underneath every path.
            </p>
          </motion.div>

          <motion.div className="ep-home-grid-cta" {...reveal(0.08)} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 44 }}>
            {[
              { kind: 'Developer', accent: color.green, title: 'Protect an MCP tool', body: 'Use the open packages to return Receipt Required before one privileged tool call. Self-hosted verification stays free.', label: 'Open the MCP guide', href: '/mcp', btn: { background: '#FAFAF9', color: '#1C1917' } },
              { kind: 'Operator', accent: color.blue, title: 'Deploy EMILIA Gate', body: 'Managed policy, approval orchestration, evidence operations, and enterprise deployment around one consequential workflow.', label: 'See Gate pricing', href: '/pricing', btn: { background: color.gold, color: '#FAFAF9' } },
              { kind: 'Assurance', accent: color.gold, title: 'Re-perform the record', body: 'Managed re-performance, conformance records, continuous evidence, and technical packages for your auditor or underwriter.', label: 'Explore Assurance', href: '/assurance', btn: null },
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
          <span>Open Protocol: Apache 2.0 · IETF Internet-Drafts</span>
          <span>Test cases: {TEST_CASES} · all applicable pass</span>
          <span>Tamarin: {TAMARIN_OBLIGATIONS} verified lemmas · {TAMARIN_ATTACK_TRACES} attack traces</span>
        </div>
      </section>

      <EmailCapture
        eyebrow="Stay in the loop"
        heading="Follow Gate and the Protocol as they ship."
        sub="Product releases, open verification work, and pilot evidence — sent only when there’s something worth your time. No spam."
      />

      <SiteFooter />
    </div>
  );
}
