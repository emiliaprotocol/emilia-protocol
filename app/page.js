'use client';

import Link from 'next/link';
import { motion } from 'motion/react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import CrashTestDemo from '@/components/CrashTestDemo';
import ProofBlock from '@/components/ProofBlock';
import { styles, cta, color, font, radius } from '@/lib/tokens';

// ─────────────────────────────────────────────────────────────────────────────
// Homepage — buyer-facing flow.
// The technical depth (8 binding properties, 4-step rollout schematic, MFA
// comparison, DEPLOY_LAYERS table, protocol-properties grid) lives one click
// away on /protocol. The homepage's only job is to convert a cold reader
// into someone who clicks "See Live Example" or "Request Pilot" within 30s.
// ─────────────────────────────────────────────────────────────────────────────

// Stats — independently verifiable in the repo:
//   3,200+ tests (static it/test count; parameterized runs exceed it) — `npx vitest run`
//   26 TLA+ invariants verified — formal/PROOF_STATUS.md (T1–T26)
//   35 Alloy facts — formal/Alloy/EP.als
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md
//   Apache 2.0 — LICENSE
const STATS = [
  { value: '3,200+',    label: 'Automated Tests',  sub: 'static count — runs expand it', accent: color.t1    },
  { value: '26',        label: 'TLA+ Theorems',    sub: 'TLC 2.19, zero errors',         accent: color.blue  },
  { value: '35',        label: 'Alloy Facts',       sub: '15 assertions verified',        accent: color.gold  },
  { value: '3',         label: 'Independent Verifiers', sub: 'JS · Python · Go, proven to agree', accent: color.t1 },
  { value: 'Apache 2.0', label: 'License',          sub: 'Open specification',            accent: color.green },
];

const PROBLEMS = [
  { num: '01', title: 'The vendor wire that passed',     body: 'A payment destination changed inside a valid session, approved through the normal process, to a vendor whose bank details quietly moved. Business email compromise — not a hack.' },
  { num: '02', title: 'The beneficiary swap',            body: 'A remittance beneficiary was updated through approved channels. The system saw a legitimate change and let the money go.' },
  { num: '03', title: 'The production credential',       body: 'An infrastructure credential was rotated and a deploy was pushed without action-bound authorization. Every access was valid; the blast radius was not.' },
  { num: '04', title: 'The agent that executed',         body: 'An AI agent with broad tool access ran a high-risk, irreversible action. No human assumed responsibility for that specific operation.' },
];

const SURFACES = [
  { title: 'AI Agent Action Governance',        body: 'Gate every autonomous agent action behind a verified trust ceremony before any irreversible real-world execution. One line of code; works with any framework.', href: '/agent-guard',         accent: color.t2,   tags: ['AGENTIC AI', 'HUMAN-IN-LOOP']    },
  { title: 'Financial — Money Movement',         body: 'Ceremony-grade authorization on wire releases, beneficiary changes, account modifications, and privileged treasury actions before funds move.', href: '/finguard',           accent: color.blue,  tags: ['BEC PREVENTION', 'SOX-READY']    },
  { title: 'Government — Benefit Integrity',     body: 'Bind identity, authority, and action context before a benefit determination, redirect, or override. Accountable decisions, due process proven.', href: '/govguard',           accent: color.green, tags: ['NIST AI RMF', 'EU AI ACT']       },
  { title: 'Enterprise Privileged Actions',      body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise', accent: color.gold,  tags: ['ZERO TRUST', 'PAM LAYER']        },
];

// Three-step product story. The four-layer technical model (Eye → Handshake →
// Signoff → Commit) lives on /protocol; the homepage shows the customer-facing
// version: a high-risk action arrives, EP demands proof, EP issues a receipt.
const HOW_IT_WORKS = [
  { step: '01', accent: color.green, label: 'Intercept',           body: 'EP sits between approval and execution. Payments, overrides, vendor changes, autonomous AI actions — every high-risk write is gated before it reaches the system of record.' },
  { step: '02', accent: color.blue,  label: 'Require Proof',       body: 'Verified actor identity. Verified authority chain. Policy-pinned action context. One-time nonce. Where policy requires it: a named, accountable human signoff bound to the exact action hash.' },
  { step: '03', accent: color.gold,  label: 'Generate Authorization Receipt', body: 'A signed, Merkle-anchored receipt is produced. Auditor-grade evidence packet at /api/v1/trust-receipts/{id}/evidence. Publicly verifiable with `npm install @emilia-protocol/verify`.' },
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

// Scroll-triggered fade-up: used for every section below the hero.
// viewport.once:true means it animates once and stays visible.
const reveal = (delay = 0) => ({
  initial: { opacity: 0, y: 18 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-40px' },
  transition: { duration: 0.58, delay, ease: EASE },
});

// Above-fold hero elements: triggered by animate (not scroll) so they play
// immediately on load regardless of viewport position.
const heroIn = (delay = 0) => ({
  initial: { opacity: 0, y: 14 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.6, delay, ease: EASE },
});

export default function HomePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ─────────────────────────────────────────────── */}
      <section style={{ paddingTop: 120 }}>
        <C>
          {/* Metadata strip — flat, mono, no widget chrome */}
          <motion.div {...heroIn(0)} style={{
            display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap',
            marginBottom: 52, paddingBottom: 24,
            borderBottom: `1px solid ${color.border}`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: color.gold, display: 'inline-block', flexShrink: 0 }} />
              <span style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase' }}>
                Formally verified · Apache 2.0
              </span>
            </div>
            <span style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 0.5 }}>
              26 TLA+ theorems · 35 Alloy facts
            </span>
            <span style={{ flex: 1 }} />
            <a href="/spec" style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', textDecoration: 'none' }}>
              View Spec →
            </a>
            <a href="/security" style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase', textDecoration: 'none' }}>
              Trust Model →
            </a>
          </motion.div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.88fr', gap: 72, alignItems: 'start' }}>
            {/* Left — editorial headline */}
            <motion.div {...heroIn(0.06)}>
              <div style={{
                fontFamily: font.mono, fontSize: 11, fontWeight: 500,
                letterSpacing: 2.5, textTransform: 'uppercase',
                color: color.gold, marginBottom: 28,
              }}>
                The Accountability Layer for AI Agents
              </div>

              <h1 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(48px, 6vw, 82px)',
                letterSpacing: -3, lineHeight: 0.95,
                color: color.t1, margin: '0 0 32px',
              }}>
                Every AI action needs an{' '}
                <em style={{ fontStyle: 'normal', color: color.gold }}>owner.</em>
              </h1>

              <p style={{
                fontSize: 17, color: color.t2,
                maxWidth: 470, lineHeight: 1.72, margin: '0 0 40px',
              }}>
                AI can reason, plan, and execute — but it can&rsquo;t be accountable. Before an agent
                does anything irreversible, EMILIA assigns a named human owner who approves the exact
                action on their own device. So when someone asks{' '}
                <em style={{ fontStyle: 'normal', color: color.t1, fontWeight: 600 }}>who approved this?</em>{' '}
                — there is always an answer. One neither a compromised agent nor EMILIA itself can forge.
              </p>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <Link href="/try" className="ep-cta" style={cta.primary}>Approve one yourself with Face ID →</Link>
                <Link href="/demo" className="ep-cta-secondary" style={cta.secondary}>Or just watch one get stopped</Link>
              </div>

              {/* Inline proof metrics — editorial data strip */}
              <div style={{
                display: 'flex', gap: 36, marginTop: 52,
                paddingTop: 28, borderTop: `1px solid ${color.border}`,
              }}>
                {[
                  { val: '3,500', label: 'Tests Passing' },
                  { val: '26',    label: 'TLA+ Theorems' },
                  { val: '85',    label: 'Red Team Cases' },
                ].map(({ val, label }) => (
                  <div key={label}>
                    <div style={{ fontFamily: font.sans, fontSize: 24, fontWeight: 700, color: color.t1, letterSpacing: -0.5, lineHeight: 1 }}>
                      {val}
                    </div>
                    <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase', marginTop: 7 }}>
                      {label}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* Right — live crash test */}
            <motion.div {...heroIn(0.12)} style={{ paddingTop: 12 }}>
              <CrashTestDemo />
            </motion.div>
          </div>
        </C>
      </section>

      {/* ── STATS STRIP — left-bar pattern (Fingerprint reference) ─ */}
      <motion.div {...reveal()} style={{
        borderTop: `1px solid ${color.border}`,
        borderBottom: `1px solid ${color.border}`,
        background: 'rgba(245,244,240,0.45)',
        marginTop: 96,
      }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)' }}>
            {STATS.map((s, i) => (
              <div key={i} style={{
                display: 'flex', gap: 14, alignItems: 'flex-start',
                padding: '28px 24px',
                paddingLeft: i === 0 ? 0 : 24,
                borderRight: i < STATS.length - 1 ? `1px solid ${color.border}` : 'none',
              }}>
                {/* Left accent bar */}
                <div style={{
                  width: 3, height: 38, borderRadius: 2,
                  background: s.accent, flexShrink: 0, marginTop: 1,
                }} />
                <div>
                  <div style={{
                    fontFamily: font.sans, fontSize: 26, fontWeight: 700,
                    color: s.accent, letterSpacing: -0.5, lineHeight: 1, marginBottom: 7,
                  }}>
                    {s.value}
                  </div>
                  <div style={{ fontFamily: font.mono, fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', color: color.t3, lineHeight: 1.4 }}>
                    {s.label}
                  </div>
                  <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 0.3, marginTop: 2, opacity: 0.7 }}>
                    {s.sub}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </C>
      </motion.div>

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

      {/* ── THE PROBLEM ──────────────────────────────────────── */}
      <section style={{ padding: '104px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '5fr 7fr', gap: 80, alignItems: 'start' }}>
            {/* Sticky editorial label */}
            <motion.div {...reveal()} style={{ position: 'sticky', top: 96 }}>
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
                Identity and access tools check <em style={{ fontStyle: 'normal', color: color.t1 }}>who</em> is acting. EMILIA checks whether <em style={{ fontStyle: 'normal', color: color.t1 }}>this exact action</em> should happen &mdash; and binds a named, accountable human to it.{' '}
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

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 32 }}>
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

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
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

          <motion.div {...reveal(0.08)} style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 44 }}>
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
        <div aria-hidden style={{
          position: 'absolute', bottom: 0, left: 0, right: 0,
          borderTop: '1px solid rgba(255,255,255,0.07)',
          padding: '10px 32px',
          display: 'flex', justifyContent: 'space-between', gap: 24,
          fontFamily: font.mono, fontSize: 9,
          color: 'rgba(255,255,255,0.22)', letterSpacing: 1.5, textTransform: 'uppercase',
        }}>
          <span>Compliance: NIST AI RMF · EU AI ACT</span>
          <span>Tests: 3,500 passing · 0 failing</span>
          <span>Formal verification: 26 theorems · 0 errors</span>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
