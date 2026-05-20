'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import HeroStatic from '@/components/HeroStatic';
import { styles, cta, color, font, radius } from '@/lib/tokens';

// ─────────────────────────────────────────────────────────────────────────────
// Homepage — buyer-facing flow.
// The technical depth (8 binding properties, 4-step rollout schematic, MFA
// comparison, DEPLOY_LAYERS table, protocol-properties grid) lives one click
// away on /protocol. The homepage's only job is to convert a cold reader
// into someone who clicks "See Live Example" or "Request Pilot" within 30s.
// ─────────────────────────────────────────────────────────────────────────────

// Stats — independently verifiable in the repo:
//   3,483 tests / 132 files — `npx vitest run` summary
//   26 TLA+ invariants verified — formal/PROOF_STATUS.md (T1–T26)
//   35 Alloy facts — formal/Alloy/EP.als
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md
//   Apache 2.0 — LICENSE
const STATS = [
  { value: '3,483',     label: 'Automated Tests',  sub: '132 test files',                accent: color.t1    },
  { value: '26',        label: 'TLA+ Theorems',    sub: 'TLC 2.19, zero errors',         accent: color.blue  },
  { value: '35',        label: 'Alloy Facts',       sub: '15 assertions verified',        accent: color.gold  },
  { value: '85',        label: 'Red Team Cases',    sub: 'Cataloged in repo',             accent: color.t1    },
  { value: 'Apache 2.0', label: 'License',          sub: 'Open specification',            accent: color.green },
];

const PROBLEMS = [
  { num: '01', title: 'Benefit payment redirection',        body: 'An authorized operator changes a payment destination inside a valid session. No control catches the action itself.' },
  { num: '02', title: 'Beneficiary and remittance changes',  body: 'A wire transfer beneficiary is swapped through approved channels. The system sees a legitimate update, not fraud.' },
  { num: '03', title: 'Privileged infrastructure actions',   body: 'A production credential is rotated or a deployment is pushed without action-bound authorization. Access was valid.' },
  { num: '04', title: 'AI agent destructive execution',      body: 'An agent with broad tool access executes a high-risk action. No human assumed responsibility for the specific operation.' },
];

const SURFACES = [
  { title: 'Government Fraud Prevention',       body: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.', href: '/use-cases/government', accent: color.green, tags: ['NIST AI RMF', 'EU AI ACT']      },
  { title: 'Financial Infrastructure Controls', body: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.', href: '/use-cases/financial', accent: color.blue,  tags: ['SOX-READY', 'BEC PREVENTION']   },
  { title: 'Enterprise Privileged Actions',     body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise', accent: color.gold,  tags: ['ZERO TRUST', 'PAM LAYER']        },
  { title: 'AI/Agent Execution Governance',     body: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.', href: '/use-cases/ai-agent',  accent: color.t2,   tags: ['AGENTIC AI', 'HUMAN-IN-LOOP']    },
];

// Three-step product story. The four-layer technical model (Eye → Handshake →
// Signoff → Commit) lives on /protocol; the homepage shows the customer-facing
// version: a high-risk action arrives, EP demands proof, EP issues a receipt.
const HOW_IT_WORKS = [
  { step: '01', accent: color.green, label: 'Intercept',           body: 'EP sits between approval and execution. Payments, overrides, vendor changes, autonomous AI actions — every high-risk write is gated before it reaches the system of record.' },
  { step: '02', accent: color.blue,  label: 'Require Proof',       body: 'Verified actor identity. Verified authority chain. Policy-pinned action context. One-time nonce. Where policy requires it: a named, accountable human signoff bound to the exact action hash.' },
  { step: '03', accent: color.gold,  label: 'Generate Trust Receipt', body: 'A signed, Merkle-anchored receipt is produced. Auditor-grade evidence packet at /api/v1/trust-receipts/{id}/evidence. Publicly verifiable with `npm install @emilia-protocol/verify`.' },
];

const DEV_TOOLS = [
  { title: 'Verify Package',   body: 'Zero-dependency offline receipt verification. Ed25519 + Merkle proofs. Just math, no EP server required.',                           code: 'npm install @emilia-protocol/verify', href: 'https://www.npmjs.com/package/@emilia-protocol/verify', accent: color.green, dark: true  },
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

function useReveal() {
  useEffect(() => {
    const all = Array.from(document.querySelectorAll('.ep-reveal'));
    if (!all.length) return;

    // --- Split: on-screen vs below-fold -----------------------------------
    // Elements already in (or very near) the viewport must NEVER be hidden.
    // Only elements clearly below the fold get the 'will-reveal' class (which
    // is what sets opacity:0 in CSS). This makes content visible-by-default
    // on SSR/no-JS and prevents a blank page if IO fires slowly.
    const vH = window.innerHeight;
    const below = all.filter(el => el.getBoundingClientRect().top > vH - 60);
    below.forEach(el => el.classList.add('will-reveal'));

    if (!below.length) return;

    // --- IntersectionObserver for below-fold reveals ----------------------
    const obs = new IntersectionObserver(
      (entries) => entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.remove('will-reveal');
          e.target.classList.add('is-visible');
          obs.unobserve(e.target);
        }
      }),
      { rootMargin: '0px 0px -40px 0px', threshold: 0 }
    );
    below.forEach(el => obs.observe(el));

    // --- Hard fallback: 2s guarantee --------------------------------------
    // If IO never fires (browser quirk, extension interference, etc.), clear
    // will-reveal so content is never permanently invisible.
    const t = setTimeout(() => {
      below.forEach(el => {
        el.classList.remove('will-reveal');
        el.classList.add('is-visible');
      });
    }, 2000);

    return () => { obs.disconnect(); clearTimeout(t); };
  }, []);
}

export default function HomePage() {
  useReveal();

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ─────────────────────────────────────────────── */}
      <section style={{ paddingTop: 120 }}>
        <C>
          {/* Metadata strip — flat, mono, no widget chrome */}
          <div className="ep-hero-badge" style={{
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
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.88fr', gap: 72, alignItems: 'start' }}>
            {/* Left — editorial headline */}
            <div className="ep-hero-text">
              <div style={{
                fontFamily: font.mono, fontSize: 11, fontWeight: 500,
                letterSpacing: 2.5, textTransform: 'uppercase',
                color: color.gold, marginBottom: 28,
              }}>
                Pre-Execution Trust Layer
              </div>

              <h1 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(52px, 6.5vw, 88px)',
                letterSpacing: -3.5, lineHeight: 0.92,
                color: color.t1, margin: '0 0 32px',
              }}>
                Fraud stops{' '}
                <em style={{ fontStyle: 'normal', color: color.gold }}>before</em>{' '}
                money moves.
              </h1>

              <p style={{
                fontSize: 17, color: color.t2,
                maxWidth: 440, lineHeight: 1.72, margin: '0 0 40px',
              }}>
                Every high-risk action — payments, overrides, approvals — is
                cryptographically verified before execution. No trust.
                No assumptions. Only proof.
              </p>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <a href="/partners" className="ep-cta" style={cta.primary}>Request Pilot</a>
                <Link href="/r/example" className="ep-cta-secondary" style={cta.secondary}>See Live Example</Link>
              </div>

              {/* Inline proof metrics — editorial data strip */}
              <div style={{
                display: 'flex', gap: 36, marginTop: 52,
                paddingTop: 28, borderTop: `1px solid ${color.border}`,
              }}>
                {[
                  { val: '3,483', label: 'Tests Passing' },
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
            </div>

            {/* Right — protocol schematic */}
            <div className="ep-hero-visual" style={{ paddingTop: 12 }}>
              <HeroStatic />
            </div>
          </div>
        </C>
      </section>

      {/* ── STATS STRIP — left-bar pattern (Fingerprint reference) ─ */}
      <div className="ep-reveal" style={{
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
      </div>

      {/* ── HOW IT WORKS — editorial stepped rows ─────────────── */}
      <section style={{ padding: '104px 0 80px', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 64 }}>
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
          </div>

          {/* Steps as horizontal editorial rows — no card boxes */}
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {HOW_IT_WORKS.map((item, i) => (
              <div
                key={i}
                className={`ep-reveal ep-stagger-${i + 1}`}
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
              </div>
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
            <div className="ep-reveal" style={{ position: 'sticky', top: 96 }}>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Structural Vulnerabilities
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(22px, 2.5vw, 34px)',
                letterSpacing: -0.75, lineHeight: 1.18, color: color.t1, marginBottom: 20,
              }}>
                Built for approved-looking workflows where ordinary auth fails
              </h2>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.72 }}>
                Fraud is moving inside valid sessions. Authenticated users,
                legitimate tools, approved channels — the attack surface is
                the action itself.
              </p>
            </div>

            {/* Problem rows — ep-problem-row gives left-bar gold hover */}
            <div className="ep-reveal ep-stagger-2" style={{ borderTop: `1px solid ${color.border}` }}>
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
            </div>
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
          <div className="ep-reveal" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 48 }}>
            <div>
              <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 16 }}>
                Control Surfaces
              </div>
              <h2 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(24px, 2.8vw, 38px)',
                letterSpacing: -1, lineHeight: 1.15, color: color.t1, maxWidth: 480,
              }}>
                Built for the workflows where weak authorization causes real damage
              </h2>
            </div>
            <a href="/use-cases" style={{
              fontFamily: font.mono, fontSize: 10, color: color.t3,
              letterSpacing: 1.5, textTransform: 'uppercase',
              textDecoration: 'none', whiteSpace: 'nowrap', flexShrink: 0,
            }}>
              All use cases →
            </a>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            {SURFACES.map((s, i) => (
              <a
                key={i}
                href={s.href}
                className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
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
              </a>
            ))}
          </div>
        </C>
      </section>

      {/* ── DEVELOPER TOOLS ──────────────────────────────────── */}
      <section style={{ padding: '104px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 48 }}>
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
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {DEV_TOOLS.map((item, i) => (
              <a key={i} href={item.href} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={{
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
              </a>
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
          <div className="ep-reveal" style={{ maxWidth: 640 }}>
            <div style={{
              fontFamily: font.mono, fontSize: 10, letterSpacing: 2,
              textTransform: 'uppercase', color: 'rgba(176,141,53,0.55)',
              marginBottom: 24,
            }}>
              Initiate Architecture Review
            </div>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(32px, 4.5vw, 60px)',
              letterSpacing: -2.5, lineHeight: 0.97,
              marginBottom: 44, color: '#FAFAF9',
            }}>
              Enforce trust before<br />high-risk action
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
              <Link href="/r/example" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917' }}>
                See Live Example
              </Link>
              <a href="/protocol" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#FAFAF9' }}>
                Read the Protocol
              </a>
              <a href="/partners" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.8)', borderColor: 'rgba(255,255,255,0.15)' }}>
                Request Pilot
              </a>
            </div>
          </div>
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
          <span>Tests: 3,483 passing · 0 failing</span>
          <span>Formal verification: 26 theorems · 0 errors</span>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
