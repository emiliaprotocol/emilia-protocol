'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const HeroAnimation = dynamic(() => import('@/components/HeroAnimation'), {
  ssr: false,
  loading: () => (
    <div style={{ width: '100%', aspectRatio: '600/560', borderRadius: 6, border: `1px solid ${color.border}`, background: '#F5F5F4' }} />
  ),
});

// ─────────────────────────────────────────────────────────────────────────────
// Homepage — buyer-facing flow.
// The technical depth (8 binding properties, 4-step rollout schematic, MFA
// comparison, DEPLOY_LAYERS table, protocol-properties grid) lives one click
// away on /protocol. The homepage's only job is to convert a cold reader
// into someone who clicks "See Live Example" or "Request Pilot" within 30s.
// ─────────────────────────────────────────────────────────────────────────────

// Stats below are the source-of-truth numbers as of 2026-04-30. Each value
// is independently verifiable in the repo:
//   3,483 tests / 132 files — `npx vitest run` summary
//   26 TLA+ invariants verified — formal/PROOF_STATUS.md (T1–T26)
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md line 1
//   Apache 2.0 — LICENSE
//   Internal review — docs/security/AUDIT_METHODOLOGY.md (self-administered)
//
// Note: deliberately removed "100/100" framing. External procurement
// reviewers treat self-awarded perfect scores as a marketing claim, not
// an assurance signal. Lead with reproducible evidence instead — the
// methodology link is the credibility carrier.
const STATS = [
  { value: '3,483',     label: 'Automated Tests',  sub: '132 test files',           accent: color.t1 },
  { value: '26',        label: 'Theorems Proven',  sub: 'TLC 2.19, zero errors',    accent: color.blue },
  { value: '85',        label: 'Red Team Cases',   sub: 'Cataloged in repo',        accent: color.t1 },
  { value: 'Reviewed',  label: 'Internal Audit',   sub: 'Methodology public · Apr 2', accent: color.gold },
  { value: 'Apache 2.0', label: 'License',         sub: 'Open specification',       accent: color.green },
];

const PROBLEMS = [
  { num: '01', title: 'Benefit payment redirection', body: 'An authorized operator changes a payment destination inside a valid session. No control catches the action itself.' },
  { num: '02', title: 'Beneficiary and remittance changes', body: 'A wire transfer beneficiary is swapped through approved channels. The system sees a legitimate update, not fraud.' },
  { num: '03', title: 'Privileged infrastructure actions', body: 'A production credential is rotated or a deployment is pushed without action-bound authorization. Access was valid.' },
  { num: '04', title: 'AI agent destructive execution', body: 'An agent with broad tool access executes a high-risk action. No human assumed responsibility for the specific operation.' },
];

const SURFACES = [
  { title: 'Government Fraud Prevention',       body: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.', href: '/use-cases/government', accent: color.green,  tags: ['NIST AI RMF', 'EU AI ACT'] },
  { title: 'Financial Infrastructure Controls', body: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.', href: '/use-cases/financial', accent: color.blue,   tags: ['SOX-READY', 'BEC PREVENTION'] },
  { title: 'Enterprise Privileged Actions',     body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise', accent: color.gold,   tags: ['ZERO TRUST', 'PAM LAYER'] },
  { title: 'AI/Agent Execution Governance',     body: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.', href: '/use-cases/ai-agent',  accent: color.t2,    tags: ['AGENTIC AI', 'HUMAN-IN-LOOP'] },
];

// Three-step product story for the homepage. The four-layer technical
// model (Eye → Handshake → Signoff → Commit) lives on /protocol; what
// the homepage shows is the customer-facing version: a high-risk
// action arrives, EP demands proof, EP issues a receipt. Same plumbing,
// non-technical framing.
const HOW_IT_WORKS = [
  { step: '01', color: color.green, label: 'Intercept',           body: 'EP sits between approval and execution. Payments, overrides, vendor changes, autonomous AI actions — every high-risk write is gated before it reaches the system of record.' },
  { step: '02', color: color.blue,  label: 'Require Proof',       body: 'Verified actor identity. Verified authority chain. Policy-pinned action context. One-time nonce. Where policy requires it: a named, accountable human signoff bound to the exact action hash.' },
  { step: '03', color: color.gold,  label: 'Generate Trust Receipt', body: 'A signed, Merkle-anchored receipt is produced. Auditor-grade evidence packet at /api/v1/trust-receipts/{id}/evidence. Publicly verifiable with `npm install @emilia-protocol/verify`.' },
];

const DEV_TOOLS = [
  { title: 'Verify Package',    body: 'Zero-dependency offline receipt verification. Ed25519 + Merkle proofs. Just math, no EP server required.', code: 'npm install @emilia-protocol/verify', href: 'https://www.npmjs.com/package/@emilia-protocol/verify', accent: color.green,  codeLight: false },
  { title: 'Trust Playground',  body: 'Walk through the EP lifecycle interactively. Create entities, issue receipts, run handshakes — all from one page.', code: '/playground', href: '/playground', accent: color.blue,   codeLight: true },
  { title: 'Trust Explorer',    body: 'Verify any receipt, proof, or entity. Like Etherscan for trust. Public, transparent, cryptographically verified.', code: '/explorer', href: '/explorer', accent: color.gold,   codeLight: true },
  { title: 'Embed Widget',      body: 'Drop a trust badge on any page. One script tag, one web component. Live data from the EP operator.', code: '<ep-trust-badge />', href: '/adopt', accent: color.t2,    codeLight: true },
];

function tagChip(label) {
  return (
    <span key={label} style={{
      fontFamily: font.mono, fontSize: 9, letterSpacing: 0.8,
      textTransform: 'uppercase', color: color.t3,
      padding: '4px 9px', background: '#F5F4F0',
      border: `1px solid ${color.border}`, borderRadius: 2,
      display: 'inline-block',
    }}>{label}</span>
  );
}

const C = ({ children }) => (
  <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>{children}</div>
);

function Eyebrow({ children, light }) {
  return (
    <div style={{
      fontFamily: font.mono, fontSize: 10, fontWeight: 500,
      letterSpacing: 2, textTransform: 'uppercase',
      color: light ? 'rgba(176,141,53,0.7)' : color.gold,
      marginBottom: 14,
    }}>{children}</div>
  );
}

function SectionTitle({ children, light }) {
  return (
    <h2 style={{
      fontFamily: font.sans, fontWeight: 700,
      fontSize: 'clamp(24px, 3vw, 36px)',
      letterSpacing: -0.5, lineHeight: 1.2,
      marginBottom: 16,
      color: light ? '#FAFAF9' : color.t1,
    }}>{children}</h2>
  );
}

function SectionDesc({ children, light }) {
  return (
    <p style={{
      fontSize: 16,
      color: light ? 'rgba(250,250,249,0.6)' : color.t2,
      maxWidth: 560, lineHeight: 1.7,
    }}>{children}</p>
  );
}

function useReveal() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      (entries) => entries.forEach(e => {
        if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); }
      }),
      { rootMargin: '-60px', threshold: 0.05 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);
}

const ALT = { background: '#F5F4F0', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` };

export default function HomePage() {
  useReveal();

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ─────────────────────────────────────────────── */}
      <section style={{ padding: '112px 0 0' }}>
        <C>
          {/* Structural certification badge */}
          <div className="ep-hero-badge" style={{ marginBottom: 36 }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 12,
              padding: '7px 16px 7px 12px',
              border: `1px solid ${color.border}`,
              borderRadius: 2,
              background: '#F5F4F0',
              boxShadow: `0 0 0 1px ${color.border}, 0 2px 4px rgba(12,10,9,0.02)`,
            }}>
              <span className="ep-pulse-dot" style={{
                display: 'inline-block', width: 6, height: 6,
                borderRadius: '50%', background: color.gold, flexShrink: 0,
              }} />
              <div>
                <div style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 600, color: color.t1, letterSpacing: 0.5, lineHeight: 1.2 }}>
                  Internal Protocol Assurance Review
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 0.5, lineHeight: 1.2, marginTop: 1 }}>
                  April 2, 2026 · <a href="/docs/security/AUDIT_METHODOLOGY.md" style={{ color: 'inherit', textDecoration: 'underline' }}>Methodology &amp; scope (public)</a>
                </div>
              </div>
              <div style={{ marginLeft: 4, paddingLeft: 12, borderLeft: `1px solid ${color.border}` }}>
                {/* Display "INTERNAL" not "VERIFIED" — the review is self-
                    administered per docs/security/AUDIT_METHODOLOGY.md.
                    The previous "100/100" framing was removed because federal
                    procurement teams treat self-awarded perfect scores as
                    marketing, not assurance. The methodology link is the
                    credibility carrier; the badge points readers at it. */}
                <div style={{ fontFamily: font.mono, fontSize: 9, color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 600 }}>INTERNAL</div>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.9fr', gap: 80, alignItems: 'center' }}>
            <div className="ep-hero-text">
              <div style={{
                fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                letterSpacing: 2, textTransform: 'uppercase',
                color: color.gold, marginBottom: 20,
              }}>Pre-Execution Trust Layer</div>

              <h1 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(44px, 5.5vw, 72px)',
                letterSpacing: -2.5, lineHeight: 0.96,
                marginBottom: 28, color: color.t1,
              }}>
                Fraud stops{' '}
                <em style={{ fontStyle: 'normal', color: color.gold }}>before</em>{' '}
                money moves.
              </h1>

              <p style={{
                fontSize: 17, color: color.t2,
                maxWidth: 460, lineHeight: 1.7, marginBottom: 36,
              }}>
                Every high-risk action — payments, overrides, approvals — is cryptographically verified before execution. No trust. No assumptions. Only proof.
              </p>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <a href="/partners" className="ep-cta"          style={cta.primary}>Request Pilot</a>
                <Link href="/r/example" className="ep-cta-secondary" style={cta.secondary}>See Live Example</Link>
                <a href="/protocol" className="ep-cta-ghost"    style={cta.ghost}>Read the Protocol →</a>
              </div>
            </div>

            <div className="ep-hero-visual">
              <HeroAnimation />
            </div>
          </div>
        </C>
      </section>

      {/* ── STATS SCORECARD ──────────────────────────────────── */}
      <div className="ep-reveal" style={{
        borderTop: `1px solid ${color.border}`,
        borderBottom: `1px solid ${color.border}`,
        background: 'rgba(245,244,240,0.5)',
        marginTop: 80,
      }}>
        <C>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(5, 1fr)',
          }}>
            {STATS.map((s, i) => (
              <div key={i} style={{
                padding: '28px 0',
                borderRight: i < STATS.length - 1 ? `1px solid ${color.border}` : 'none',
                paddingLeft: i === 0 ? 0 : 24,
                paddingRight: 24,
              }}>
                <div style={{ fontFamily: font.mono, fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: color.gold, marginBottom: 8 }}>{s.label}</div>
                <div style={{ fontFamily: font.sans, fontSize: 28, fontWeight: 600, color: s.accent, letterSpacing: -0.5, marginBottom: 4 }}>{s.value}</div>
                <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 0.3 }}>{s.sub}</div>
              </div>
            ))}
          </div>
        </C>
      </div>

      {/* ── HOW IT WORKS — 3-step product story ───────────────── */}
      <section style={{ padding: '96px 0 80px', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40, textAlign: 'center' }}>
            <Eyebrow>How EMILIA Works</Eyebrow>
            <SectionTitle>A control layer between approval and execution.</SectionTitle>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, position: 'relative' }}>
            {HOW_IT_WORKS.map((item, i) => (
              <div
                key={i}
                className="ep-card-lift ep-reveal"
                style={{
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: '32px 28px',
                }}
              >
                <div style={{
                  fontFamily: font.mono, fontSize: 11, fontWeight: 600,
                  color: item.color, letterSpacing: 1.5,
                  textTransform: 'uppercase', marginBottom: 8,
                }}>{item.step} · {item.label}</div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginTop: 12 }}>{item.body}</p>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 32, textAlign: 'center' }}>
            <Link href="/r/example" style={{
              fontFamily: font.mono, fontSize: 12, color: color.gold,
              letterSpacing: 1, textTransform: 'uppercase',
              textDecoration: 'underline', textUnderlineOffset: 4,
            }}>
              See a real receipt →
            </Link>
          </div>
        </C>
      </section>

      {/* ── THE PROBLEM ──────────────────────────────────────── */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '5fr 7fr', gap: 72, alignItems: 'start' }}>
            <div className="ep-reveal" style={{ position: 'sticky', top: 96 }}>
              <Eyebrow>Structural Vulnerabilities</Eyebrow>
              <SectionTitle>Built for approved-looking workflows where ordinary auth fails</SectionTitle>
              <SectionDesc>Fraud is moving inside valid sessions. Authenticated users, legitimate tools, approved channels — the attack surface is the action itself.</SectionDesc>
            </div>
            <div className="ep-reveal ep-stagger-2" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {PROBLEMS.map((p, i) => (
                <div key={i} className="ep-card-lift" style={{
                  position: 'relative', overflow: 'hidden',
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: '20px 24px',
                }}>
                  {/* Ghost large number */}
                  <div aria-hidden style={{
                    position: 'absolute', right: -6, top: -18,
                    fontFamily: font.mono, fontWeight: 700, fontSize: 88,
                    color: 'rgba(232,229,225,0.55)', pointerEvents: 'none',
                    lineHeight: 1, userSelect: 'none',
                  }}>{p.num}</div>
                  <div style={{ position: 'relative', zIndex: 1 }}>
                    <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1, marginBottom: 8 }}>{p.num}</div>
                    <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 4, color: color.t1 }}>{p.title}</h3>
                    <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>{p.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </C>
      </section>

      {/* ── CONTROL SURFACES ──────────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div className="ep-reveal" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 40 }}>
            <div>
              <Eyebrow>Control Surfaces</Eyebrow>
              <SectionTitle>Built for the workflows where weak authorization causes real damage</SectionTitle>
            </div>
            <a href="/use-cases" style={{ fontFamily: font.mono, fontSize: 11, color: color.t2, letterSpacing: 0.5, textDecoration: 'none', whiteSpace: 'nowrap' }}>
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
                  borderRadius: radius.base,
                  borderTop: `3px solid ${s.accent}`,
                  padding: '28px',
                  textDecoration: 'none',
                }}
              >
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 8, color: color.t1 }}>{s.title}</h3>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6, marginBottom: 16, flexGrow: 1 }}>{s.body}</p>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {s.tags.map(t => tagChip(t))}
                </div>
              </a>
            ))}
          </div>
        </C>
      </section>

      {/* ── DEVELOPER TOOLS ──────────────────────────────────── */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>Implementation Surface</Eyebrow>
            <SectionTitle>Start anywhere. Go as far as you need.</SectionTitle>
            <SectionDesc>Zero-dependency verification. Interactive playground. Embeddable trust badges. Everything you need to integrate EP in minutes.</SectionDesc>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            {DEV_TOOLS.map((item, i) => (
              <a key={i} href={item.href} className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`} style={{
                background: color.card,
                border: `1px solid ${color.border}`,
                borderRadius: radius.base,
                borderTop: `3px solid ${item.accent}`,
                padding: '24px',
                textDecoration: 'none', display: 'flex', flexDirection: 'column',
                minHeight: 200,
              }}>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 8, color: color.t1 }}>{item.title}</h3>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65, flexGrow: 1, marginBottom: 16 }}>{item.body}</p>
                {/* Code snippet at bottom */}
                <div style={{
                  fontFamily: font.mono, fontSize: 9,
                  background: item.codeLight ? '#F5F4F0' : color.t1,
                  color: item.codeLight ? color.t2 : '#F5F5F4',
                  border: item.codeLight ? `1px solid ${color.border}` : 'none',
                  padding: '7px 10px', borderRadius: 2,
                  overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis',
                }}>{item.code}</div>
              </a>
            ))}
          </div>
        </C>
      </section>

      {/* ── CTA — DARK ───────────────────────────────────────── */}
      <section style={{
        position: 'relative', overflow: 'hidden',
        padding: '96px 0 80px',
        background: '#1C1917',
        borderTop: `4px solid ${color.gold}`,
      }}>
        {/* Radial gradient overlay */}
        <div aria-hidden style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: 'radial-gradient(ellipse at center, rgba(255,255,255,0.04) 0%, transparent 70%)',
        }} />
        <C>
          <div className="ep-reveal" style={{ maxWidth: 600 }}>
            <Eyebrow light>Initiate Architecture Review</Eyebrow>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(28px, 3.5vw, 48px)',
              letterSpacing: -1.5, lineHeight: 1.05,
              marginBottom: 32, color: '#FAFAF9',
            }}>
              Enforce trust before<br />high-risk action
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <Link href="/r/example" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917', borderRadius: 2 }}>See Live Example</Link>
              <a href="/protocol" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#FAFAF9', borderRadius: 2 }}>Read the Protocol</a>
              <a href="/partners" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.85)', borderColor: 'rgba(255,255,255,0.18)', borderRadius: 2 }}>Request Pilot</a>
            </div>
          </div>
        </C>
        {/* Footer data ticker */}
        <div aria-hidden style={{
          position: 'absolute', bottom: 0, left: 0, right: 0,
          borderTop: '1px solid rgba(255,255,255,0.08)',
          padding: '8px 32px',
          display: 'flex', justifyContent: 'space-between',
          fontFamily: font.mono, fontSize: 9,
          color: 'rgba(255,255,255,0.3)', letterSpacing: 1.5, textTransform: 'uppercase',
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
