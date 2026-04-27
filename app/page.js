'use client';

import { useEffect } from 'react';
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

// Stats below are the source-of-truth numbers as of 2026-04-27. Each value
// is independently verifiable in the repo:
//   3,436 tests / 129 files — `npx vitest run` summary
//   20 TLA+ theorems verified — formal/PROOF_STATUS.md (T1–T20)
//   85 red team cases — docs/conformance/RED_TEAM_CASES.md line 1
//   Internal audit — docs/security/AUDIT_METHODOLOGY.md (self-administered)
// Do NOT mark as third-party "Verified". Do NOT inflate.
const STATS = [
  { value: '3,436', label: 'Automated Tests',   sub: '129 test files',           accent: color.t1 },
  { value: '20',    label: 'Theorems Proven',   sub: 'TLC 2.19, zero errors',    accent: color.blue },
  { value: '85',    label: 'Red Team Cases',    sub: 'Cataloged in repo',        accent: color.t1 },
  { value: '100/100', label: 'Internal Audit',  sub: 'Self-administered · Apr 2', accent: color.gold },
  { value: 'Apache 2.0', label: 'License',      sub: 'Open specification',       accent: color.green },
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

const BINDINGS = [
  { num: '01', title: 'Actor identity',                    body: 'Cryptographically verified identity of the entity requesting the action.',              code: 'verify(entity.keyId)' },
  { num: '02', title: 'Authority chain',                   body: 'Complete delegation path from root authority to the acting principal.',                  code: '∀d ∈ D: d(root→actor)' },
  { num: '03', title: 'Exact action context',              body: 'The precise operation, target, parameters, and environmental conditions.',               code: 'bind(action, params)' },
  { num: '04', title: 'Policy version and hash',           body: 'Immutable reference to the exact policy version that authorized this action.',           code: 'pin(policy.sha256)' },
  { num: '05', title: 'Nonce and expiry',                  body: 'One-time cryptographic nonce and strict temporal bounds on authorization.',              code: 'N_{t} ≠ N_{t-1}' },
  { num: '06', title: 'One-time consumption',              body: 'Each ceremony token is consumed on use — no replay, no reuse, no ambiguity.',           code: 'consume(token_id, lock)' },
  { num: '07', title: 'Immutable event traceability',      body: 'Append-only audit trail linking every authorization to its outcome.',                    code: 'Append(Log, Hash(E))' },
  { num: '08', title: 'Accountable signoff, when required', body: 'Named human responsibility for the exact action, cryptographically bound to the ceremony.', code: 'attest(actor, action)' },
];

const DEPLOY_LAYERS = [
  { badge: 'OPEN',     name: 'Open Protocol',  desc: 'Apache 2.0 licensed specification. Read, implement, extend.', accent: color.green },
  { badge: 'OPEN',     name: 'Open Runtime',   desc: 'Self-hosted reference implementation for on-premise deployment.', accent: color.green },
  { badge: 'MANAGED',  name: 'EP Cloud',       desc: 'Managed control plane with observability, analytics, and policy management.', accent: color.blue },
  { badge: 'PRIVATE',  name: 'EP Enterprise',  desc: 'Private deployment with dedicated infrastructure, SLAs, and compliance controls.', accent: color.gold },
  { badge: 'VERTICAL', name: 'Vertical Packs', desc: 'Pre-built policy templates for government, financial services, and agent governance.', accent: color.t3 },
];

const DEPLOY_STEPS = [
  { step: '01', color: color.green, label: 'Start with Eye',          body: 'Observe, shadow, then enforce. Eye runs alongside existing workflows — logging first, flagging without blocking, then enforcing full ceremony when ready.', filled: true },
  { step: '02', color: color.blue,  label: 'Enforce with Handshake',  body: 'Policy-bound pre-action trust enforcement. Canonical binding, replay resistance, one-time consumption. Seven properties verified before execution proceeds.', filled: false },
  { step: '03', color: color.gold,  label: 'Own with Signoff',        body: 'Named human ownership when policy requires it. Not MFA. Cryptographically bound, action-specific accountability before execution.', filled: false },
  { step: '04', color: color.t2,    label: 'Seal with Commit',        body: 'Atomic write to the immutable audit chain. Handshake consumed, signoff consumed, event chain sealed. Execution released. Cannot be undone.', filled: false },
];

const DEV_TOOLS = [
  { title: 'Verify Package',    body: 'Zero-dependency offline receipt verification. Ed25519 + Merkle proofs. Just math, no EP server required.', code: 'packages/verify (npm publish pending)', href: 'https://github.com/emiliaprotocol/emilia-protocol/tree/main/packages/verify', accent: color.green,  codeLight: false },
  { title: 'Trust Playground',  body: 'Walk through the EP lifecycle interactively. Create entities, issue receipts, run handshakes — all from one page.', code: '/playground', href: '/playground', accent: color.blue,   codeLight: true },
  { title: 'Trust Explorer',    body: 'Verify any receipt, proof, or entity. Like Etherscan for trust. Public, transparent, cryptographically verified.', code: '/explorer', href: '/explorer', accent: color.gold,   codeLight: true },
  { title: 'Embed Widget',      body: 'Drop a trust badge on any page. One script tag, one web component. Live data from the EP operator.', code: '<ep-trust-badge />', href: '/adopt', accent: color.t2,    codeLight: true },
];

const BADGE_STYLE = {
  OPEN:     { color: color.green, bg: 'rgba(22,163,74,0.08)',    border: 'rgba(22,163,74,0.2)' },
  MANAGED:  { color: color.blue,  bg: 'rgba(59,130,246,0.08)',   border: 'rgba(59,130,246,0.2)' },
  PRIVATE:  { color: color.gold,  bg: 'rgba(176,141,53,0.08)',   border: 'rgba(176,141,53,0.2)' },
  VERTICAL: { color: color.t3,    bg: 'rgba(120,113,108,0.06)',  border: 'rgba(120,113,108,0.18)' },
};

function badgeChip(badge) {
  const s = BADGE_STYLE[badge] || BADGE_STYLE.VERTICAL;
  return {
    fontFamily: font.mono, fontSize: 9, fontWeight: 500,
    color: s.color, letterSpacing: 1.2, textTransform: 'uppercase',
    padding: '4px 10px', background: s.bg,
    border: `1px solid ${s.border}`, borderRadius: 2,
    display: 'inline-block',
  };
}

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
const DARK = { background: '#1C1917' };

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
                  Internal Security Audit — 100/100
                </div>
                <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 0.5, lineHeight: 1.2, marginTop: 1 }}>
                  April 2, 2026 · <a href="/docs/security/AUDIT_METHODOLOGY.md" style={{ color: 'inherit', textDecoration: 'underline' }}>Methodology &amp; scope</a>
                </div>
              </div>
              <div style={{ marginLeft: 4, paddingLeft: 12, borderLeft: `1px solid ${color.border}` }}>
                {/* "INTERNAL" not "VERIFIED" — the audit is self-administered
                    per docs/security/AUDIT_METHODOLOGY.md. Federal procurement
                    teams treat "Verified" badges as third-party attestations;
                    misrepresenting an internal review as third-party-verified
                    is the kind of claim that triggers protests. */}
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
              }}>Trust Infrastructure</div>

              <h1 style={{
                fontFamily: font.sans, fontWeight: 700,
                fontSize: 'clamp(44px, 5.5vw, 72px)',
                letterSpacing: -2.5, lineHeight: 0.96,
                marginBottom: 28, color: color.t1,
              }}>
                Trust, before<br />
                high-risk{' '}
                <em style={{ fontStyle: 'normal', color: color.gold }}>action.</em>
              </h1>

              <p style={{
                fontSize: 17, color: color.t2,
                maxWidth: 440, lineHeight: 1.7, marginBottom: 36,
              }}>
                Most systems verify who is acting. EP verifies whether this exact high-risk action should be allowed — by this actor, under this policy, right now.
              </p>

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <a href="/protocol" className="ep-cta"           style={cta.primary}>Read the Protocol</a>
                <a href="/partners" className="ep-cta-secondary" style={cta.secondary}>Request Pilot</a>
                <a href="/use-cases" className="ep-cta-ghost"    style={cta.ghost}>Use Cases →</a>
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

      {/* ── PROTOCOL DISCIPLINE ──────────────────────────────── */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>Protocol Discipline</Eyebrow>
            <SectionTitle>Core verification axioms</SectionTitle>
            <SectionDesc>The fundamental properties guaranteed before execution. Any state resolving outside these bounds results in immediate rejection.</SectionDesc>
          </div>
          {/* Border-collapse grid — no gaps, borders shared between cells */}
          <div className="ep-reveal ep-stagger-1" style={{
            display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
            borderTop: `1px solid ${color.border}`,
            borderLeft: `1px solid ${color.border}`,
            background: '#F5F4F0',
          }}>
            {BINDINGS.map((b, i) => (
              <div key={i} className="ep-card-lift" style={{
                position: 'relative', overflow: 'hidden',
                background: color.card,
                borderRight: `1px solid ${color.border}`,
                borderBottom: `1px solid ${color.border}`,
                padding: '24px',
              }}>
                {/* Ghost number */}
                <div aria-hidden style={{
                  position: 'absolute', right: -8, top: -16,
                  fontFamily: font.mono, fontWeight: 700, fontSize: 80,
                  color: 'rgba(232,229,225,0.6)', pointerEvents: 'none',
                  lineHeight: 1, userSelect: 'none',
                }}>{b.num}</div>
                <div style={{ position: 'relative', zIndex: 1 }}>
                  <div style={{ fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 14 }}>Property_{b.num}</div>
                  <h4 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 13, marginBottom: 6, color: color.t1 }}>{b.title}</h4>
                  <p style={{ fontSize: 12, color: color.t2, lineHeight: 1.55, marginBottom: 14 }}>{b.body}</p>
                  <div style={{
                    fontFamily: font.mono, fontSize: 9,
                    background: '#F5F4F0', border: `1px solid ${color.border}`,
                    padding: '6px 10px', textAlign: 'center', color: color.t3,
                  }}>{b.code}</div>
                </div>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ── ACCOUNTABLE SIGNOFF ──────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div className="ep-reveal" style={{ textAlign: 'center', marginBottom: 48 }}>
            <Eyebrow>Architecture Analysis</Eyebrow>
            <SectionTitle>When policy requires human ownership</SectionTitle>
          </div>
          <div className="ep-reveal ep-stagger-1" style={{
            display: 'grid', gridTemplateColumns: '1fr 1fr',
            maxWidth: 900, margin: '0 auto',
            border: `1px solid ${color.border}`,
            borderRadius: radius.base, overflow: 'hidden',
          }}>
            {/* Left — standard auth flow */}
            <div style={{ background: '#FDFCFB', padding: '32px', borderRight: `1px solid ${color.border}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, borderBottom: `1px solid ${color.border}`, paddingBottom: 16, marginBottom: 24 }}>
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'rgba(185,28,28,0.7)', flexShrink: 0 }} />
                <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 600, color: color.t1 }}>Standard MFA Pipeline</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { step: '1', label: 'User authenticates via session', tag: 'Session-level only' },
                  { step: '2', label: 'Session cookie granted', tag: 'Exportable, reusable' },
                  { step: '3', label: 'Action executes within session', tag: 'No action verification' },
                  { step: '4', label: 'Fraud succeeds', tag: 'Looks legitimate at auth layer', final: true, error: true },
                ].map((item, i) => (
                  <div key={i} style={{
                    position: 'relative',
                    padding: '10px 14px',
                    background: item.error ? 'rgba(185,28,28,0.04)' : color.card,
                    border: `1px solid ${item.error ? 'rgba(185,28,28,0.25)' : color.border}`,
                    borderRadius: 3,
                  }}>
                    {!item.final && (
                      <div style={{ position: 'absolute', bottom: -10, left: 18, width: 1, height: 10, background: color.border, zIndex: 1 }} />
                    )}
                    <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t2 }}>{item.step}. {item.label}</div>
                    <div style={{
                      fontFamily: font.mono, fontSize: 9, marginTop: 4,
                      color: item.error ? 'rgba(185,28,28,0.8)' : color.t3,
                      background: item.error ? 'rgba(185,28,28,0.07)' : 'transparent',
                      display: 'inline-block', padding: item.error ? '2px 6px' : 0,
                      borderRadius: 2,
                    }}>{item.tag}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right — EP Accountable Signoff */}
            <div style={{ background: color.card, padding: '32px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: `1px solid ${color.border}`, paddingBottom: 16, marginBottom: 24 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: color.green, flexShrink: 0 }} />
                  <span style={{ fontFamily: font.mono, fontSize: 12, fontWeight: 600, color: color.t1 }}>EP Accountable Signoff</span>
                </div>
                <span style={{ fontFamily: font.mono, fontSize: 9, background: color.t1, color: color.gold, padding: '3px 8px', borderRadius: 2, letterSpacing: 1, textTransform: 'uppercase' }}>PASS</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { step: '1', label: 'Action context bound', tag: 'Exact params + target' },
                  { step: '2', label: 'Policy version evaluated', tag: 'Pinned policy hash' },
                  { step: '3', label: 'Human attestation required', tag: 'Named, cryptographically bound' },
                  { step: '4', label: 'Trust established', tag: 'One-time consumption, sealed', final: true },
                ].map((item, i) => (
                  <div key={i} style={{
                    position: 'relative',
                    padding: '10px 14px',
                    background: item.final ? 'rgba(22,163,74,0.04)' : '#FFFFFF',
                    border: `1px solid ${item.final ? 'rgba(22,163,74,0.3)' : 'rgba(22,163,74,0.15)'}`,
                    borderRadius: 3,
                  }}>
                    {!item.final && (
                      <div style={{ position: 'absolute', bottom: -10, left: 18, width: 1, height: 10, background: 'rgba(22,163,74,0.3)', zIndex: 1 }} />
                    )}
                    <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t1 }}>{item.step}. {item.label}</div>
                    <div style={{ fontFamily: font.mono, fontSize: 9, color: color.green, marginTop: 4, background: 'rgba(22,163,74,0.08)', display: 'inline-block', padding: '2px 6px', borderRadius: 2 }}>{item.tag}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </C>
      </section>

      {/* ── PRODUCT LAYERS ───────────────────────────────────── */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 32 }}>
            <Eyebrow>Infrastructure Layers</Eyebrow>
            <SectionTitle>Deployment options at every layer</SectionTitle>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={{ borderBottom: `1px solid ${color.border}`, paddingBottom: 12, paddingLeft: 16, textAlign: 'left', fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 2, textTransform: 'uppercase' }}>Layer</th>
                  <th style={{ borderBottom: `1px solid ${color.border}`, paddingBottom: 12, textAlign: 'left', fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 2, textTransform: 'uppercase' }}>Name</th>
                  <th style={{ borderBottom: `1px solid ${color.border}`, paddingBottom: 12, textAlign: 'left', fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 2, textTransform: 'uppercase' }}>Description</th>
                  <th style={{ borderBottom: `1px solid ${color.border}`, paddingBottom: 12, textAlign: 'right', paddingRight: 16, fontFamily: font.mono, fontSize: 9, color: color.t3, letterSpacing: 2, textTransform: 'uppercase' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {DEPLOY_LAYERS.map((l, i) => (
                  <tr key={i} className="ep-row-hover" style={{ borderBottom: i < DEPLOY_LAYERS.length - 1 ? `1px solid ${color.border}` : 'none' }}>
                    <td style={{ padding: '14px 16px' }}>
                      <span style={badgeChip(l.badge)}>{l.badge}</span>
                    </td>
                    <td style={{ padding: '14px 0', fontFamily: font.sans, fontWeight: 600, fontSize: 14, color: color.t1, minWidth: 160 }}>{l.name}</td>
                    <td style={{ padding: '14px 24px 14px 0', fontSize: 13, color: color.t2 }}>{l.desc}</td>
                    <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 5,
                        fontFamily: font.mono, fontSize: 9, textTransform: 'uppercase', letterSpacing: 1,
                        color: color.green, background: 'rgba(22,163,74,0.08)',
                        border: '1px solid rgba(22,163,74,0.2)',
                        padding: '4px 10px', borderRadius: 2,
                      }}>
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: color.green, display: 'inline-block' }} />
                        Active
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </C>
      </section>

      {/* ── HOW EP DEPLOYS ───────────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>Rollout Schematics</Eyebrow>
            <SectionTitle>Progressive phased deployment</SectionTitle>
          </div>
          <div style={{ position: 'relative' }}>
            {/* Connecting line */}
            <div aria-hidden style={{
              position: 'absolute', top: 20, left: 36, right: 36,
              height: 1, background: color.border, zIndex: 0,
            }} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, position: 'relative', zIndex: 1 }}>
              {DEPLOY_STEPS.map((item, i) => (
                <div
                  key={i}
                  className="ep-card-lift ep-reveal"
                  style={{
                    background: color.card,
                    border: `1px solid ${color.border}`,
                    borderRadius: radius.base,
                    padding: '28px',
                  }}
                >
                  {/* Step badge */}
                  <div style={{
                    width: 40, height: 40, borderRadius: 2,
                    background: item.filled ? color.t1 : '#F5F4F0',
                    border: item.filled ? 'none' : `1px solid ${color.border}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginBottom: 20,
                    fontFamily: font.mono, fontSize: 12, fontWeight: 600,
                    color: item.filled ? color.gold : color.t2,
                  }}>{item.step}</div>
                  <div style={{
                    fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                    color: item.color, letterSpacing: 1.5,
                    textTransform: 'uppercase', marginBottom: 10,
                  }}>{item.label}</div>
                  <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.65 }}>{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </C>
      </section>

      {/* ── PROTOCOL PROPERTIES ──────────────────────────────── */}
      <section style={{ padding: '88px 0', borderBottom: `1px solid ${color.border}` }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 48 }}>
            <Eyebrow>Protocol Properties</Eyebrow>
            <SectionTitle>Why EP is a protocol, not just an API</SectionTitle>
          </div>
          <div className="ep-reveal ep-stagger-1" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 48 }}>
            {[
              {
                code: 'SYS_ARCH::001',
                title: 'Self-verifying receipts',
                body: 'Every EP receipt is Ed25519-signed and Merkle-anchored. Anyone can verify it without calling our API — no account, no trust relationship. Just math.',
                accent: color.green,
              },
              {
                code: 'SYS_ARCH::002',
                title: 'Compliance-mapped',
                body: 'Formal mappings to 38 NIST AI RMF subcategories across all four functions (GOVERN, MAP, MEASURE, MANAGE) and EU AI Act Articles 9–15 + 26. SOC 2 Type II preparation underway. Built for procurement, not just developers.',
                accent: color.blue,
              },
              {
                code: 'SYS_ARCH::003',
                title: 'Federation-ready',
                body: 'Multiple independent operators can issue and cross-verify receipts via shared cryptographic proofs. No single point of failure. No central authority. Like email — anyone can run a server.',
                accent: color.gold,
              },
            ].map((item, i) => (
              <div key={i}>
                <div style={{
                  fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                  color: item.accent, letterSpacing: 1, display: 'block',
                  marginBottom: 12, borderBottom: `1px solid ${color.border}`,
                  paddingBottom: 8,
                }}>{item.code}</div>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 17, marginBottom: 10, color: color.t1 }}>{item.title}</h3>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.7 }}>{item.body}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ── DEVELOPER TOOLS ──────────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
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
              <a href="/protocol" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917', borderRadius: 2 }}>Read the Protocol</a>
              <a href="/playground" className="ep-cta" style={{ ...cta.primary, background: color.gold, color: '#FAFAF9', borderRadius: 2 }}>Open Playground</a>
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
          <span>Tests: 3,436 passing · 0 failing</span>
          <span>Formal verification: 20 theorems · 0 errors</span>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
