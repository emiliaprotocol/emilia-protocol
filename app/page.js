'use client';

import { useEffect } from 'react';
import dynamic from 'next/dynamic';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const HeroAnimation = dynamic(() => import('@/components/HeroAnimation'), {
  ssr: false,
  loading: () => (
    <div style={{ width: '100%', aspectRatio: '4/3', borderRadius: 6, border: `1px solid ${color.border}`, background: '#F5F5F4' }} />
  ),
});

const STATS = [
  { value: '3,277', label: 'automated tests', accent: color.t1 },
  { value: '20',    label: 'theorems proven', accent: color.blue },
  { value: '116',   label: 'red team cases',  accent: color.t1 },
  { value: '100/100', label: 'audit score',   accent: color.gold },
  { value: 'Apache 2.0', label: 'license',    accent: color.green },
];

const PROBLEMS = [
  { title: 'Benefit payment redirection', body: 'An authorized operator changes a payment destination inside a valid session. No control catches the action itself.' },
  { title: 'Beneficiary and remittance changes', body: 'A wire transfer beneficiary is swapped through approved channels. The system sees a legitimate update, not fraud.' },
  { title: 'Privileged infrastructure actions', body: 'A production credential is rotated or a deployment is pushed without action-bound authorization. Access was valid.' },
  { title: 'AI agent destructive execution', body: 'An agent with broad tool access executes a high-risk action. No human assumed responsibility for the specific operation.' },
];

const SURFACES = [
  { title: 'Government Fraud Prevention',      body: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.',                         href: '/use-cases/government', accent: color.green },
  { title: 'Financial Infrastructure Controls', body: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.',                  href: '/use-cases/financial',  accent: color.blue },
  { title: 'Enterprise Privileged Actions',     body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.',                       href: '/use-cases/enterprise', accent: color.gold },
  { title: 'AI/Agent Execution Governance',     body: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.',                          href: '/use-cases/ai-agent',   accent: color.t1 },
];

const BINDINGS = [
  { num: '01', title: 'Actor identity',           body: 'Cryptographically verified identity of the entity requesting the action.' },
  { num: '02', title: 'Authority chain',           body: 'Complete delegation path from root authority to the acting principal.' },
  { num: '03', title: 'Exact action context',      body: 'The precise operation, target, parameters, and environmental conditions.' },
  { num: '04', title: 'Policy version and hash',   body: 'Immutable reference to the exact policy version that authorized this action.' },
  { num: '05', title: 'Nonce and expiry',          body: 'One-time cryptographic nonce and strict temporal bounds on authorization.' },
  { num: '06', title: 'One-time consumption',      body: 'Each ceremony token is consumed on use — no replay, no reuse, no ambiguity.' },
  { num: '07', title: 'Immutable event traceability', body: 'Append-only audit trail linking every authorization to its outcome.' },
  { num: '08', title: 'Accountable signoff, when required', body: 'Named human responsibility for the exact action, cryptographically bound to the ceremony.' },
];

const DEPLOY_LAYERS = [
  { badge: 'OPEN',     name: 'Open Protocol',   desc: 'Apache 2.0 licensed specification. Read, implement, extend.' },
  { badge: 'OPEN',     name: 'Open Runtime',    desc: 'Self-hosted reference implementation for on-premise deployment.' },
  { badge: 'MANAGED',  name: 'EP Cloud',        desc: 'Managed control plane with observability, analytics, and policy management.' },
  { badge: 'PRIVATE',  name: 'EP Enterprise',   desc: 'Private deployment with dedicated infrastructure, SLAs, and compliance controls.' },
  { badge: 'VERTICAL', name: 'Vertical Packs',  desc: 'Pre-built policy templates for government, financial services, and agent governance.' },
];

const DEPLOY_STEPS = [
  { color: color.green, label: 'Start with Eye',          body: 'Observe, shadow, then enforce. Eye runs alongside existing workflows — logging first, flagging without blocking, then enforcing full ceremony when ready.' },
  { color: color.blue,  label: 'Enforce with Handshake',  body: 'Policy-bound pre-action trust enforcement. Canonical binding, replay resistance, one-time consumption. Seven properties verified before execution proceeds.' },
  { color: color.gold,  label: 'Own with Signoff',        body: 'Named human ownership when policy requires it. Not MFA. Cryptographically bound, action-specific accountability before execution.' },
  { color: color.t2,    label: 'Seal with Commit',        body: 'Atomic write to the immutable audit chain. Handshake consumed, signoff consumed, event chain sealed. Execution released. Cannot be undone.' },
];

/* ─── Badge chip for product layer rows ─────────────────── */
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
    border: `1px solid ${s.border}`, borderRadius: 100,
    display: 'inline-block',
  };
}

/* ─── Layout container ───────────────────────────────────── */
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

/* ─── Scroll reveal hook ─────────────────────────────────── */
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

/* ─── Section background alternation ─────────────────────── */
const ALT = { background: '#F5F5F4', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` };
const DARK = { background: '#1C1917' };

export default function HomePage() {
  useReveal();

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ────────────────────────────────────────────── */}
      <section style={{ padding: '112px 0 0' }}>
        <C>
          {/* Audit badge */}
          <div className="ep-hero-badge" style={{ marginBottom: 36 }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 9,
              padding: '5px 14px',
              border: '1px solid rgba(176,141,53,0.28)',
              borderRadius: 100,
              background: 'rgba(176,141,53,0.05)',
            }}>
              <span className="ep-pulse-dot" style={{
                display: 'inline-block', width: 6, height: 6,
                borderRadius: '50%', background: color.gold, flexShrink: 0,
              }} />
              <span style={{
                fontFamily: font.mono, fontSize: 10,
                color: color.gold, letterSpacing: 1.5, textTransform: 'uppercase',
              }}>100/100 Independent Code Audit — April 2, 2026 · <a href="/docs/security/AUDIT_METHODOLOGY.md" style={{ color: 'inherit', textDecoration: 'underline' }}>Methodology & scope</a></span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.9fr', gap: 80, alignItems: 'center' }}>
            {/* Text — LEFT */}
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

            {/* Animation — RIGHT */}
            <div className="ep-hero-visual">
              <HeroAnimation />
            </div>
          </div>
        </C>
      </section>

      {/* ── STATS BAR ───────────────────────────────────────── */}
      <div className="ep-reveal" style={{
        borderTop: `1px solid ${color.border}`,
        borderBottom: `1px solid ${color.border}`,
        padding: '22px 0', marginTop: 80,
      }}>
        <C>
          <div style={{
            display: 'flex', justifyContent: 'space-between',
            alignItems: 'center', flexWrap: 'wrap', gap: 16,
          }}>
            {STATS.map((s, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 7 }}>
                  <span style={{
                    fontFamily: font.mono, fontWeight: 600,
                    fontSize: 17, color: s.accent, letterSpacing: -0.3,
                  }}>{s.value}</span>
                  <span style={{
                    fontFamily: font.mono, fontSize: 10,
                    color: color.t3, letterSpacing: 0.5,
                  }}>{s.label}</span>
                </div>
                {i < STATS.length - 1 && (
                  <div style={{ width: 1, height: 18, background: color.border }} />
                )}
              </div>
            ))}
          </div>
        </C>
      </div>

      {/* ── THE PROBLEM ─────────────────────────────────────── */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 72, alignItems: 'start' }}>
            <div className="ep-reveal">
              <Eyebrow>The Problem</Eyebrow>
              <SectionTitle>Built for approved-looking workflows where ordinary auth fails</SectionTitle>
              <SectionDesc>Fraud is moving inside valid sessions. Authenticated users, legitimate tools, approved channels — the attack surface is the action itself.</SectionDesc>
            </div>
            <div className="ep-reveal ep-stagger-2">
              {PROBLEMS.map((p, i) => (
                <div key={i} className="ep-problem-row" style={{
                  padding: '16px 0 16px 12px',
                  borderBottom: `1px solid ${color.border}`,
                  ...(i === 0 ? { borderTop: `1px solid ${color.border}` } : {}),
                }}>
                  <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 4, color: color.t1 }}>{p.title}</h3>
                  <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6 }}>{p.body}</p>
                </div>
              ))}
            </div>
          </div>
        </C>
      </section>

      {/* ── CONTROL SURFACES ────────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>Control Surfaces</Eyebrow>
            <SectionTitle>Built for the workflows where weak authorization causes real damage</SectionTitle>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            {SURFACES.map((s, i) => (
              <a
                key={i}
                href={s.href}
                className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
                style={{
                  display: 'block',
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  borderTop: `3px solid ${s.accent}`,
                  padding: '24px 28px',
                  textDecoration: 'none',
                }}
              >
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 8, color: color.t1 }}>{s.title}</h3>
                <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.6, marginBottom: 14 }}>{s.body}</p>
                <span style={{ fontFamily: font.mono, fontSize: 11, color: s.accent, letterSpacing: 0.3 }}>See architecture →</span>
              </a>
            ))}
          </div>
        </C>
      </section>

      {/* ── PROTOCOL DISCIPLINE ─────────────────────────────── */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>Protocol Discipline</Eyebrow>
            <SectionTitle>What EP proves before action</SectionTitle>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {BINDINGS.map((b, i) => (
              <div
                key={i}
                className={`ep-card-lift ep-reveal ep-stagger-${(i % 4) + 1}`}
                style={{
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: '20px',
                }}
              >
                <span style={{
                  fontFamily: font.mono, fontSize: 10, color: color.gold,
                  letterSpacing: 1, display: 'block', marginBottom: 10,
                }}>{b.num}</span>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 13, marginBottom: 5, color: color.t1 }}>{b.title}</h3>
                <p style={{ fontSize: 12, color: color.t2, lineHeight: 1.55 }}>{b.body}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ── ACCOUNTABLE SIGNOFF ─────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 72, alignItems: 'start' }}>
            <div className="ep-reveal">
              <Eyebrow>Human Accountability</Eyebrow>
              <SectionTitle>When policy requires human ownership</SectionTitle>
              <SectionDesc>
                EP can require a named responsible human to explicitly assume responsibility for the exact action before execution. The signoff is cryptographically bound to the action context, the policy, and the signer's identity.
              </SectionDesc>
            </div>
            <div className="ep-reveal ep-stagger-2">
              <div style={{
                border: `1px solid ${color.border}`,
                borderRadius: radius.base,
                overflow: 'hidden',
                marginBottom: 16,
              }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
                  <div style={{ padding: '24px', borderRight: `1px solid ${color.border}` }}>
                    <div style={{
                      fontFamily: font.mono, fontSize: 10, color: color.t3,
                      letterSpacing: 1.5, marginBottom: 12, textTransform: 'uppercase',
                    }}>MFA</div>
                    <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.7 }}>
                      Proves user presence.<br />Says nothing about the action.
                    </p>
                  </div>
                  <div style={{ padding: '24px', background: 'rgba(176,141,53,0.05)' }}>
                    <div style={{
                      fontFamily: font.mono, fontSize: 10, color: color.gold,
                      letterSpacing: 1.5, marginBottom: 12, textTransform: 'uppercase',
                    }}>Accountable Signoff</div>
                    <p style={{ fontSize: 14, color: color.t1, lineHeight: 1.7, fontWeight: 500 }}>
                      Proves action-specific responsibility.<br />Bound to the exact operation.
                    </p>
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {['Passkey', 'Secure App', 'Platform Authenticator', 'Dual Signoff'].map(m => (
                  <span key={m} style={{
                    fontFamily: font.mono, fontSize: 11, color: color.t3,
                    padding: '5px 12px', border: `1px solid ${color.border}`,
                    borderRadius: radius.sm, letterSpacing: 0.5,
                  }}>{m}</span>
                ))}
              </div>
            </div>
          </div>
        </C>
      </section>

      {/* ── PRODUCT LAYERS ──────────────────────────────────── */}
      <section style={{ padding: '88px 0' }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 32 }}>
            <Eyebrow>From Protocol to Product</Eyebrow>
            <SectionTitle>Deployment options at every layer</SectionTitle>
          </div>
          <div style={{ borderTop: `1px solid ${color.border}` }}>
            {DEPLOY_LAYERS.map((l, i) => (
              <div
                key={i}
                className={`ep-reveal ep-stagger-${i + 1}`}
                style={{
                  display: 'flex', alignItems: 'center', gap: 24,
                  padding: '16px 0', borderBottom: `1px solid ${color.border}`,
                }}
              >
                <span style={{ ...badgeChip(l.badge), minWidth: 80, textAlign: 'center' }}>{l.badge}</span>
                <span style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, minWidth: 180, color: color.t1 }}>{l.name}</span>
                <span style={{ fontSize: 14, color: color.t2 }}>{l.desc}</span>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ── HOW EP DEPLOYS ──────────────────────────────────── */}
      <section style={{ padding: '88px 0', ...ALT }}>
        <C>
          <div className="ep-reveal" style={{ marginBottom: 40 }}>
            <Eyebrow>How Emilia Deploys in Practice</Eyebrow>
            <SectionTitle>Four layers, one control surface</SectionTitle>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            {DEPLOY_STEPS.map((item, i) => (
              <div
                key={i}
                className={`ep-card-lift ep-reveal ep-stagger-${i + 1}`}
                style={{
                  background: color.card,
                  border: `1px solid ${color.border}`,
                  borderRadius: radius.base,
                  padding: '28px',
                }}
              >
                {/* Circle indicator */}
                <div style={{
                  width: 40, height: 40, borderRadius: '50%',
                  background: `${item.color}14`,
                  border: `1px solid ${item.color}38`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  marginBottom: 20,
                }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: item.color }} />
                </div>
                <div style={{
                  fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                  color: item.color, letterSpacing: 1.5,
                  textTransform: 'uppercase', marginBottom: 10,
                }}>{item.label}</div>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.65 }}>{item.body}</p>
              </div>
            ))}
          </div>
        </C>
      </section>

      {/* ── CTA — DARK ──────────────────────────────────────── */}
      <section style={{ padding: '96px 0', ...DARK }}>
        <C>
          <div className="ep-reveal">
            <Eyebrow light>Ready</Eyebrow>
            <h2 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(28px, 3.5vw, 44px)',
              letterSpacing: -1, lineHeight: 1.1,
              marginBottom: 32, color: '#FAFAF9',
              maxWidth: 520,
            }}>
              Enforce trust before<br />high-risk action
            </h2>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <a href="/protocol" className="ep-cta" style={{ ...cta.primary, background: '#FAFAF9', color: '#1C1917' }}>Read the Protocol</a>
              <a href="/partners" className="ep-cta-secondary" style={{ ...cta.secondary, color: 'rgba(250,250,249,0.85)', borderColor: 'rgba(255,255,255,0.18)' }}>Request Pilot</a>
              <a href="/use-cases" className="ep-cta-ghost" style={{ ...cta.ghost, color: 'rgba(250,250,249,0.4)' }}>Use Cases →</a>
            </div>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
