'use client';

import dynamic from 'next/dynamic';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

const HeroAnimation = dynamic(() => import('@/components/HeroAnimation'), {
  ssr: false,
  loading: () => (
    <div style={{ width: '100%', aspectRatio: '640 / 400', borderRadius: 4, border: `1px solid ${color.border}`, background: '#F5F5F4' }} />
  ),
});

const STATS = [
  { value: '1,511', label: 'tests' },
  { value: '19', label: 'safety theorems' },
  { value: '85', label: 'red team cases' },
  { value: 'Formally', label: 'verified' },
  { value: 'Apache 2.0', label: 'license' },
];

const PROBLEMS = [
  { title: 'Benefit payment redirection', body: 'An authorized operator changes a payment destination inside a valid session. No control catches the action itself.' },
  { title: 'Beneficiary and remittance changes', body: 'A wire transfer beneficiary is swapped through approved channels. The system sees a legitimate update, not fraud.' },
  { title: 'Privileged infrastructure actions', body: 'A production credential is rotated or a deployment is pushed without action-bound authorization. Access was valid.' },
  { title: 'AI agent destructive execution', body: 'An agent with broad tool access executes a high-risk action. No human assumed responsibility for the specific operation.' },
];

const SURFACES = [
  { title: 'Government Fraud Prevention', body: 'Bind identity, authority, and action context before benefit disbursement, procurement approval, or credential issuance.', href: '/use-cases/government' },
  { title: 'Financial Infrastructure Controls', body: 'Enforce ceremony-grade authorization on wire transfers, limit changes, account modifications, and privileged treasury actions.', href: '/use-cases/financial' },
  { title: 'Enterprise Privileged Actions', body: 'Require bound authorization for infrastructure changes, data exports, permission escalations, and production deployments.', href: '/use-cases/enterprise' },
  { title: 'AI/Agent Execution Governance', body: 'Gate autonomous agent actions behind protocol-enforced trust ceremonies before any irreversible real-world execution.', href: '/use-cases/ai-agent' },
];

const BINDINGS = [
  { num: '01', title: 'Actor identity', body: 'Cryptographically verified identity of the entity requesting the action.' },
  { num: '02', title: 'Authority chain', body: 'Complete delegation path from root authority to the acting principal.' },
  { num: '03', title: 'Exact action context', body: 'The precise operation, target, parameters, and environmental conditions.' },
  { num: '04', title: 'Policy version and hash', body: 'Immutable reference to the exact policy version that authorized this action.' },
  { num: '05', title: 'Nonce and expiry', body: 'One-time cryptographic nonce and strict temporal bounds on authorization.' },
  { num: '06', title: 'One-time consumption', body: 'Each ceremony token is consumed on use — no replay, no reuse, no ambiguity.' },
  { num: '07', title: 'Immutable event traceability', body: 'Append-only audit trail linking every authorization to its outcome.' },
  { num: '08', title: 'Accountable signoff, when required', body: 'Named human responsibility for the exact action, cryptographically bound to the ceremony.' },
];

const DEPLOY_LAYERS = [
  { badge: 'OPEN', name: 'Open Protocol', desc: 'Apache 2.0 licensed specification. Read, implement, extend.' },
  { badge: 'OPEN', name: 'Open Runtime', desc: 'Self-hosted reference implementation for on-premise deployment.' },
  { badge: 'MANAGED', name: 'EP Cloud', desc: 'Managed control plane with observability, analytics, and policy management.' },
  { badge: 'PRIVATE', name: 'EP Enterprise', desc: 'Private deployment with dedicated infrastructure, SLAs, and compliance controls.' },
  { badge: 'VERTICAL', name: 'Vertical Packs', desc: 'Pre-built policy templates for government, financial services, and agent governance.' },
];

const DEPLOY_STEPS = [
  { color: '#16A34A', label: 'Start with Eye', body: 'Warning-only escalation. Flag when stricter controls should apply. No enforcement, no friction.' },
  { color: '#3B82F6', label: 'Enforce with Handshake', body: 'Policy-bound pre-action trust enforcement. Canonical binding, replay resistance, one-time consumption.' },
  { color: '#B08D35', label: 'Own with Signoff', body: 'Named human ownership when policy requires it. Not MFA. Cryptographically bound, action-specific accountability.' },
];

/* ─── Reusable layout primitives ─── */

function Eyebrow({ children }) {
  return (
    <div style={{
      fontFamily: font.mono, fontSize: 10, fontWeight: 500,
      letterSpacing: 2, textTransform: 'uppercase',
      color: color.gold, marginBottom: 14,
    }}>{children}</div>
  );
}

function SectionTitle({ children }) {
  return (
    <h2 style={{
      fontFamily: font.sans, fontWeight: 700,
      fontSize: 'clamp(24px, 3vw, 36px)',
      letterSpacing: -0.5, lineHeight: 1.2,
      marginBottom: 16, color: color.t1,
    }}>{children}</h2>
  );
}

function SectionDesc({ children }) {
  return (
    <p style={{
      fontSize: 16, color: color.t2,
      maxWidth: 560, lineHeight: 1.7,
    }}>{children}</p>
  );
}

function Section({ children, wide }) {
  return (
    <section style={{ padding: '100px 0' }}>
      <div style={{ maxWidth: wide ? 1120 : 1120, margin: '0 auto', padding: '0 32px' }}>
        {children}
      </div>
    </section>
  );
}

export default function HomePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ── */}
      <section style={{ display: 'flex', alignItems: 'center', minHeight: 'calc(100vh - 56px)', padding: '56px 0 0' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: 48,
          alignItems: 'center', width: '100%', maxWidth: 1120,
          margin: '0 auto', padding: '0 32px',
        }}>
          {/* Animation — left, fills column */}
          <div>
            <HeroAnimation />
          </div>

          {/* Text — right */}
          <div>
            <div style={{
              fontFamily: font.mono, fontSize: 10, fontWeight: 500,
              letterSpacing: 2, textTransform: 'uppercase',
              color: color.gold, marginBottom: 20,
            }}>Trust Infrastructure</div>

            <h1 style={{
              fontFamily: font.sans, fontWeight: 700,
              fontSize: 'clamp(36px, 4.5vw, 56px)',
              letterSpacing: -1.5, lineHeight: 1.06,
              marginBottom: 20, color: color.t1,
            }}>
              Trust, before<br />high-risk <em style={{ fontStyle: 'normal', color: color.gold }}>action.</em>
            </h1>

            <p style={{
              fontSize: 17, fontWeight: 400,
              color: color.t2, maxWidth: 440,
              lineHeight: 1.65, marginBottom: 32,
            }}>
              Most systems verify who is acting. EP verifies whether this exact high-risk action should be allowed to proceed — by this actor, under this policy, right now.
            </p>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <a href="/protocol" className="ep-cta" style={cta.primary}>Read the Protocol</a>
              <a href="/partners" className="ep-cta-secondary" style={cta.secondary}>Request Pilot</a>
              <a href="/use-cases" className="ep-cta-ghost" style={cta.ghost}>Use Cases →</a>
            </div>
          </div>
        </div>
      </section>

      {/* ── STATS BAR ── */}
      <div style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, padding: '20px 0' }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          flexWrap: 'wrap', gap: 16, maxWidth: 1120, margin: '0 auto', padding: '0 32px',
        }}>
          {STATS.map((s, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                <span style={{ fontFamily: font.mono, fontWeight: 500, fontSize: 15, color: color.t1 }}>{s.value}</span>
                <span style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 0.5 }}>{s.label}</span>
              </div>
              {i < STATS.length - 1 && <div style={{ width: 1, height: 20, background: color.border }} />}
            </div>
          ))}
        </div>
      </div>

      {/* ── THE PROBLEM ── */}
      <Section>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'start' }}>
          <div>
            <Eyebrow>THE PROBLEM</Eyebrow>
            <SectionTitle>Built for approved-looking workflows where ordinary auth fails</SectionTitle>
            <SectionDesc>Fraud is moving inside valid sessions. Authenticated users, legitimate tools, approved channels — the attack surface is the action itself.</SectionDesc>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {PROBLEMS.map((p, i) => (
              <div key={i} style={{
                padding: '20px 0',
                borderBottom: `1px solid ${color.border}`,
                ...(i === 0 ? { borderTop: `1px solid ${color.border}` } : {}),
              }}>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 4, color: color.t1 }}>{p.title}</h3>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{p.body}</p>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* ── CONTROL SURFACES ── */}
      <Section>
        <Eyebrow>CONTROL SURFACES</Eyebrow>
        <SectionTitle>Built for the workflows where weak authorization causes real damage</SectionTitle>
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0,
          marginTop: 40, borderTop: `1px solid ${color.border}`,
        }}>
          {SURFACES.map((s, i) => (
            <div key={i} style={{
              padding: '24px 20px 24px 0',
              borderRight: i < 3 ? `1px solid ${color.border}` : 'none',
              ...(i > 0 ? { paddingLeft: 20 } : {}),
            }}>
              <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, marginBottom: 8, color: color.t1 }}>{s.title}</h3>
              <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.55, marginBottom: 10 }}>{s.body}</p>
              <a href={s.href} style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, textDecoration: 'none', transition: 'color 0.15s' }}>See architecture →</a>
            </div>
          ))}
        </div>
      </Section>

      {/* ── PROTOCOL DISCIPLINE ── */}
      <Section>
        <Eyebrow>PROTOCOL DISCIPLINE</Eyebrow>
        <SectionTitle>What EP proves before action</SectionTitle>
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0,
          marginTop: 40, borderTop: `1px solid ${color.border}`,
        }}>
          {BINDINGS.map((b, i) => (
            <div key={i} style={{
              padding: '20px 16px 20px 0',
              borderBottom: `1px solid ${color.border}`,
              borderRight: (i + 1) % 4 !== 0 ? `1px solid ${color.border}` : 'none',
              ...((i % 4 !== 0) ? { paddingLeft: 16 } : {}),
            }}>
              <span style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1, display: 'block', marginBottom: 6 }}>{b.num}</span>
              <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, marginBottom: 4, color: color.t1 }}>{b.title}</h3>
              <p style={{ fontSize: 13, color: color.t2, lineHeight: 1.5 }}>{b.body}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── ACCOUNTABLE SIGNOFF ── */}
      <Section>
        <Eyebrow>HUMAN ACCOUNTABILITY</Eyebrow>
        <SectionTitle>When policy requires human ownership</SectionTitle>
        <SectionDesc>
          EP can require a named responsible human to explicitly assume responsibility for the exact action before execution. The signoff is cryptographically bound to the action context, the policy, and the signer's identity.
        </SectionDesc>
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0,
          marginTop: 28, maxWidth: 520,
          border: `1px solid ${color.border}`, borderRadius: 4, overflow: 'hidden',
        }}>
          <div style={{ padding: '20px 24px', borderRight: `1px solid ${color.border}` }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, color: color.t3, letterSpacing: 1.5, marginBottom: 8, textTransform: 'uppercase' }}>MFA</div>
            <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>Proves user presence.<br />Says nothing about the action.</p>
          </div>
          <div style={{ padding: '20px 24px', background: 'rgba(176,141,53,0.06)' }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, color: color.gold, letterSpacing: 1.5, marginBottom: 8, textTransform: 'uppercase' }}>Accountable Signoff</div>
            <p style={{ fontSize: 14, color: color.t1, lineHeight: 1.6 }}>Proves action-specific responsibility.<br />Bound to the exact operation.</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 20 }}>
          {['Passkey', 'Secure App', 'Platform Authenticator', 'Dual Signoff'].map(m => (
            <span key={m} style={{
              fontFamily: font.mono, fontSize: 11, color: color.t3,
              padding: '6px 14px', border: `1px solid ${color.border}`, borderRadius: 4,
              letterSpacing: 0.5,
            }}>{m}</span>
          ))}
        </div>
      </Section>

      {/* ── PRODUCT LAYERS ── */}
      <Section>
        <Eyebrow>FROM PROTOCOL TO PRODUCT</Eyebrow>
        <SectionTitle>Deployment options at every layer</SectionTitle>
        <div style={{ marginTop: 32, borderTop: `1px solid ${color.border}` }}>
          {DEPLOY_LAYERS.map((l, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 24,
              padding: '16px 0',
              borderBottom: `1px solid ${color.border}`,
              transition: 'background 0.15s',
            }}>
              <span style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 500, color: color.t3, minWidth: 72, letterSpacing: 1 }}>{l.badge}</span>
              <span style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, minWidth: 180, color: color.t1 }}>{l.name}</span>
              <span style={{ fontSize: 14, color: color.t2 }}>{l.desc}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* ── HOW EP DEPLOYS ── */}
      <Section>
        <Eyebrow>HOW EMILIA DEPLOYS IN PRACTICE</Eyebrow>
        <SectionTitle>Three layers, one control surface</SectionTitle>
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 0,
          marginTop: 32, borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`,
        }}>
          {DEPLOY_STEPS.map((item, i) => (
            <div key={i} style={{
              padding: '24px 20px 24px 0',
              borderRight: i < 2 ? `1px solid ${color.border}` : 'none',
              ...(i > 0 ? { paddingLeft: 20 } : {}),
            }}>
              <div style={{
                fontFamily: font.mono, fontSize: 10, fontWeight: 500,
                color: item.color, letterSpacing: 1.5,
                textTransform: 'uppercase', marginBottom: 8,
              }}>{item.label}</div>
              <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{item.body}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── CTA STRIP ── */}
      <section style={{ padding: '80px 0', borderTop: `1px solid ${color.border}` }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>
          <h2 style={{
            fontFamily: font.sans, fontWeight: 600,
            fontSize: 'clamp(20px, 2.5vw, 28px)',
            letterSpacing: -0.3, marginBottom: 24, color: color.t2,
          }}>Enforce trust before high-risk action</h2>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/protocol" className="ep-cta" style={cta.primary}>Read the Protocol</a>
            <a href="/partners" className="ep-cta-secondary" style={cta.secondary}>Request Pilot</a>
            <a href="/use-cases" className="ep-cta-ghost" style={cta.ghost}>Use Cases →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
