'use client';

import { Suspense } from 'react';
import dynamic from 'next/dynamic';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius, grid } from '@/lib/tokens';

const HeroAnimation = dynamic(() => import('@/components/HeroAnimation'), {
  ssr: false,
  loading: () => (
    <div style={{ width: '100%', maxWidth: 580, height: 320, borderRadius: 6, border: `1px solid ${color.border}`, background: '#F5F5F4' }} />
  ),
});

const STATS = [
  { value: '1,511', label: 'Tests' },
  { value: '19', label: 'Safety Theorems' },
  { value: '85', label: 'Red Team Cases' },
  { value: 'Formally', label: 'Verified' },
  { value: 'Apache 2.0', label: 'License' },
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

function Divider() {
  return <div style={{ height: 1, background: color.border, maxWidth: 600, margin: '0 auto' }} />;
}

function Eyebrow({ children }) {
  return <div style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 500, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 14 }}>{children}</div>;
}

function SectionTitle({ children }) {
  return <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(28px, 3.5vw, 42px)', letterSpacing: -1, lineHeight: 1.15, marginBottom: 20, color: color.t1 }}>{children}</h2>;
}

function Section({ children, alt, wide }) {
  return (
    <section style={alt ? { background: '#F5F5F4', borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}` } : undefined}>
      <div style={{ maxWidth: wide ? 1120 : 760, margin: '0 auto', padding: '100px 32px' }}>{children}</div>
    </section>
  );
}

export default function HomePage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      {/* ── HERO ── */}
      <section style={{ minHeight: '85vh', display: 'flex', alignItems: 'center', padding: '120px 0 80px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 80, alignItems: 'center', width: '100%', maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>
          {/* Animation — left */}
          <div>
            <HeroAnimation />
          </div>

          {/* Text — right */}
          <div style={{ maxWidth: 520 }}>
            <div style={{ fontFamily: font.mono, fontSize: 10, fontWeight: 500, letterSpacing: 2, textTransform: 'uppercase', color: color.gold, marginBottom: 20 }}>
              TRUST INFRASTRUCTURE
            </div>

            <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(36px, 4.5vw, 56px)', letterSpacing: -1.5, lineHeight: 1.06, marginBottom: 20, color: color.t1 }}>
              Trust, before<br />high-risk action.
            </h1>

            <p style={{ fontSize: 17, fontWeight: 400, color: color.t2, maxWidth: 440, lineHeight: 1.65, marginBottom: 32 }}>
              Most systems verify who is acting. EP verifies whether this exact high-risk action should be allowed to proceed.
            </p>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <a href="/protocol" className="ep-cta" style={{ ...cta.primary }}>Read the Protocol</a>
              <a href="/use-cases" className="ep-cta-secondary" style={cta.secondary}>Explore Use Cases</a>
              <a href="/partners" className="ep-cta" style={cta.ghost}>Request Pilot →</a>
            </div>
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section style={{ borderTop: `1px solid ${color.border}`, borderBottom: `1px solid ${color.border}`, padding: '20px 0' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>
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
      </section>

      <Divider />

      {/* ── THE PROBLEM ── */}
      <Section wide>
        <Eyebrow>THE PROBLEM</Eyebrow>
        <SectionTitle>Built for approved-looking workflows where ordinary auth fails</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 40, marginTop: 48 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i}>
              <div style={{ width: 24, height: 1, background: color.gold, marginBottom: 16 }} />
              <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, marginBottom: 6, color: color.t1 }}>{p.title}</h3>
              <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>{p.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* ── CONTROL SURFACES ── */}
      <Section wide>
        <Eyebrow>CONTROL SURFACES</Eyebrow>
        <SectionTitle>Built for the workflows where weak authorization causes real damage</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20, marginTop: 48 }}>
          {SURFACES.map((s, i) => (
            <div key={i} className="ep-card" style={{ ...styles.card, borderTop: '2px solid transparent', transition: 'transform 0.3s, box-shadow 0.3s, background 0.3s, border-color 0.3s' }}>
              <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 18, marginBottom: 10, color: color.t1 }}>{s.title}</h3>
              <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6, marginBottom: 16 }}>{s.body}</p>
              <a href={s.href} style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: color.gold, textDecoration: 'none' }}>See architecture →</a>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* ── PROTOCOL DISCIPLINE ── */}
      <Section>
        <Eyebrow>PROTOCOL DISCIPLINE</Eyebrow>
        <SectionTitle>What EP proves before action</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0, marginTop: 48 }}>
          {BINDINGS.map((b, i) => (
            <div key={i} style={{ padding: '20px 0', borderBottom: `1px solid ${color.border}`, display: 'flex', gap: 20, alignItems: 'baseline', ...(i % 2 === 0 ? { paddingRight: 40 } : { paddingLeft: 40, borderLeft: `1px solid ${color.border}` }) }}>
              <span style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, flexShrink: 0, minWidth: 24 }}>{b.num}</span>
              <div>
                <h3 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 15, marginBottom: 4, color: color.t1 }}>{b.title}</h3>
                <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.5 }}>{b.body}</p>
              </div>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* ── ACCOUNTABLE SIGNOFF ── */}
      <Section>
        <Eyebrow>HUMAN ACCOUNTABILITY</Eyebrow>
        <SectionTitle>When policy requires human ownership</SectionTitle>
        <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.75, marginBottom: 24, maxWidth: 620 }}>
          EP can require a named responsible human to explicitly assume responsibility for the exact action before execution. The signoff is cryptographically bound to the action context, the policy, and the signer's identity.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, maxWidth: 600 }}>
          <div style={{ padding: 24, border: `1px solid ${color.border}`, borderRadius: 6 }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, color: color.t3, letterSpacing: 2, marginBottom: 10 }}>MFA</div>
            <p style={{ fontSize: 14, color: color.t2, lineHeight: 1.6 }}>Proves user presence.<br />Says nothing about the action.</p>
          </div>
          <div style={{ padding: 24, border: '1px solid rgba(176,141,53,0.25)', borderRadius: 6, background: 'rgba(176,141,53,0.06)' }}>
            <div style={{ fontFamily: font.mono, fontSize: 11, color: color.gold, letterSpacing: 2, marginBottom: 10 }}>ACCOUNTABLE SIGNOFF</div>
            <p style={{ fontSize: 14, color: color.t1, lineHeight: 1.6 }}>Proves action-specific responsibility.<br />Bound to the exact operation.</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 24 }}>
          {['Passkey', 'Secure App', 'Platform Authenticator', 'Dual Signoff'].map(m => (
            <span key={m} style={{ fontFamily: font.mono, fontSize: 12, color: color.t2, padding: '8px 16px', border: `1px solid ${color.border}`, borderRadius: 4 }}>{m}</span>
          ))}
        </div>
        <div style={{ marginTop: 28 }}>
          <a href="/product/accountable-signoff" style={{ fontFamily: font.sans, fontSize: 13, fontWeight: 500, color: color.gold, textDecoration: 'none' }}>See Accountable Signoff →</a>
        </div>
      </Section>

      <Divider />

      {/* ── PRODUCT LAYERS ── */}
      <Section>
        <Eyebrow>FROM PROTOCOL TO PRODUCT</Eyebrow>
        <SectionTitle>Deployment options at every layer</SectionTitle>
        <div style={{ marginTop: 48 }}>
          {DEPLOY_LAYERS.map((l, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 24, padding: '20px 0', borderBottom: i < DEPLOY_LAYERS.length - 1 ? `1px solid ${color.border}` : 'none' }}>
              <span style={{ fontFamily: font.mono, fontSize: 11, fontWeight: 500, color: color.gold, minWidth: 140, flexShrink: 0 }}>{l.badge}</span>
              <span style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 16, minWidth: 220, flexShrink: 0, color: color.t1 }}>{l.name}</span>
              <span style={{ fontSize: 14, color: color.t2 }}>{l.desc}</span>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* ── HOW EP DEPLOYS ── */}
      <Section wide>
        <Eyebrow>HOW EMILIA DEPLOYS IN PRACTICE</Eyebrow>
        <SectionTitle>Three layers, one control surface</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 20, marginTop: 24 }}>
          {[
            { label: 'Start with Eye', body: 'Warning-only escalation. Flag when stricter controls should apply. No enforcement, no friction.' },
            { label: 'Enforce with Handshake', body: 'Policy-bound pre-action trust enforcement. Canonical binding, replay resistance, one-time consumption.' },
            { label: 'Own with Signoff', body: 'Named human ownership when policy requires it. Not MFA. Cryptographically bound, action-specific accountability.' },
          ].map((item, i) => (
            <div key={i} style={styles.card}>
              <h3 style={{ color: color.gold, fontSize: 13, fontFamily: font.mono, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 8 }}>{item.label}</h3>
              <p style={{ fontSize: 15, color: color.t2, lineHeight: 1.6 }}>{item.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Divider />

      {/* ── CTA STRIP ── */}
      <section style={{ padding: '80px 0', borderTop: `1px solid ${color.border}` }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 32px' }}>
          <h2 style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 'clamp(20px, 2.5vw, 28px)', letterSpacing: -0.3, marginBottom: 24, color: color.t2 }}>Enforce trust before high-risk action</h2>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="/protocol" className="ep-cta" style={cta.primary}>Read the Protocol</a>
            <a href="/use-cases" className="ep-cta-secondary" style={cta.secondary}>Explore Use Cases</a>
            <a href="/partners" className="ep-cta" style={cta.ghost}>Request Pilot →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
